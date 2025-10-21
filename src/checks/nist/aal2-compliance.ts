/**
 * NIST AAL2 Compliance Check
 *
 * Validates that an OAuth 2.0/OIDC provider meets NIST SP 800-63B
 * Authentication Assurance Level 2 (AAL2) requirements.
 *
 * AAL2 Requirements Summary:
 * - Multi-factor authentication (MFA) REQUIRED
 * - At least one factor must be cryptographic
 * - HTTPS required for all endpoints
 * - Session timeout: Maximum 12 hours
 * - Idle timeout: 30 minutes preferred, 60 minutes maximum
 * - Reauthentication required for sensitive operations
 * - Resistance to replay attacks
 *
 * References:
 * - NIST SP 800-63B Section 4.2 (AAL2): https://pages.nist.gov/800-63-3/sp800-63b.html#aal2
 * - NIST SP 800-63B Section 7.2 (Session Management): https://pages.nist.gov/800-63-3/sp800-63b.html#sessionmgmt
 */

import { BaseNISTCheck, AALLevel } from "./base-nist-check.js";
import {
  CheckResult,
  CheckCategory,
  Severity,
  CheckContext,
} from "../../types/index.js";

/**
 * Check that validates AAL2 compliance requirements
 */
export class AAL2ComplianceCheck extends BaseNISTCheck {
  readonly id = "nist-aal2-compliance";
  readonly name = "NIST AAL2 Compliance";
  readonly category = CheckCategory.NIST;
  readonly defaultSeverity = Severity.HIGH;
  readonly description =
    "Validates compliance with NIST SP 800-63B Authentication Assurance Level 2 (AAL2) requirements for multi-factor authentication";

  protected override references = [
    "https://pages.nist.gov/800-63-3/sp800-63b.html#aal2",
    "https://pages.nist.gov/800-63-3/sp800-63b.html#sessionmgmt",
    "https://openid.net/specs/openid-connect-core-1_0.html",
    "https://www.rfc-editor.org/rfc/rfc8176.html",
  ];

  async execute(context: CheckContext): Promise<CheckResult> {
    this.log(context, "Starting NIST AAL2 compliance check...");

    // Discover OAuth/OIDC metadata
    const discoveryResult = await this.discoverMetadata(context);

    if (!discoveryResult.success || !discoveryResult.metadata) {
      return this.createMetadataWarning(
        discoveryResult.error || "Metadata discovery failed"
      );
    }

    const metadata = discoveryResult.metadata;
    const criticalIssues: string[] = [];
    const recommendations: string[] = [];
    const complianceDetails: Record<string, unknown> = {
      issuer: metadata.issuer,
    };

    // Check 1: HTTPS enforcement (CRITICAL - REQUIRED)
    this.log(context, "Checking HTTPS enforcement...");
    const httpsCheck = this.isHTTPSEnforced(metadata);

    if (!httpsCheck.enforced) {
      criticalIssues.push(
        `❌ HTTPS not enforced for all endpoints:\n${httpsCheck.insecureEndpoints
          .map((e) => `  - ${e}`)
          .join("\n")}`
      );
      complianceDetails.https_enforced = false;
      complianceDetails.insecure_endpoints = httpsCheck.insecureEndpoints;
    } else {
      complianceDetails.https_enforced = true;
    }

    // Check 2: OIDC support (REQUIRED for AAL2 - need MFA detection)
    this.log(context, "Checking OIDC support...");
    const isOIDC = this.isOIDCProvider(metadata);
    complianceDetails.oidc_provider = isOIDC;

    if (!isOIDC) {
      criticalIssues.push(
        "❌ Not an OpenID Connect provider. AAL2 requires OIDC for proper multi-factor authentication context (ACR/AMR claims)."
      );
    } else {
      // Check 3: AAL2 support detection (CRITICAL)
      this.log(context, "Analyzing AAL2 support...");
      const aalSupport = this.detectAALSupport(metadata);
      const supportsAAL2 = aalSupport.supportedAALs.includes(AALLevel.AAL2);

      if (aalSupport.canDetermine) {
        complianceDetails.aal2_advertised = supportsAAL2;
        complianceDetails.acr_values = aalSupport.acrAnalysis.acrValues;

        if (!supportsAAL2) {
          criticalIssues.push(
            "❌ Provider does not advertise AAL2 support in ACR values. AAL2 requires explicit multi-factor authentication with cryptographic methods."
          );
        }
      } else {
        recommendations.push(
          "⚠️  Unable to determine AAL2 support from metadata. Implement acr_values_supported with AAL2 values."
        );
        complianceDetails.aal2_advertised = "unknown";
      }

      // Check 4: MFA indicators in metadata
      this.log(context, "Checking for MFA indicators...");
      const hasMFAIndicators = this.checkMFAIndicators(metadata);
      complianceDetails.mfa_indicators = hasMFAIndicators;

      if (!hasMFAIndicators.hasIndicators) {
        recommendations.push(
          "⚠️  No multi-factor authentication indicators found in metadata. Ensure your implementation supports MFA methods like OTP, TOTP, WebAuthn, or hardware tokens."
        );
      }

      // Check 5: Authentication event timestamp (REQUIRED for session management)
      const hasAuthTime = metadata.claims_supported?.includes("auth_time");
      complianceDetails.auth_time_supported = hasAuthTime || false;

      if (!hasAuthTime) {
        criticalIssues.push(
          "❌ auth_time claim not advertised. AAL2 requires authentication event timestamping for session timeout enforcement (12-hour maximum)."
        );
      }

      // Check 6: AMR claim support (RECOMMENDED for MFA verification)
      const hasAMRClaim = metadata.claims_supported?.includes("amr");
      complianceDetails.amr_claim_supported = hasAMRClaim || false;

      if (!hasAMRClaim) {
        recommendations.push(
          "⚠️  AMR (Authentication Method Reference) claim not advertised. Recommended for verifying which authentication factors were used."
        );
      }
    }

    // Determine result based on findings
    if (criticalIssues.length > 0) {
      // FAIL: Critical requirements not met
      return this.fail(
        this.buildFailureMessage(criticalIssues, recommendations),
        Severity.HIGH,
        this.buildRemediationGuidance(criticalIssues, recommendations),
        complianceDetails
      );
    }

    if (recommendations.length > 0) {
      // WARNING: All critical requirements met, but has recommendations
      return this.warning(
        this.buildWarningMessage(recommendations),
        this.buildRemediationGuidance([], recommendations),
        complianceDetails
      );
    }

    // PASS: All requirements met
    return this.pass(this.buildPassMessage(), complianceDetails);
  }

  /**
   * Check for multi-factor authentication indicators in metadata
   */
  private checkMFAIndicators(metadata: any): {
    hasIndicators: boolean;
    indicators: string[];
  } {
    const indicators: string[] = [];

    // Check ACR values for MFA patterns
    const acrValues = metadata.acr_values_supported || [];
    const mfaPatterns = [
      "mfa",
      "2fa",
      "multi",
      "aal:2",
      "aal2",
      "phr",
      "totp",
      "otp",
    ];

    for (const acr of acrValues) {
      const normalized = acr.toLowerCase();
      if (mfaPatterns.some((pattern) => normalized.includes(pattern))) {
        indicators.push(`ACR value: ${acr}`);
      }
    }

    // Check for WebAuthn/FIDO support
    if (metadata.code_challenge_methods_supported?.includes("S256")) {
      // PKCE is often used with WebAuthn
      indicators.push("PKCE support (often used with WebAuthn)");
    }

    return {
      hasIndicators: indicators.length > 0,
      indicators,
    };
  }

  /**
   * Build failure message for AAL2 non-compliance
   */
  private buildFailureMessage(
    issues: string[],
    recommendations: string[]
  ): string {
    let message = "AAL2 compliance check FAILED. Critical issues found:\n\n";
    message += issues.join("\n\n");

    if (recommendations.length > 0) {
      message += "\n\nAdditional recommendations:\n\n";
      message += recommendations.join("\n");
    }

    message += "\n\nAAL2 requires multi-factor authentication with at least one cryptographic factor.";

    return message;
  }

  /**
   * Build warning message for AAL2 partial compliance
   */
  private buildWarningMessage(recommendations: string[]): string {
    let message = "AAL2 compliance check passed with recommendations.\n\n";
    message +=
      "All critical AAL2 requirements are met, but the following improvements are recommended:\n\n";
    message += recommendations.join("\n");

    return message;
  }

  /**
   * Build pass message for full AAL2 compliance
   */
  private buildPassMessage(): string {
    return `AAL2 compliance check PASSED.

The provider meets all NIST SP 800-63B AAL2 requirements:
  ✅ HTTPS enforced for all endpoints
  ✅ OpenID Connect provider with MFA support
  ✅ AAL2 support advertised in metadata
  ✅ Authentication event timestamping supported (auth_time claim)
  ✅ Multi-factor authentication indicators present

AAL2 provides high authentication assurance through multi-factor authentication with cryptographic methods.

Session Requirements:
  - Maximum session duration: 12 hours
  - Idle timeout: 30 minutes (preferred) or 60 minutes (maximum)
  - Reauthentication required for sensitive operations`;
  }

  /**
   * Build remediation guidance based on findings
   */
  private buildRemediationGuidance(
    criticalIssues: string[],
    recommendations: string[]
  ): string {
    let guidance = "To achieve NIST AAL2 compliance:\n\n";

    // Critical fixes
    if (criticalIssues.length > 0) {
      guidance += "**Critical Fixes Required:**\n\n";

      if (criticalIssues.some((i) => i.includes("HTTPS"))) {
        guidance += `1. Enable HTTPS for all OAuth endpoints:

   Configure your server to use TLS 1.2 or higher for all endpoints.

   <pre><code>
   ✅ https://example.com/oauth/authorize
   ✅ https://example.com/oauth/token
   </code></pre>

`;
      }

      if (criticalIssues.some((i) => i.includes("OpenID Connect"))) {
        guidance += `2. Implement OpenID Connect:

   Add OIDC Discovery endpoint:
   <pre><code>
   GET /.well-known/openid-configuration
   </code></pre>

   Include id_token in response_types_supported:
   <pre><code>
   {
     "response_types_supported": ["code", "id_token", "code id_token"]
   }
   </code></pre>

`;
      }

      if (criticalIssues.some((i) => i.includes("AAL2"))) {
        guidance += `3. Implement and advertise AAL2 multi-factor authentication:

   Add AAL2 to acr_values_supported:
   <pre><code>
   {
     "acr_values_supported": [
       "urn:nist:800-63-3:aal:2",
       "urn:nist:800-63-3:aal:1"
     ],
     "claims_supported": ["acr", "amr", "auth_time"]
   }
   </code></pre>

   Implement MFA flows:
   - Password + OTP (Time-based or SMS)
   - Password + Hardware token (FIDO2/WebAuthn)
   - Password + Cryptographic certificate
   - Biometric + PIN

`;
      }

      if (criticalIssues.some((i) => i.includes("auth_time"))) {
        guidance += `4. Implement authentication event timestamping:

   Include auth_time in all ID tokens:
   <pre><code>
   {
     "iss": "https://your-server.com",
     "sub": "user123",
     "acr": "urn:nist:800-63-3:aal:2",
     "amr": ["pwd", "otp"],
     "auth_time": 1234567890
   }
   </code></pre>

   This enables proper session timeout enforcement (12-hour maximum for AAL2).

`;
      }
    }

    // Recommendations
    if (recommendations.length > 0) {
      guidance += "**Recommended Improvements:**\n\n";

      let stepNum = 1;

      if (recommendations.some((r) => r.includes("MFA") || r.includes("multi-factor"))) {
        guidance += `${stepNum}. Enhance MFA implementation:

   Supported AAL2 authentication methods:
   - **Cryptographic authenticators**: FIDO2/WebAuthn, smart cards, PKI certificates
   - **OTP tokens**: TOTP (Google Authenticator, Authy), HOTP, hardware tokens
   - **Push notifications**: Mobile app-based authentication
   - **SMS OTP**: Less secure but acceptable as second factor

   Example AMR values for ID tokens:
   <pre><code>
   "amr": ["pwd", "otp"]     // Password + Time-based OTP
   "amr": ["pwd", "hwk"]     // Password + Hardware key (FIDO2)
   "amr": ["pwd", "sms"]     // Password + SMS OTP
   "amr": ["pwd", "swk"]     // Password + Software key
   </code></pre>

`;
        stepNum++;
      }

      if (recommendations.some((r) => r.includes("AMR"))) {
        guidance += `${stepNum}. Implement AMR (Authentication Method Reference) claim:

   Add amr to claims_supported and include in ID tokens:
   <pre><code>
   {
     "claims_supported": ["sub", "iss", "acr", "amr", "auth_time"]
   }
   </code></pre>

   AMR provides transparency about which authentication factors were used.

`;
        stepNum++;
      }
    }

    guidance += `**AAL2 Session Management Requirements:**

- **Maximum session duration**: 12 hours from authentication
- **Idle timeout**: 30 minutes preferred, 60 minutes maximum
- **Reauthentication**: Required after timeout or for sensitive operations
- **Session binding**: Sessions must be bound to the authenticated device

**AAL2 Technical Requirements:**

1. **Multi-factor authentication** - At least two different factors
2. **Cryptographic factor** - At least one factor must use approved cryptography
3. **Replay resistance** - Implementation must prevent replay attacks
4. **Session management** - Proper timeout and reauthentication enforcement

**Additional Resources:**

- NIST SP 800-63B AAL2: https://pages.nist.gov/800-63-3/sp800-63b.html#aal2
- OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html
- RFC 8176 (AMR Values): https://www.rfc-editor.org/rfc/rfc8176.html
- FIDO2/WebAuthn: https://webauthn.io/`;

    return guidance.trim();
  }
}
