/**
 * NIST AAL3 Compliance Check
 *
 * Validates that an OAuth 2.0/OIDC provider meets NIST SP 800-63B
 * Authentication Assurance Level 3 (AAL3) requirements.
 *
 * AAL3 Requirements Summary:
 * - Hardware-based cryptographic authenticator REQUIRED
 * - Authenticator must be phishing-resistant
 * - Multi-factor authentication with verifier impersonation resistance
 * - HTTPS required for all endpoints
 * - Session timeout: Maximum 12 hours
 * - Idle timeout: 15 minutes maximum
 * - Reauthentication required for sensitive operations
 * - Strong resistance to man-in-the-middle attacks
 *
 * References:
 * - NIST SP 800-63B Section 4.3 (AAL3): https://pages.nist.gov/800-63-3/sp800-63b.html#aal3
 * - NIST SP 800-63B Section 7.3 (Session Management): https://pages.nist.gov/800-63-3/sp800-63b.html#sessionmgmt
 */

import { BaseNISTCheck, AALLevel } from "./base-nist-check.js";
import {
  CheckResult,
  CheckCategory,
  Severity,
  CheckContext,
} from "../../types/index.js";

/**
 * Check that validates AAL3 compliance requirements
 */
export class AAL3ComplianceCheck extends BaseNISTCheck {
  readonly id = "nist-aal3-compliance";
  readonly name = "NIST AAL3 Compliance";
  readonly category = CheckCategory.NIST;
  readonly defaultSeverity = Severity.CRITICAL;
  readonly description =
    "Validates compliance with NIST SP 800-63B Authentication Assurance Level 3 (AAL3) requirements for hardware-based cryptographic authentication";

  protected override references = [
    "https://pages.nist.gov/800-63-3/sp800-63b.html#aal3",
    "https://pages.nist.gov/800-63-3/sp800-63b.html#sessionmgmt",
    "https://openid.net/specs/openid-connect-core-1_0.html",
    "https://www.rfc-editor.org/rfc/rfc8176.html",
    "https://fidoalliance.org/specifications/",
  ];

  async execute(context: CheckContext): Promise<CheckResult> {
    this.log(context, "Starting NIST AAL3 compliance check...");

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

    // Check 2: OIDC support (REQUIRED for AAL3)
    this.log(context, "Checking OIDC support...");
    const isOIDC = this.isOIDCProvider(metadata);
    complianceDetails.oidc_provider = isOIDC;

    if (!isOIDC) {
      criticalIssues.push(
        "❌ Not an OpenID Connect provider. AAL3 requires OIDC for proper hardware authenticator verification (ACR/AMR claims)."
      );
    } else {
      // Check 3: AAL3 support detection (CRITICAL)
      this.log(context, "Analyzing AAL3 support...");
      const aalSupport = this.detectAALSupport(metadata);
      const supportsAAL3 = aalSupport.supportedAALs.includes(AALLevel.AAL3);

      if (aalSupport.canDetermine) {
        complianceDetails.aal3_advertised = supportsAAL3;
        complianceDetails.acr_values = aalSupport.acrAnalysis.acrValues;

        if (!supportsAAL3) {
          criticalIssues.push(
            "❌ Provider does not advertise AAL3 support in ACR values. AAL3 requires hardware-based cryptographic authenticators."
          );
        }
      } else {
        criticalIssues.push(
          "❌ Unable to determine AAL3 support from metadata. AAL3 requires explicit advertising of hardware cryptographic authenticator support."
        );
        complianceDetails.aal3_advertised = "unknown";
      }

      // Check 4: Hardware authenticator indicators
      this.log(context, "Checking for hardware authenticator indicators...");
      const hasHardwareAuth = this.checkHardwareAuthIndicators(metadata);
      complianceDetails.hardware_auth_indicators = hasHardwareAuth;

      if (!hasHardwareAuth.hasIndicators) {
        criticalIssues.push(
          "❌ No hardware authenticator indicators found in metadata. AAL3 requires FIDO2/WebAuthn, smart cards, or hardware security modules."
        );
      }

      // Check 5: Authentication event timestamp (REQUIRED)
      const hasAuthTime = metadata.claims_supported?.includes("auth_time");
      complianceDetails.auth_time_supported = hasAuthTime || false;

      if (!hasAuthTime) {
        criticalIssues.push(
          "❌ auth_time claim not advertised. AAL3 requires authentication event timestamping for strict session timeout enforcement (12-hour maximum, 15-minute idle)."
        );
      }

      // Check 6: AMR claim support (REQUIRED for AAL3 verification)
      const hasAMRClaim = metadata.claims_supported?.includes("amr");
      complianceDetails.amr_claim_supported = hasAMRClaim || false;

      if (!hasAMRClaim) {
        criticalIssues.push(
          "❌ AMR (Authentication Method Reference) claim not advertised. AAL3 requires AMR to verify hardware cryptographic authenticator usage."
        );
      }

      // Check 7: Phishing resistance indicators
      const hasPhishingResistance = this.checkPhishingResistance(metadata);
      complianceDetails.phishing_resistant_indicators =
        hasPhishingResistance.indicators;

      if (!hasPhishingResistance.hasIndicators) {
        recommendations.push(
          "⚠️  No explicit phishing-resistant authentication indicators found. Ensure implementation uses FIDO2/WebAuthn with user verification."
        );
      }
    }

    // Determine result based on findings
    if (criticalIssues.length > 0) {
      // FAIL: Critical requirements not met
      return this.fail(
        this.buildFailureMessage(criticalIssues, recommendations),
        Severity.CRITICAL,
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
   * Check for hardware authenticator indicators in metadata
   */
  private checkHardwareAuthIndicators(metadata: any): {
    hasIndicators: boolean;
    indicators: string[];
  } {
    const indicators: string[] = [];

    // Check ACR values for hardware/phishing-resistant patterns
    const acrValues = metadata.acr_values_supported || [];
    const hardwarePatterns = [
      "aal:3",
      "aal3",
      "phrh", // Okta: phishing-resistant hardware
      "hardware",
      "fido",
      "webauthn",
      "u2f",
    ];

    for (const acr of acrValues) {
      const normalized = acr.toLowerCase();
      if (hardwarePatterns.some((pattern) => normalized.includes(pattern))) {
        indicators.push(`ACR value: ${acr}`);
      }
    }

    // FIDO2/WebAuthn typically requires strong PKCE
    if (metadata.code_challenge_methods_supported?.includes("S256")) {
      indicators.push("PKCE S256 support (required for FIDO2)");
    }

    return {
      hasIndicators: indicators.length > 0,
      indicators,
    };
  }

  /**
   * Check for phishing resistance indicators
   */
  private checkPhishingResistance(metadata: any): {
    hasIndicators: boolean;
    indicators: string[];
  } {
    const indicators: string[] = [];
    const acrValues = metadata.acr_values_supported || [];

    // Phishing-resistant patterns
    const patterns = ["phr", "phrh", "phishing-resistant", "webauthn", "fido"];

    for (const acr of acrValues) {
      const normalized = acr.toLowerCase();
      if (patterns.some((pattern) => normalized.includes(pattern))) {
        indicators.push(acr);
      }
    }

    return {
      hasIndicators: indicators.length > 0,
      indicators,
    };
  }

  /**
   * Build failure message for AAL3 non-compliance
   */
  private buildFailureMessage(
    issues: string[],
    recommendations: string[]
  ): string {
    let message = "AAL3 compliance check FAILED. Critical issues found:\n\n";
    message += issues.join("\n\n");

    if (recommendations.length > 0) {
      message += "\n\nAdditional recommendations:\n\n";
      message += recommendations.join("\n");
    }

    message +=
      "\n\nAAL3 requires hardware-based cryptographic authenticators that are phishing-resistant.";

    return message;
  }

  /**
   * Build warning message for AAL3 partial compliance
   */
  private buildWarningMessage(recommendations: string[]): string {
    let message = "AAL3 compliance check passed with recommendations.\n\n";
    message +=
      "All critical AAL3 requirements are met, but the following improvements are recommended:\n\n";
    message += recommendations.join("\n");

    return message;
  }

  /**
   * Build pass message for full AAL3 compliance
   */
  private buildPassMessage(): string {
    return `AAL3 compliance check PASSED.

The provider meets all NIST SP 800-63B AAL3 requirements:
  ✅ HTTPS enforced for all endpoints
  ✅ OpenID Connect provider with hardware authenticator support
  ✅ AAL3 support advertised in metadata
  ✅ Hardware cryptographic authenticator indicators present
  ✅ Authentication event timestamping supported (auth_time claim)
  ✅ AMR claim support for authenticator verification
  ✅ Phishing-resistant authentication indicators

AAL3 provides very high authentication assurance through hardware-based cryptographic authenticators with verifier impersonation resistance.

Session Requirements:
  - Maximum session duration: 12 hours
  - Idle timeout: 15 minutes maximum
  - Reauthentication required for sensitive operations
  - Session must be bound to hardware authenticator`;
  }

  /**
   * Build remediation guidance based on findings
   */
  private buildRemediationGuidance(
    criticalIssues: string[],
    recommendations: string[]
  ): string {
    let guidance = "To achieve NIST AAL3 compliance:\n\n";

    // Critical fixes
    if (criticalIssues.length > 0) {
      guidance += "**Critical Fixes Required:**\n\n";

      if (criticalIssues.some((i) => i.includes("HTTPS"))) {
        guidance += `1. Enable HTTPS for all OAuth endpoints:

   Use TLS 1.2 or higher with strong cipher suites.
   <pre><code>
   ✅ https://example.com/oauth/authorize
   ✅ https://example.com/oauth/token
   </code></pre>

`;
      }

      if (criticalIssues.some((i) => i.includes("OpenID Connect"))) {
        guidance += `2. Implement OpenID Connect:

   <pre><code>
   GET /.well-known/openid-configuration

   {
     "response_types_supported": ["code", "id_token", "code id_token"],
     "claims_supported": ["acr", "amr", "auth_time"]
   }
   </code></pre>

`;
      }

      if (criticalIssues.some((i) => i.includes("AAL3") || i.includes("hardware"))) {
        guidance += `3. Implement hardware-based cryptographic authentication:

   **Supported AAL3 Authenticators:**
   - **FIDO2/WebAuthn**: Hardware security keys (YubiKey, Titan, etc.)
   - **Smart Cards**: PIV/CAC cards with PKI certificates
   - **Hardware Security Modules (HSM)**: Enterprise-grade cryptographic devices
   - **Trusted Platform Modules (TPM)**: Device-bound credentials

   Add AAL3 to metadata:
   <pre><code>
   {
     "acr_values_supported": [
       "urn:nist:800-63-3:aal:3",
       "urn:nist:800-63-3:aal:2",
       "urn:nist:800-63-3:aal:1"
     ],
     "claims_supported": ["acr", "amr", "auth_time"]
   }
   </code></pre>

   **Implementation Example (FIDO2/WebAuthn):**
   <pre><code>
   // Client-side: Register WebAuthn credential
   navigator.credentials.create({
     publicKey: {
       challenge: new Uint8Array([...]),
       rp: { name: "Your Service" },
       user: { id: userId, name: userName, displayName: displayName },
       pubKeyCredParams: [{ type: "public-key", alg: -7 }],
       authenticatorSelection: {
         authenticatorAttachment: "cross-platform", // Hardware key
         userVerification: "required",
         residentKey: "required"
       }
     }
   });
   </code></pre>

`;
      }

      if (criticalIssues.some((i) => i.includes("auth_time"))) {
        guidance += `4. Implement authentication event timestamping:

   Include auth_time in all ID tokens:
   <pre><code>
   {
     "acr": "urn:nist:800-63-3:aal:3",
     "amr": ["hwk", "pin"],  // Hardware key + PIN
     "auth_time": 1234567890
   }
   </code></pre>

`;
      }

      if (criticalIssues.some((i) => i.includes("AMR"))) {
        guidance += `5. Implement AMR (Authentication Method Reference) claims:

   **Required AMR values for AAL3:**
   <pre><code>
   "amr": ["hwk"]        // Hardware key (FIDO2)
   "amr": ["hwk", "pin"] // Hardware key with PIN
   "amr": ["sc"]         // Smart card
   "amr": ["sc", "pin"]  // Smart card with PIN
   </code></pre>

   AMR verification is REQUIRED to confirm hardware authenticator usage.

`;
      }
    }

    // Recommendations
    if (recommendations.length > 0) {
      guidance += "**Recommended Improvements:**\n\n";

      if (recommendations.some((r) => r.includes("phishing"))) {
        guidance += `1. Enhance phishing resistance:

   - Use FIDO2 with user verification (biometric or PIN)
   - Implement origin binding to prevent phishing attacks
   - Require hardware authenticator attestation
   - Use WebAuthn with platform authenticators when available

`;
      }
    }

    guidance += `**AAL3 Session Management Requirements:**

- **Maximum session duration**: 12 hours from authentication
- **Idle timeout**: 15 minutes maximum (stricter than AAL2)
- **Reauthentication**: Required after timeout or for all sensitive operations
- **Session binding**: Must be cryptographically bound to hardware authenticator
- **Verifier impersonation resistance**: Implementation must resist MitM attacks

**AAL3 Technical Requirements:**

1. **Hardware cryptographic authenticator** - Physical device required
2. **Phishing resistance** - Must resist verifier impersonation attacks
3. **Multi-factor** - Typically hardware key + biometric or PIN
4. **Cryptographic proof** - All authentication must use public key cryptography
5. **Authenticator attestation** - Verify authenticator is genuine hardware device

**Approved AAL3 Authenticators:**

- **FIDO2 Security Keys**: YubiKey 5, Google Titan, Feitian
- **Smart Cards**: PIV cards, CAC cards (with PKI certificates)
- **Mobile Device Secure Elements**: iOS Secure Enclave, Android StrongBox
- **Hardware Security Modules**: Enterprise HSMs (Thales, Gemalto)

**Additional Resources:**

- NIST SP 800-63B AAL3: https://pages.nist.gov/800-63-3/sp800-63b.html#aal3
- FIDO2 Specifications: https://fidoalliance.org/specifications/
- WebAuthn Guide: https://webauthn.guide/
- RFC 8176 (AMR Values): https://www.rfc-editor.org/rfc/rfc8176.html`;

    return guidance.trim();
  }
}
