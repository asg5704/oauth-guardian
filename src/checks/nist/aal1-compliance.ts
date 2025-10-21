/**
 * NIST AAL1 Compliance Check
 *
 * Validates that an OAuth 2.0/OIDC provider meets NIST SP 800-63B
 * Authentication Assurance Level 1 (AAL1) requirements.
 *
 * AAL1 Requirements Summary:
 * - Single-factor OR multi-factor authentication
 * - HTTPS required for all endpoints
 * - Session timeout: Maximum 30 days (720 hours)
 * - No specific idle timeout requirement
 * - Authentication event timestamping recommended
 *
 * References:
 * - NIST SP 800-63B Section 4.1 (AAL1): https://pages.nist.gov/800-63-3/sp800-63b.html#aal1
 * - NIST SP 800-63B Section 7.1 (Session Management): https://pages.nist.gov/800-63-3/sp800-63b.html#sessionmgmt
 */

import { BaseNISTCheck, AALLevel } from "./base-nist-check.js";
import {
  CheckResult,
  CheckCategory,
  Severity,
  CheckContext,
} from "../../types/index.js";

/**
 * Check that validates AAL1 compliance requirements
 */
export class AAL1ComplianceCheck extends BaseNISTCheck {
  readonly id = "nist-aal1-compliance";
  readonly name = "NIST AAL1 Compliance";
  readonly category = CheckCategory.NIST;
  readonly defaultSeverity = Severity.MEDIUM;
  readonly description =
    "Validates compliance with NIST SP 800-63B Authentication Assurance Level 1 requirements for OAuth 2.0/OIDC providers";

  protected override references = [
    "https://pages.nist.gov/800-63-3/sp800-63b.html#aal1",
    "https://pages.nist.gov/800-63-3/sp800-63b.html#sessionmgmt",
    "https://openid.net/specs/openid-connect-core-1_0.html",
  ];

  async execute(context: CheckContext): Promise<CheckResult> {
    this.log(context, "Starting NIST AAL1 compliance check...");

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

    // Check 2: OIDC support (RECOMMENDED for AAL implementation)
    this.log(context, "Checking OIDC support...");
    const isOIDC = this.isOIDCProvider(metadata);
    complianceDetails.oidc_provider = isOIDC;

    if (!isOIDC) {
      recommendations.push(
        "⚠️  Not an OpenID Connect provider. While OAuth 2.0 alone can meet AAL1 baseline requirements, OIDC provides better support for authentication context and claims."
      );
    } else {
      // Check 3: ACR/AMR support (RECOMMENDED for OIDC providers)
      this.log(context, "Analyzing AAL support...");
      const aalSupport = this.detectAALSupport(metadata);

      // Check if AAL1 is advertised
      const supportsAAL1 = aalSupport.supportedAALs.includes(AALLevel.AAL1);

      if (aalSupport.canDetermine) {
        complianceDetails.aal1_advertised = supportsAAL1;
        complianceDetails.acr_values = aalSupport.acrAnalysis.acrValues;

        if (!supportsAAL1) {
          recommendations.push(
            "⚠️  Provider does not advertise AAL1 support in ACR values. Consider adding explicit AAL1 ACR value (e.g., 'urn:nist:800-63-3:aal:1')"
          );
        }
      } else {
        recommendations.push(
          "⚠️  Unable to determine AAL support from metadata. Consider implementing acr_values_supported in discovery metadata."
        );
        complianceDetails.aal1_advertised = "unknown";
      }

      // Check 4: Authentication event timestamp (RECOMMENDED)
      const hasAuthTime = metadata.claims_supported?.includes("auth_time");
      complianceDetails.auth_time_supported = hasAuthTime || false;

      if (!hasAuthTime) {
        recommendations.push(
          "⚠️  auth_time claim not advertised. NIST recommends timestamping authentication events for session management."
        );
      }
    }

    // Determine result based on findings
    if (criticalIssues.length > 0) {
      // FAIL: Critical requirements not met (HTTPS)
      return this.fail(
        this.buildFailureMessage(criticalIssues, recommendations),
        Severity.MEDIUM,
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
   * Build failure message for AAL1 non-compliance
   */
  private buildFailureMessage(
    issues: string[],
    recommendations: string[]
  ): string {
    let message = "AAL1 compliance check FAILED. Critical issues found:\n\n";
    message += issues.join("\n\n");

    if (recommendations.length > 0) {
      message += "\n\nAdditional recommendations:\n\n";
      message += recommendations.join("\n");
    }

    return message;
  }

  /**
   * Build warning message for AAL1 partial compliance
   */
  private buildWarningMessage(recommendations: string[]): string {
    let message = "AAL1 compliance check passed with recommendations.\n\n";
    message +=
      "All critical AAL1 requirements are met (HTTPS enforcement), but the following improvements are recommended:\n\n";
    message += recommendations.join("\n");

    return message;
  }

  /**
   * Build pass message for full AAL1 compliance
   */
  private buildPassMessage(): string {
    return `AAL1 compliance check PASSED.

The provider meets all NIST SP 800-63B AAL1 requirements:
  ✅ HTTPS enforced for all endpoints
  ✅ OpenID Connect provider with proper authentication context support
  ✅ AAL1 support advertised in metadata
  ✅ Authentication event timestamping supported (auth_time claim)

AAL1 provides basic authentication assurance through single-factor or multi-factor authentication with secure transport.`;
  }

  /**
   * Build remediation guidance based on findings
   */
  private buildRemediationGuidance(
    criticalIssues: string[],
    recommendations: string[]
  ): string {
    let guidance = "To achieve NIST AAL1 compliance:\n\n";

    // Critical fixes
    if (criticalIssues.length > 0) {
      guidance += "**Critical Fixes Required:**\n\n";

      if (criticalIssues.some((i) => i.includes("HTTPS"))) {
        guidance += `1. Enable HTTPS for all OAuth endpoints:

   Configure your server to use TLS 1.2 or higher for:
   - Authorization endpoint
   - Token endpoint
   - OIDC discovery endpoint
   - JWKS endpoint

   Example (authorization_endpoint):
   ❌ http://example.com/oauth/authorize
   ✅ https://example.com/oauth/authorize

`;
      }
    }

    // Recommendations
    if (recommendations.length > 0) {
      guidance += "**Recommended Improvements:**\n\n";

      let stepNum = 1;

      if (recommendations.some((r) => r.includes("OpenID Connect"))) {
        guidance += `${stepNum}. Implement OpenID Connect:

   Add OIDC Discovery endpoint:
   GET /.well-known/openid-configuration

   Include id_token in response_types_supported:
   <pre><code>
   {
     "response_types_supported": ["code", "id_token", "code id_token"]
   }
  </code></pre>
`;
        stepNum++;
      }

      if (
        recommendations.some(
          (r) => r.includes("AAL1") || r.includes("AAL support")
        )
      ) {
        guidance += `${stepNum}. Advertise AAL1 support in metadata:

   Add to .well-known/openid-configuration:
   <pre><code>
   {
     "acr_values_supported": [
       "urn:nist:800-63-3:aal:1"
     ],
     "claims_supported": ["acr", "amr", "auth_time"]
   }
  </code></pre>

   Include acr claim in ID tokens:
   <pre><code>
   {
     "iss": "https://your-server.com",
     "sub": "user123",
     "acr": "urn:nist:800-63-3:aal:1",
     "auth_time": 1234567890
   }
      </code></pre>
`;
        stepNum++;
      }

      if (recommendations.some((r) => r.includes("auth_time"))) {
        guidance += `${stepNum}. Support authentication event timestamping:

   Include auth_time in claims_supported metadata
   Include auth_time claim in all ID tokens

   This enables relying parties to enforce session timeouts
   per NIST requirements (max 30 days for AAL1).

`;
      }
    }

    guidance += `**AAL1 Session Requirements:**

- Maximum session duration: 30 days (720 hours)
- No specific idle timeout requirement
- Reauthentication required after session expiration

**Additional Resources:**

- NIST SP 800-63B AAL1: https://pages.nist.gov/800-63-3/sp800-63b.html#aal1
- OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html
- RFC 8414 (OAuth Metadata): https://datatracker.ietf.org/doc/html/rfc8414`;

    return guidance.trim();
  }
}
