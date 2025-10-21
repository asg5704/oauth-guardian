/**
 * NIST AAL Detection Check
 *
 * Discovers and reports which NIST Authentication Assurance Levels (AAL) are
 * supported by an OAuth 2.0/OIDC provider based on metadata analysis.
 *
 * This is an informational check that provides visibility into AAL support
 * without enforcing specific compliance requirements.
 *
 * References:
 * - NIST SP 800-63B: https://pages.nist.gov/800-63-3/sp800-63b.html
 * - OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html
 */

import { BaseNISTCheck } from "./base-nist-check.js";
import {
  CheckResult,
  CheckCategory,
  Severity,
  CheckContext,
} from "../../types/index.js";

/**
 * Check that detects and reports supported NIST AAL levels
 */
export class AALDetectionCheck extends BaseNISTCheck {
  readonly id = "nist-aal-detection";
  readonly name = "NIST AAL Support Detection";
  readonly category = CheckCategory.NIST;
  readonly defaultSeverity = Severity.INFO;
  readonly description =
    "Discovers which NIST Authentication Assurance Levels (AAL1, AAL2, AAL3) are supported by analyzing OAuth/OIDC metadata";

  protected override references = [
    "https://pages.nist.gov/800-63-3/sp800-63b.html",
    "https://openid.net/specs/openid-connect-core-1_0.html#IDToken",
    "https://openid.net/specs/openid-connect-discovery-1_0.html",
  ];

  async execute(context: CheckContext): Promise<CheckResult> {
    this.log(context, "Starting NIST AAL detection...");

    // Discover OAuth/OIDC metadata
    const discoveryResult = await this.discoverMetadata(context);

    if (!discoveryResult.success || !discoveryResult.metadata) {
      return this.createMetadataWarning(
        discoveryResult.error || "Metadata discovery failed"
      );
    }

    const metadata = discoveryResult.metadata;

    // Check if this is an OIDC provider (NIST AAL requires OIDC)
    const isOIDC = this.isOIDCProvider(metadata);

    if (!isOIDC) {
      return this.skip(
        "This is not an OpenID Connect provider. NIST AAL compliance requires OIDC with ACR/AMR claims support."
      );
    }

    this.log(context, "OIDC provider detected, analyzing AAL support...");

    // Detect AAL support from metadata
    const aalSupport = this.detectAALSupport(metadata);
    const { highestAAL, supportedAALs, acrAnalysis, canDetermine } = aalSupport;

    // Case 1: No ACR values found - cannot determine AAL support
    if (!canDetermine) {
      const hasACRClaim = metadata.claims_supported?.includes("acr");
      const hasAMRClaim = metadata.claims_supported?.includes("amr");

      let message = "Unable to determine AAL support from metadata.";

      if (hasACRClaim || hasAMRClaim) {
        message += `\n\nThe provider supports ${hasACRClaim ? "ACR" : ""}${
          hasACRClaim && hasAMRClaim ? " and " : ""
        }${
          hasAMRClaim ? "AMR" : ""
        } claims, but does not advertise specific ACR values in metadata.`;
        message +=
          "\n\nAAL support may be available but requires manual verification:";
        message +=
          "\n  1. Consult provider documentation for supported ACR values";
        message += "\n  2. Test authentication flows with acr_values parameter";
        message += "\n  3. Inspect ID token claims for acr and amr values";
      } else {
        message +=
          "\n\nThe provider does not advertise ACR or AMR claim support in metadata.";
      }

      return this.warning(message, this.getACRImplementationGuidance(), {
        issuer: metadata.issuer,
        acr_claim_supported: hasACRClaim,
        amr_claim_supported: hasAMRClaim,
        claims_supported: metadata.claims_supported,
      });
    }

    // Case 2: ACR values found with unmapped values
    if (acrAnalysis.unmappedValues.length > 0) {
      const mappedAALs = supportedAALs
        .map((aal) => this.formatAAL(aal))
        .join(", ");
      const unmappedList = acrAnalysis.unmappedValues
        .map((v) => `  - ${v}`)
        .join("\n");

      const message = `AAL support detected with ${
        acrAnalysis.confidence
      } confidence.

Detected AAL levels: ${mappedAALs}
Highest AAL: ${highestAAL ? this.formatAAL(highestAAL) : "Unknown"}

The following ACR values could not be mapped to NIST AAL levels:
${unmappedList}

These may be provider-specific or custom ACR values. Consult your provider's documentation for their meaning.`;

      return this.pass(message, {
        issuer: metadata.issuer,
        highest_aal: highestAAL,
        supported_aals: supportedAALs,
        detected_acr_values: acrAnalysis.acrValues,
        unmapped_acr_values: acrAnalysis.unmappedValues,
        confidence: acrAnalysis.confidence,
        acr_values_supported: metadata.acr_values_supported,
      });
    }

    // Case 3: All ACR values successfully mapped
    const aalList = supportedAALs
      .map((aal) => this.formatAAL(aal))
      .join("\n  - ");
    const acrList = acrAnalysis.acrValues.map((v) => `  - ${v}`).join("\n");

    const message = `NIST AAL support detected with ${
      acrAnalysis.confidence
    } confidence.

Supported AAL levels:
  - ${aalList}

Highest AAL: ${this.formatAAL(highestAAL!)}

Detected ACR values:
${acrList}

The provider properly advertises AAL support in metadata, enabling automated compliance verification.`;

    return this.pass(message, {
      issuer: metadata.issuer,
      highest_aal: highestAAL,
      supported_aals: supportedAALs,
      detected_acr_values: acrAnalysis.acrValues,
      confidence: acrAnalysis.confidence,
      acr_values_supported: metadata.acr_values_supported,
      claims_supported: metadata.claims_supported,
    });
  }

  /**
   * Get guidance for implementing ACR support
   */
  private getACRImplementationGuidance(): string {
    return `
To implement NIST AAL support with proper metadata advertising:

1. Implement OpenID Connect Discovery:
   Endpoint: /.well-known/openid-configuration

2. Add acr_values_supported to your metadata response:
<pre><code>
{
  "issuer": "https://your-server.com",
  "acr_values_supported": [
    "urn:nist:800-63-3:aal:1",
    "urn:nist:800-63-3:aal:2",
    "urn:nist:800-63-3:aal:3"
  ],
  "claims_supported": [
    "sub", "iss", "aud", "exp", "iat",
    "acr", "amr", "auth_time"
  ]
}
</code></pre>
3. Support the acr_values parameter in authorization requests:
GET /authorize?
  response_type=code
  &client_id=CLIENT_ID
  &redirect_uri=REDIRECT_URI
  &scope=openid
  &acr_values=urn:nist:800-63-3:aal:2

4. Include acr and amr claims in ID tokens:
<pre><code>
{
  "iss": "https://your-server.com",
  "sub": "user123",
  "aud": "client_id",
  "exp": 1234567890,
  "iat": 1234567800,
  "acr": "urn:nist:800-63-3:aal:2",
  "amr": ["pwd", "otp"]
}
</code></pre>

5. Implement authentication flows for each AAL level:
   - AAL1: Single-factor (password) or multi-factor
   - AAL2: Multi-factor with cryptographic methods
   - AAL3: Hardware-based cryptographic authenticator

References:
- NIST SP 800-63B: https://pages.nist.gov/800-63-3/sp800-63b.html
- OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html
- RFC 8176 (AMR Values): https://www.rfc-editor.org/rfc/rfc8176.html
`.trim();
  }
}
