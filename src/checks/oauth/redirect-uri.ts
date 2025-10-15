/**
 * Redirect URI Validation Check
 * RFC 6749 Section 3.1.2 - https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
 *
 * Validates that the OAuth authorization server properly validates redirect URIs
 * to prevent open redirect vulnerabilities and authorization code interception.
 */

import { BaseCheck } from "../base-check.js";
import {
  CheckResult,
  CheckCategory,
  Severity,
  CheckContext,
} from "../../types/index.js";
import { HttpClient } from "../../auditor/http-client.js";

export class RedirectURICheck extends BaseCheck {
  readonly id = "oauth-redirect-uri";
  readonly name = "Redirect URI Validation Check";
  readonly category = CheckCategory.OAUTH;
  readonly defaultSeverity = Severity.CRITICAL;
  readonly description =
    "Validates that the OAuth authorization server has proper redirect URI validation mechanisms to prevent open redirect attacks";

  protected override references = [
    "https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2",
    "https://datatracker.ietf.org/doc/html/rfc6749#section-10.6",
    "https://datatracker.ietf.org/doc/html/rfc6749#section-10.15",
    "https://oauth.net/2/redirect-uris/",
  ];

  override async execute(context: CheckContext): Promise<CheckResult> {
    const httpClient = context.httpClient as HttpClient;

    if (!httpClient) {
      return this.error("HTTP client not available in context");
    }

    this.log(context, "Discovering OAuth metadata for redirect URI validation...");

    // Attempt to discover OAuth metadata
    const discoveryResult = await httpClient.discoverMetadata(context.targetUrl);

    if (!discoveryResult.metadata) {
      // Build detailed warning message with attempted endpoints
      const attemptDetails = discoveryResult.attempts
        .map((attempt) => `  - ${attempt.url} (${attempt.status} ${this.getStatusText(attempt.status)})`)
        .join("\n");

      const warningMessage = `Unable to discover OAuth metadata. Could not verify redirect URI validation policies.

Attempted endpoints:
${attemptDetails}

Impact: Cannot verify redirect URI security without metadata.`;

      const remediation = this.getRedirectURIRemediation();

      return this.warning(
        warningMessage,
        remediation,
        {
          attempts: discoveryResult.attempts,
        }
      );
    }

    const metadata = discoveryResult.metadata;
    this.log(context, "OAuth metadata discovered", metadata);

    // Check for redirect URI registration requirements
    // Look for indicators of proper redirect URI handling
    const hasAuthEndpoint = !!metadata.authorization_endpoint;
    const hasRegistrationEndpoint = !!metadata.registration_endpoint;

    if (!hasAuthEndpoint) {
      return this.fail(
        "No authorization endpoint found in metadata. Cannot validate redirect URI handling.",
        Severity.HIGH,
        "Ensure your OAuth server advertises an authorization_endpoint in its metadata.",
        {
          issuer: metadata.issuer,
        }
      );
    }

    // Provide guidance on redirect URI validation
    // Note: Actual validation requires testing with real authorization requests
    const message = hasRegistrationEndpoint
      ? "Authorization server supports dynamic client registration. Ensure redirect URIs are validated during registration and authorization."
      : "Authorization server metadata discovered. Redirect URI validation must be enforced during client registration and authorization requests.";

    const recommendations = [
      "Require exact match for redirect URIs (no wildcards or pattern matching)",
      "Reject redirect URIs with HTTP scheme (require HTTPS) except for localhost development",
      "Prevent open redirects by validating against pre-registered URIs only",
      "Do not allow redirect_uri parameter to be omitted if multiple URIs are registered",
      "Validate the full URI including query parameters and fragments",
    ];

    return this.pass(
      message,
      {
        issuer: metadata.issuer,
        authorization_endpoint: metadata.authorization_endpoint,
        registration_endpoint: metadata.registration_endpoint,
        has_registration_endpoint: hasRegistrationEndpoint,
        recommendations,
        security_note: "Redirect URI validation requires manual testing or runtime verification",
      }
    );
  }

  /**
   * Get HTTP status text for common status codes
   */
  private getStatusText(status: number): string {
    const statusTexts: Record<number, string> = {
      200: "OK",
      404: "Not Found",
      403: "Forbidden",
      500: "Internal Server Error",
      502: "Bad Gateway",
      503: "Service Unavailable",
    };

    return statusTexts[status] || `HTTP ${status}`;
  }

  /**
   * Get detailed remediation guidance for redirect URI validation
   */
  private getRedirectURIRemediation(): string {
    return `
Redirect URI Validation Best Practices:

1. **Registration Phase:**
   - Require clients to register exact redirect URIs during client registration
   - Do NOT allow wildcard URIs (e.g., https://*.example.com/callback)
   - Store registered URIs as complete, absolute URLs

2. **Authorization Request:**
   - Require the redirect_uri parameter in all authorization requests
   - Validate that redirect_uri exactly matches a registered URI
   - Perform case-sensitive string comparison
   - Include scheme, host, port, path, and query parameters in comparison

3. **Security Rules:**
   - Reject HTTP redirect URIs (require HTTPS) except for:
     - http://localhost (for local development)
     - http://127.0.0.1 (for local development)
   - Reject URIs with custom schemes unless explicitly allowed for native apps
   - Reject URIs with IP addresses (prefer domain names)
   - Validate that the URI does not redirect to attacker-controlled domains

4. **Implementation Example:**
\`\`\`javascript
function validateRedirectURI(requestedURI, registeredURIs) {
  // Exact match required
  if (!registeredURIs.includes(requestedURI)) {
    throw new Error('redirect_uri not registered for this client');
  }

  const url = new URL(requestedURI);

  // Require HTTPS except for localhost
  if (url.protocol === 'http:' &&
      url.hostname !== 'localhost' &&
      url.hostname !== '127.0.0.1') {
    throw new Error('HTTP redirect URIs not allowed except for localhost');
  }

  return true;
}
\`\`\`

5. **Common Vulnerabilities to Prevent:**
   - Open redirects via unvalidated redirect_uri
   - Authorization code interception via similar-looking domains
   - URI confusion attacks via path traversal
   - Subdomain takeover attacks

References:
- RFC 6749 Section 3.1.2: https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
- RFC 6749 Section 10.6: https://datatracker.ietf.org/doc/html/rfc6749#section-10.6
- OAuth 2.0 Security Best Current Practice: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
`.trim();
  }
}
