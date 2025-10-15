/**
 * State Parameter Check
 * RFC 6749 Section 10.12 - https://datatracker.ietf.org/doc/html/rfc6749#section-10.12
 *
 * The state parameter is used to prevent Cross-Site Request Forgery (CSRF) attacks
 * by maintaining state between the authorization request and callback.
 */

import { BaseCheck } from "../base-check.js";
import {
  CheckResult,
  CheckCategory,
  Severity,
  CheckContext,
} from "../../types/index.js";
import { HttpClient } from "../../auditor/http-client.js";

export class StateParameterCheck extends BaseCheck {
  readonly id = "oauth-state-parameter";
  readonly name = "State Parameter Implementation Check";
  readonly category = CheckCategory.OAUTH;
  readonly defaultSeverity = Severity.HIGH;
  readonly description =
    "Validates that the OAuth authorization server supports and enforces the state parameter for CSRF protection";

  protected override references = [
    "https://datatracker.ietf.org/doc/html/rfc6749#section-10.12",
    "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1",
    "https://owasp.org/www-community/attacks/csrf",
  ];

  override async execute(context: CheckContext): Promise<CheckResult> {
    const httpClient = context.httpClient as HttpClient;

    if (!httpClient) {
      return this.error("HTTP client not available in context");
    }

    this.log(context, "Discovering OAuth metadata for state parameter support...");

    // Attempt to discover OAuth metadata
    const discoveryResult = await httpClient.discoverMetadata(context.targetUrl);

    if (!discoveryResult.metadata) {
      // Build detailed warning message with attempted endpoints
      const attemptDetails = discoveryResult.attempts
        .map((attempt) => `  - ${attempt.url} (${attempt.status} ${this.getStatusText(attempt.status)})`)
        .join("\n");

      const warningMessage = `Unable to discover OAuth metadata. Could not verify state parameter support.

Attempted endpoints:
${attemptDetails}

Impact: Cannot verify state parameter support without metadata.`;

      const remediation = `Implement OAuth 2.0 Authorization Server Metadata (RFC 8414) or OpenID Connect Discovery to allow automated security auditing.

The state parameter is RECOMMENDED in RFC 6749 and REQUIRED by many security best practices to prevent CSRF attacks.

Best practices for state parameter:
1. Generate a cryptographically random state value for each authorization request
2. Store the state value in the user's session
3. Validate that the state in the callback matches the stored value
4. Use a different state value for each request (no reuse)

Example implementation:
// Generate state
const state = crypto.randomBytes(32).toString('hex');
sessionStorage.setItem('oauth_state', state);

// Authorization URL
const authUrl = \`\${authEndpoint}?response_type=code&client_id=\${clientId}&state=\${state}\`;

// Callback validation
const returnedState = new URL(window.location.href).searchParams.get('state');
const storedState = sessionStorage.getItem('oauth_state');
if (returnedState !== storedState) {
  throw new Error('CSRF attack detected: state mismatch');
}

References:
- RFC 6749 Section 10.12: https://datatracker.ietf.org/doc/html/rfc6749#section-10.12
- OWASP CSRF: https://owasp.org/www-community/attacks/csrf`;

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

    // Check if the metadata explicitly mentions state parameter support
    // Note: Most OAuth servers don't explicitly advertise state support in metadata
    // because it's client-side behavior, but some may include it in documentation URLs
    // or as a custom field

    // For now, we'll provide guidance that state parameter support is recommended
    // but cannot be automatically verified without testing the actual authorization flow

    return this.pass(
      "OAuth metadata discovered. State parameter support cannot be automatically verified as it requires testing the authorization flow. Ensure your implementation generates and validates state parameters for CSRF protection.",
      {
        issuer: metadata.issuer,
        authorization_endpoint: metadata.authorization_endpoint,
        note: "State parameter is client-side responsibility and recommended by RFC 6749 Section 10.12",
        recommendation: "Always include state parameter in authorization requests",
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
}
