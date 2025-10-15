/**
 * PKCE (Proof Key for Code Exchange) Check
 * RFC 7636 - https://datatracker.ietf.org/doc/html/rfc7636
 *
 * PKCE is a security extension to OAuth 2.0 that protects against authorization
 * code interception attacks, particularly important for mobile and SPA applications.
 */

import { BaseCheck } from "../base-check.js";
import {
  CheckResult,
  CheckCategory,
  Severity,
  CheckContext,
} from "../../types/index.js";
import { HttpClient } from "../../auditor/http-client.js";

export class PKCECheck extends BaseCheck {
  readonly id = "oauth-pkce";
  readonly name = "PKCE Implementation Check";
  readonly category = CheckCategory.OAUTH;
  readonly defaultSeverity = Severity.HIGH;
  readonly description =
    "Validates that PKCE (Proof Key for Code Exchange) is supported and enforced for OAuth 2.0 authorization code flow";

  protected override references = [
    "https://datatracker.ietf.org/doc/html/rfc7636",
    "https://oauth.net/2/pkce/",
    "https://www.oauth.com/oauth2-servers/pkce/",
  ];

  override async execute(context: CheckContext): Promise<CheckResult> {
    const httpClient = context.httpClient as HttpClient;

    if (!httpClient) {
      return this.error("HTTP client not available in context");
    }

    this.log(context, "Discovering OAuth metadata...");

    // Attempt to discover OAuth metadata
    const discoveryResult = await httpClient.discoverMetadata(context.targetUrl);

    if (!discoveryResult.metadata) {
      // Build detailed warning message with attempted endpoints
      const attemptDetails = discoveryResult.attempts
        .map((attempt) => `  - ${attempt.url} (${attempt.status} ${this.getStatusText(attempt.status)})`)
        .join("\n");

      const warningMessage = `Unable to discover OAuth metadata. Could not verify PKCE support.

Attempted endpoints:
${attemptDetails}

Impact: Cannot verify PKCE support without metadata.`;

      const remediation = `Implement OAuth 2.0 Authorization Server Metadata (RFC 8414) or OpenID Connect Discovery to allow automated security auditing.

Add one of these endpoints to your server:
  - /.well-known/oauth-authorization-server (RFC 8414)
  - /.well-known/openid-configuration (OpenID Connect Discovery)

These endpoints should return JSON metadata including:
{
  "issuer": "https://your-server.com",
  "authorization_endpoint": "https://your-server.com/oauth/authorize",
  "token_endpoint": "https://your-server.com/oauth/token",
  "code_challenge_methods_supported": ["S256", "plain"]
}

References:
- RFC 8414: https://datatracker.ietf.org/doc/html/rfc8414
- OpenID Connect Discovery: https://openid.net/specs/openid-connect-discovery-1_0.html`;

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

    // Check if PKCE is supported
    const pkceSupported = this.isPKCESupported(metadata);

    if (!pkceSupported) {
      return this.fail(
        "PKCE is not supported by this OAuth server. The server does not advertise code_challenge_methods_supported in its metadata.",
        Severity.HIGH,
        this.getRemediationGuidance(),
        {
          issuer: metadata.issuer,
          authorization_endpoint: metadata.authorization_endpoint,
          token_endpoint: metadata.token_endpoint,
        }
      );
    }

    const supportedMethods = metadata.code_challenge_methods_supported || [];

    // Check if S256 (SHA-256) is supported (recommended method)
    const s256Supported = supportedMethods.includes("S256");

    if (!s256Supported) {
      return this.warning(
        `PKCE is supported, but the recommended S256 method is not available. Supported methods: ${supportedMethods.join(", ")}`,
        "Add S256 (SHA-256) support to your PKCE implementation. The 'plain' method is less secure.",
        {
          issuer: metadata.issuer,
          supported_methods: supportedMethods,
        }
      );
    }

    this.log(context, "PKCE check passed with S256 support");

    return this.pass(
      `PKCE is properly supported with S256 method. Supported methods: ${supportedMethods.join(", ")}`,
      {
        issuer: metadata.issuer,
        supported_methods: supportedMethods,
        authorization_endpoint: metadata.authorization_endpoint,
      }
    );
  }

  /**
   * Check if PKCE is supported based on OAuth metadata
   */
  private isPKCESupported(metadata: Record<string, unknown>): boolean {
    const methods = metadata.code_challenge_methods_supported;

    if (!methods) {
      return false;
    }

    if (!Array.isArray(methods)) {
      return false;
    }

    return methods.length > 0;
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
   * Get detailed remediation guidance
   */
  private getRemediationGuidance(): string {
    return `
To implement PKCE on your OAuth server:

1. Add support for the code_challenge and code_challenge_method parameters in authorization requests
2. Store the code_challenge with the authorization code
3. Require code_verifier in token exchange requests
4. Verify that SHA-256(code_verifier) matches the stored code_challenge
5. Advertise support in your /.well-known/oauth-authorization-server metadata:

{
  "code_challenge_methods_supported": ["S256", "plain"]
}

Example authorization request with PKCE:
GET /authorize?
  response_type=code
  &client_id=CLIENT_ID
  &redirect_uri=REDIRECT_URI
  &code_challenge=CHALLENGE
  &code_challenge_method=S256

Example token request with PKCE:
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=AUTH_CODE
&redirect_uri=REDIRECT_URI
&client_id=CLIENT_ID
&code_verifier=VERIFIER

References:
- RFC 7636: https://datatracker.ietf.org/doc/html/rfc7636
- OAuth.net PKCE Guide: https://oauth.net/2/pkce/
`.trim();
  }
}
