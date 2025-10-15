/**
 * Token Storage Security Check
 * OWASP Top 10 A02:2021 - Cryptographic Failures
 *
 * Validates token endpoint security and provides guidance on secure token storage.
 * This check focuses on server-side token endpoint configuration and client-side
 * token storage best practices.
 */

import { BaseCheck } from "../base-check.js";
import {
  CheckResult,
  CheckCategory,
  Severity,
  CheckContext,
} from "../../types/index.js";
import { HttpClient } from "../../auditor/http-client.js";

export class TokenStorageCheck extends BaseCheck {
  readonly id = "oauth-token-storage";
  readonly name = "Token Storage Security Check";
  readonly category = CheckCategory.OAUTH;
  readonly defaultSeverity = Severity.HIGH;
  readonly description =
    "Validates token endpoint security and provides guidance on secure token storage practices";

  protected override references = [
    "https://datatracker.ietf.org/doc/html/rfc6749#section-10.3",
    "https://datatracker.ietf.org/doc/html/rfc6750",
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/01-Testing_for_Session_Management_Schema",
    "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage",
  ];

  override async execute(context: CheckContext): Promise<CheckResult> {
    const httpClient = context.httpClient as HttpClient;

    if (!httpClient) {
      return this.error("HTTP client not available in context");
    }

    this.log(context, "Discovering OAuth metadata for token endpoint security...");

    // Attempt to discover OAuth metadata
    const discoveryResult = await httpClient.discoverMetadata(context.targetUrl);

    if (!discoveryResult.metadata) {
      // Build detailed warning message with attempted endpoints
      const attemptDetails = discoveryResult.attempts
        .map((attempt) => `  - ${attempt.url} (${attempt.status} ${this.getStatusText(attempt.status)})`)
        .join("\n");

      const warningMessage = `Unable to discover OAuth metadata. Could not verify token endpoint security.

Attempted endpoints:
${attemptDetails}

Impact: Cannot verify token endpoint configuration without metadata.`;

      const remediation = this.getTokenStorageRemediation();

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

    const tokenEndpoint = metadata.token_endpoint;

    if (!tokenEndpoint) {
      return this.fail(
        "No token endpoint found in OAuth metadata. Token endpoint is required for secure token issuance.",
        Severity.CRITICAL,
        "Configure and advertise a token_endpoint in your OAuth server metadata.",
        {
          issuer: metadata.issuer,
        }
      );
    }

    // Check if token endpoint uses HTTPS
    const tokenURL = new URL(tokenEndpoint);
    const usesHTTPS = tokenURL.protocol === "https:";

    if (!usesHTTPS && tokenURL.hostname !== "localhost" && tokenURL.hostname !== "127.0.0.1") {
      return this.fail(
        `Token endpoint uses insecure HTTP protocol: ${tokenEndpoint}. Tokens MUST be transmitted over HTTPS to prevent interception.`,
        Severity.CRITICAL,
        "Configure your token endpoint to use HTTPS. Tokens contain sensitive credentials and must be protected in transit.",
        {
          issuer: metadata.issuer,
          token_endpoint: tokenEndpoint,
          protocol: tokenURL.protocol,
        }
      );
    }

    // Check for token endpoint authentication methods
    const tokenAuthMethods = metadata.token_endpoint_auth_methods_supported || [];
    const hasSecureAuthMethods = tokenAuthMethods.length > 0;

    let authMethodWarnings: string[] = [];

    // Check for weak authentication methods
    if (tokenAuthMethods.includes("none")) {
      authMethodWarnings.push("'none' authentication method is supported (public clients only)");
    }

    if (tokenAuthMethods.includes("client_secret_post") &&
        !tokenAuthMethods.includes("client_secret_basic") &&
        !tokenAuthMethods.includes("private_key_jwt")) {
      authMethodWarnings.push("Consider supporting more secure methods like 'private_key_jwt'");
    }

    const recommendations = this.getClientSideRecommendations();

    if (authMethodWarnings.length > 0) {
      return this.warning(
        `Token endpoint found at ${tokenEndpoint} (HTTPS ✓). ${authMethodWarnings.join(". ")}.`,
        `Server-side: ${authMethodWarnings.join(". ")}.\n\nClient-side recommendations:\n${recommendations}`,
        {
          issuer: metadata.issuer,
          token_endpoint: tokenEndpoint,
          uses_https: usesHTTPS,
          auth_methods: tokenAuthMethods,
          warnings: authMethodWarnings,
        }
      );
    }

    return this.pass(
      `Token endpoint properly configured at ${tokenEndpoint} using HTTPS. ${hasSecureAuthMethods ? `Supported auth methods: ${tokenAuthMethods.join(", ")}` : "Ensure proper client authentication."}`,
      {
        issuer: metadata.issuer,
        token_endpoint: tokenEndpoint,
        uses_https: usesHTTPS,
        auth_methods: tokenAuthMethods,
        client_storage_recommendations: recommendations,
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
   * Get client-side token storage recommendations
   */
  private getClientSideRecommendations(): string {
    return `1. Never store tokens in localStorage (vulnerable to XSS)
2. Use httpOnly, secure, SameSite cookies when possible
3. For SPAs, consider using the Backend-for-Frontend (BFF) pattern
4. Implement short-lived access tokens with refresh token rotation
5. Clear tokens on logout and session expiration`;
  }

  /**
   * Get detailed remediation guidance for token storage
   */
  private getTokenStorageRemediation(): string {
    return `
Token Storage Security Best Practices:

**Server-Side (Authorization Server):**

1. **Token Endpoint Security:**
   - Use HTTPS for token endpoint (required)
   - Implement proper client authentication
   - Support secure auth methods: client_secret_basic, private_key_jwt, client_secret_jwt
   - Validate client credentials on every token request
   - Implement rate limiting to prevent brute force attacks

2. **Token Generation:**
   - Use cryptographically secure random values
   - Implement short expiration times (access tokens: 5-60 minutes)
   - Use refresh tokens for long-lived sessions
   - Implement refresh token rotation
   - Bind tokens to specific clients and users

3. **Token Format:**
   - Use JWT with proper signing (RS256, ES256)
   - Include essential claims: iss, sub, aud, exp, iat
   - Keep token size minimal
   - Never include sensitive data in tokens

**Client-Side (Application):**

1. **Web Applications (Confidential Clients):**
   - Store tokens server-side in encrypted session storage
   - Use httpOnly, secure, SameSite=Strict cookies
   - Never expose tokens to JavaScript
   - Implement CSRF protection

2. **Single Page Applications (Public Clients):**
   - Use Authorization Code Flow with PKCE
   - Consider Backend-for-Frontend (BFF) pattern
   - If storing in browser:
     * Use sessionStorage (not localStorage)
     * Implement short-lived tokens
     * Clear on window close
   - Never store refresh tokens in browser storage
   - Implement proper logout

3. **Mobile Applications:**
   - Use system keychain/keystore
   - Enable biometric authentication
   - Implement certificate pinning
   - Use secure storage APIs provided by the platform

4. **Security Measures:**
   \`\`\`javascript
   // BAD: localStorage (persists, accessible to XSS)
   localStorage.setItem('access_token', token); // ❌ DON'T DO THIS

   // BETTER: sessionStorage (clears on close, but still XSS-vulnerable)
   sessionStorage.setItem('access_token', token); // ⚠️ Only if necessary

   // BEST: httpOnly cookie (not accessible to JavaScript)
   // Set server-side:
   Set-Cookie: access_token=xxx; HttpOnly; Secure; SameSite=Strict; Max-Age=300
   \`\`\`

5. **Token Lifecycle:**
   - Validate tokens on every request
   - Implement token refresh before expiration
   - Clear tokens on logout
   - Revoke tokens on suspicious activity
   - Monitor for token theft/reuse

References:
- RFC 6749 Section 10.3: https://datatracker.ietf.org/doc/html/rfc6749#section-10.3
- RFC 6750 (Bearer Token): https://datatracker.ietf.org/doc/html/rfc6750
- OWASP Session Management: https://owasp.org/www-project-web-security-testing-guide/
`.trim();
  }
}
