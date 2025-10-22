/**
 * NIST Session Management Compliance Check
 *
 * Validates that an OAuth 2.0/OIDC provider implements proper session
 * management controls according to NIST SP 800-63B requirements.
 *
 * Session Management Requirements:
 * - AAL1: Maximum 30-day session (720 hours), no idle timeout required
 * - AAL2: Maximum 12-hour session, 60-minute idle timeout (30 min preferred)
 * - AAL3: Maximum 12-hour session, 15-minute idle timeout
 * - Session binding to authenticator
 * - Reauthentication requirements for sensitive operations
 * - Session termination/logout endpoints
 *
 * References:
 * - NIST SP 800-63B Section 7 (Session Management): https://pages.nist.gov/800-63-3/sp800-63b.html#sec7
 * - NIST SP 800-63B Section 4 (AAL Requirements): https://pages.nist.gov/800-63-3/sp800-63b.html#sec4
 * - OpenID Connect Session Management: https://openid.net/specs/openid-connect-session-1_0.html
 * - OpenID Connect Front-Channel Logout: https://openid.net/specs/openid-connect-frontchannel-1_0.html
 * - OpenID Connect Back-Channel Logout: https://openid.net/specs/openid-connect-backchannel-1_0.html
 */

import { BaseNISTCheck, AALLevel } from "./base-nist-check.js";
import {
  CheckResult,
  CheckCategory,
  Severity,
  CheckContext,
} from "../../types/index.js";

/**
 * Session timeout configuration detected from metadata
 */
interface SessionTimeoutConfig {
  /** Whether session timeout information is available */
  hasTimeoutInfo: boolean;

  /** Detected maximum session duration in seconds */
  maxSessionDuration?: number;

  /** Detected idle timeout in seconds */
  idleTimeout?: number;

  /** Source of timeout information (e.g., 'metadata', 'token_lifetime', 'inferred') */
  source?: string;

  /** Whether timeouts meet NIST requirements for detected AAL */
  meetsRequirements?: boolean;
}

/**
 * Check that validates NIST session management requirements
 */
export class SessionManagementCheck extends BaseNISTCheck {
  readonly id = "nist-session-management";
  readonly name = "NIST Session Management";
  readonly category = CheckCategory.NIST;
  readonly defaultSeverity = Severity.HIGH;
  readonly description =
    "Validates session management controls including timeouts, binding, reauthentication, and termination according to NIST SP 800-63B";

  protected override references = [
    "https://pages.nist.gov/800-63-3/sp800-63b.html#sec7",
    "https://pages.nist.gov/800-63-3/sp800-63b.html#sessionmgmt",
    "https://openid.net/specs/openid-connect-session-1_0.html",
    "https://openid.net/specs/openid-connect-frontchannel-1_0.html",
    "https://openid.net/specs/openid-connect-backchannel-1_0.html",
  ];

  async execute(context: CheckContext): Promise<CheckResult> {
    this.log(context, "Starting NIST session management check...");

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

    // Detect AAL level to determine appropriate session requirements
    const aalSupport = this.detectAALSupport(metadata);
    const targetAAL = aalSupport.highestAAL || AALLevel.AAL1;
    complianceDetails.target_aal = targetAAL;

    // Check 1: Session timeout configuration
    this.log(context, "Checking session timeout configuration...");
    const timeoutResult = this.checkSessionTimeouts(metadata, targetAAL);
    Object.assign(complianceDetails, {
      session_timeout_check: timeoutResult,
    });

    if (!timeoutResult.hasTimeoutInfo) {
      recommendations.push(
        "⚠️  Cannot verify session timeout configuration from metadata. Manual verification required."
      );
    } else if (timeoutResult.meetsRequirements === false) {
      criticalIssues.push(
        `❌ Session timeouts do not meet NIST requirements for ${targetAAL}`
      );
    }

    // Check 2: Session binding mechanisms
    this.log(context, "Checking session binding mechanisms...");
    const bindingResult = this.checkSessionBinding(metadata);
    Object.assign(complianceDetails, {
      session_binding: bindingResult,
    });

    if (!bindingResult.hasBindingSupport) {
      recommendations.push(
        "⚠️  Cannot verify session binding mechanisms from metadata. Ensure sessions are cryptographically bound to authenticators."
      );
    }

    // Check 3: Reauthentication support
    this.log(context, "Checking reauthentication capabilities...");
    const reauthResult = this.checkReauthenticationSupport(metadata);
    Object.assign(complianceDetails, {
      reauthentication: reauthResult,
    });

    if (!reauthResult.supportsPromptLogin && !reauthResult.supportsMaxAge) {
      recommendations.push(
        "⚠️  No reauthentication mechanisms detected (prompt=login, max_age parameter). This is required for sensitive operations."
      );
    }

    // Check 4: Session termination endpoints
    this.log(context, "Checking session termination endpoints...");
    const terminationResult = this.checkSessionTermination(metadata);
    Object.assign(complianceDetails, {
      session_termination: terminationResult,
    });

    if (!terminationResult.hasLogoutEndpoint) {
      criticalIssues.push(
        "❌ No session termination endpoint detected. NIST requires ability to terminate sessions."
      );
    }

    // Check 5: Idle timeout vs absolute timeout distinction
    this.log(context, "Checking idle vs absolute timeout support...");
    const timeoutTypes = this.checkTimeoutTypes(metadata);
    Object.assign(complianceDetails, {
      timeout_types: timeoutTypes,
    });

    if (
      targetAAL !== AALLevel.AAL1 &&
      !timeoutTypes.distinguishesIdleFromAbsolute
    ) {
      recommendations.push(
        `⚠️  Cannot verify idle timeout configuration. ${targetAAL} requires idle timeout of ${this.getAALIdleTimeoutRequirement(targetAAL)} minutes.`
      );
    }

    // Determine overall result
    if (criticalIssues.length > 0) {
      return this.fail(
        `Session management check FAILED for ${targetAAL}.\n\n${criticalIssues.join("\n")}${
          recommendations.length > 0
            ? "\n\n" + recommendations.join("\n")
            : ""
        }`,
        Severity.HIGH,
        this.getSessionManagementRemediation(targetAAL),
        complianceDetails
      );
    }

    if (recommendations.length > 0) {
      return this.warning(
        `Session management check passed with recommendations for ${targetAAL}.\n\n${recommendations.join("\n")}`,
        this.getSessionManagementRemediation(targetAAL),
        complianceDetails
      );
    }

    return this.pass(
      `Session management controls meet NIST requirements for ${targetAAL}.`,
      complianceDetails
    );
  }

  /**
   * Check session timeout configuration
   */
  private checkSessionTimeouts(
    metadata: any,
    targetAAL: AALLevel
  ): SessionTimeoutConfig {
    const result: SessionTimeoutConfig = {
      hasTimeoutInfo: false,
    };

    // Try to infer from token lifetime (access_token_ttl, id_token_ttl, etc.)
    // Note: Most providers don't expose this in metadata, only in actual tokens
    const possibleFields = [
      "access_token_ttl",
      "id_token_ttl",
      "session_max_lifetime",
      "session_lifetime",
      "max_session_duration",
    ];

    for (const field of possibleFields) {
      if (metadata[field] !== undefined) {
        result.hasTimeoutInfo = true;
        result.maxSessionDuration = metadata[field];
        result.source = field;
        break;
      }
    }

    // Check if timeout meets NIST requirements
    if (result.maxSessionDuration) {
      const requiredMaxSeconds =
        this.getAALSessionTimeoutRequirement(targetAAL) * 3600;
      result.meetsRequirements =
        result.maxSessionDuration <= requiredMaxSeconds;
    }

    return result;
  }

  /**
   * Check session binding mechanisms
   */
  private checkSessionBinding(metadata: any): {
    hasBindingSupport: boolean;
    bindingMethods: string[];
    details: string;
  } {
    const bindingMethods: string[] = [];

    // Check for PKCE (indicates session binding for authorization code)
    if (metadata.code_challenge_methods_supported?.length > 0) {
      bindingMethods.push("PKCE (authorization code binding)");
    }

    // Check for DPoP support (RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession)
    if (
      metadata.dpop_signing_alg_values_supported ||
      metadata.dpop_algs_supported
    ) {
      bindingMethods.push("DPoP (token binding)");
    }

    // Check for mutual TLS (mTLS) support
    if (
      metadata.tls_client_certificate_bound_access_tokens ||
      metadata.mtls_endpoint_aliases
    ) {
      bindingMethods.push("mTLS (certificate-bound tokens)");
    }

    // Check for token binding support (deprecated but may be present)
    if (metadata.token_binding_supported) {
      bindingMethods.push("Token Binding Protocol");
    }

    return {
      hasBindingSupport: bindingMethods.length > 0,
      bindingMethods,
      details:
        bindingMethods.length > 0
          ? `Detected: ${bindingMethods.join(", ")}`
          : "No session binding mechanisms detected in metadata",
    };
  }

  /**
   * Check reauthentication support
   */
  private checkReauthenticationSupport(metadata: any): {
    supportsPromptLogin: boolean;
    supportsMaxAge: boolean;
    supportsAuthTime: boolean;
    details: string;
  } {
    // Check if prompt parameter values are advertised
    const promptValuesSupported = metadata.prompt_values_supported || [];
    const supportsPromptLogin = promptValuesSupported.includes("login");

    // Check if max_age parameter is supported (requires auth_time claim)
    const claimsSupported = metadata.claims_supported || [];
    const supportsAuthTime = claimsSupported.includes("auth_time");

    // max_age support is typically indicated by auth_time claim support
    const supportsMaxAge = supportsAuthTime;

    const mechanisms: string[] = [];
    if (supportsPromptLogin) mechanisms.push("prompt=login");
    if (supportsMaxAge) mechanisms.push("max_age parameter");
    if (supportsAuthTime) mechanisms.push("auth_time claim");

    return {
      supportsPromptLogin,
      supportsMaxAge,
      supportsAuthTime,
      details:
        mechanisms.length > 0
          ? `Supported: ${mechanisms.join(", ")}`
          : "No reauthentication mechanisms advertised",
    };
  }

  /**
   * Check session termination support
   */
  private checkSessionTermination(metadata: any): {
    hasLogoutEndpoint: boolean;
    supportsFrontChannelLogout: boolean;
    supportsBackChannelLogout: boolean;
    supportsRPInitiatedLogout: boolean;
    endpoints: string[];
  } {
    const endpoints: string[] = [];

    // Check for RP-initiated logout endpoint
    const hasRPLogout = !!metadata.end_session_endpoint;
    if (hasRPLogout) {
      endpoints.push(`end_session_endpoint: ${metadata.end_session_endpoint}`);
    }

    // Check for front-channel logout
    const hasFrontChannel = !!metadata.frontchannel_logout_supported;
    if (hasFrontChannel) {
      endpoints.push("front-channel logout supported");
    }

    // Check for back-channel logout
    const hasBackChannel = !!metadata.backchannel_logout_supported;
    if (hasBackChannel) {
      endpoints.push("back-channel logout supported");
    }

    // Check for OAuth 2.0 token revocation endpoint
    const hasRevocation = !!metadata.revocation_endpoint;
    if (hasRevocation) {
      endpoints.push(`revocation_endpoint: ${metadata.revocation_endpoint}`);
    }

    return {
      hasLogoutEndpoint: hasRPLogout || hasFrontChannel || hasBackChannel,
      supportsFrontChannelLogout: hasFrontChannel,
      supportsBackChannelLogout: hasBackChannel,
      supportsRPInitiatedLogout: hasRPLogout,
      endpoints,
    };
  }

  /**
   * Check timeout type distinction
   */
  private checkTimeoutTypes(metadata: any): {
    distinguishesIdleFromAbsolute: boolean;
    hasIdleTimeoutInfo: boolean;
    hasAbsoluteTimeoutInfo: boolean;
    details: string;
  } {
    // Check for explicit idle timeout fields (non-standard)
    const idleTimeoutFields = [
      "idle_timeout",
      "session_idle_timeout",
      "inactivity_timeout",
    ];
    const hasIdleTimeoutInfo = idleTimeoutFields.some(
      (field) => metadata[field] !== undefined
    );

    // Check for explicit absolute timeout fields
    const absoluteTimeoutFields = [
      "session_max_lifetime",
      "absolute_timeout",
      "max_session_duration",
    ];
    const hasAbsoluteTimeoutInfo = absoluteTimeoutFields.some(
      (field) => metadata[field] !== undefined
    );

    const distinguishesIdleFromAbsolute =
      hasIdleTimeoutInfo && hasAbsoluteTimeoutInfo;

    let details = "";
    if (distinguishesIdleFromAbsolute) {
      details = "Both idle and absolute timeouts configured";
    } else if (hasIdleTimeoutInfo) {
      details = "Only idle timeout detected";
    } else if (hasAbsoluteTimeoutInfo) {
      details = "Only absolute timeout detected";
    } else {
      details = "No explicit timeout configuration in metadata";
    }

    return {
      distinguishesIdleFromAbsolute,
      hasIdleTimeoutInfo,
      hasAbsoluteTimeoutInfo,
      details,
    };
  }

  /**
   * Generate comprehensive remediation guidance for session management
   */
  private getSessionManagementRemediation(targetAAL: AALLevel): string {
    const sessionTimeout = this.getAALSessionTimeoutRequirement(targetAAL);
    const idleTimeout = this.getAALIdleTimeoutRequirement(targetAAL);

    let guidance = `
To implement NIST-compliant session management for ${targetAAL}:

## 1. Session Timeout Configuration

**Absolute Timeout**: Maximum ${sessionTimeout} hours (${sessionTimeout / 24} days)
${
  idleTimeout
    ? `**Idle Timeout**: Maximum ${idleTimeout} minutes of inactivity`
    : "**Idle Timeout**: Not required"
}

### Implementation Example (Token Claims):

\`\`\`json
{
  "exp": ${Math.floor(Date.now() / 1000) + sessionTimeout * 3600},  // Expires in ${sessionTimeout} hours
  "iat": ${Math.floor(Date.now() / 1000)},
  "auth_time": ${Math.floor(Date.now() / 1000)},
  "session_state": "abc123..."
}
\`\`\`

## 2. Session Binding to Authenticator

Bind sessions cryptographically to prevent session hijacking:

### Option A: DPoP (Demonstrating Proof of Possession)

\`\`\`json
// Metadata
{
  "dpop_signing_alg_values_supported": ["ES256", "RS256"]
}
\`\`\`

### Option B: mTLS (Mutual TLS)

\`\`\`json
// Metadata
{
  "tls_client_certificate_bound_access_tokens": true,
  "mtls_endpoint_aliases": {
    "token_endpoint": "https://mtls.example.com/token"
  }
}
\`\`\`

### Option C: PKCE (for authorization code flow)

\`\`\`json
// Metadata
{
  "code_challenge_methods_supported": ["S256"]
}
\`\`\`

## 3. Reauthentication Support

Support forced reauthentication for sensitive operations:

\`\`\`json
// Metadata
{
  "prompt_values_supported": ["none", "login", "consent", "select_account"],
  "claims_supported": ["auth_time", "acr", "amr"]
}
\`\`\`

**Authorization Request with Reauthentication:**
\`\`\`
https://provider.com/authorize?
  client_id=abc&
  prompt=login&           // Force reauthentication
  max_age=0&              // Require recent authentication
  response_type=code&
  redirect_uri=...
\`\`\`

## 4. Session Termination

Provide multiple logout mechanisms:

### RP-Initiated Logout (OIDC):

\`\`\`json
// Metadata
{
  "end_session_endpoint": "https://provider.com/logout"
}
\`\`\`

\`\`\`
GET https://provider.com/logout?
  id_token_hint=...&
  post_logout_redirect_uri=...
\`\`\`

### Token Revocation (OAuth 2.0):

\`\`\`json
// Metadata
{
  "revocation_endpoint": "https://provider.com/revoke",
  "revocation_endpoint_auth_methods_supported": ["client_secret_basic"]
}
\`\`\`

### Back-Channel Logout:

\`\`\`json
// Metadata
{
  "backchannel_logout_supported": true,
  "backchannel_logout_session_supported": true
}
\`\`\`

## 5. Idle vs Absolute Timeout

Implement both types of timeouts:

- **Absolute Timeout**: Session ends after ${sessionTimeout} hours regardless of activity
- **Idle Timeout**: Session ends after ${idleTimeout || "N/A"} minutes of inactivity${
      idleTimeout
        ? ""
        : " (not required for AAL1)"
    }

Track last activity timestamp and compare on each request.

## Security Considerations

1. **Session Fixation**: Generate new session identifier after authentication
2. **CSRF Protection**: Use state parameter and validate on callback
3. **Session Storage**: Store session tokens securely (HttpOnly, Secure, SameSite cookies)
4. **Concurrent Sessions**: Consider limiting number of active sessions per user
5. **Activity Monitoring**: Log authentication and session events for audit trail

## References

- NIST SP 800-63B Section 7: https://pages.nist.gov/800-63-3/sp800-63b.html#sec7
- OpenID Connect Session Management: https://openid.net/specs/openid-connect-session-1_0.html
- RFC 9449 (DPoP): https://datatracker.ietf.org/doc/html/rfc9449
- RFC 7009 (Token Revocation): https://datatracker.ietf.org/doc/html/rfc7009
`.trim();

    return guidance;
  }
}
