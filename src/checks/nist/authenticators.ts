/**
 * NIST Authenticator Lifecycle Management Check
 *
 * Validates that an OAuth 2.0/OIDC provider implements proper authenticator
 * lifecycle management according to NIST SP 800-63B requirements.
 *
 * Authenticator Lifecycle Requirements:
 * - Secure authenticator registration/enrollment process
 * - Authenticator binding to subscriber account
 * - Authenticator expiration and renewal policies
 * - Authenticator revocation and termination capabilities
 * - Support for multiple authenticators per account
 * - Verification of authenticator status before use
 *
 * References:
 * - NIST SP 800-63B Section 6 (Authenticator Lifecycle): https://pages.nist.gov/800-63-3/sp800-63b.html#sec6
 * - NIST SP 800-63B Section 5 (Authenticators): https://pages.nist.gov/800-63-3/sp800-63b.html#sec5
 * - WebAuthn Level 2 (FIDO2): https://www.w3.org/TR/webauthn-2/
 * - RFC 8414 (OAuth Metadata): https://datatracker.ietf.org/doc/html/rfc8414
 */

import { BaseNISTCheck, AALLevel } from "./base-nist-check.js";
import {
  CheckResult,
  CheckCategory,
  Severity,
  CheckContext,
} from "../../types/index.js";

/**
 * Check that validates NIST authenticator lifecycle management requirements
 */
export class AuthenticatorLifecycleCheck extends BaseNISTCheck {
  readonly id = "nist-authenticator-lifecycle";
  readonly name = "NIST Authenticator Lifecycle Management";
  readonly category = CheckCategory.NIST;
  readonly defaultSeverity = Severity.HIGH;
  readonly description =
    "Validates authenticator lifecycle management including registration, binding, expiration, and revocation according to NIST SP 800-63B";

  protected override references = [
    "https://pages.nist.gov/800-63-3/sp800-63b.html#sec6",
    "https://pages.nist.gov/800-63-3/sp800-63b.html#sec5",
    "https://www.w3.org/TR/webauthn-2/",
    "https://datatracker.ietf.org/doc/html/rfc8414",
  ];

  async execute(context: CheckContext): Promise<CheckResult> {
    this.log(context, "Starting NIST authenticator lifecycle check...");

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

    // Detect AAL level to determine appropriate authenticator requirements
    const aalSupport = this.detectAALSupport(metadata);
    const targetAAL = aalSupport.highestAAL || AALLevel.AAL1;
    complianceDetails.target_aal = targetAAL;

    // Check 1: Authenticator registration/enrollment
    this.log(context, "Checking authenticator registration support...");
    const registrationResult = this.checkAuthenticatorRegistration(metadata);
    Object.assign(complianceDetails, {
      registration: registrationResult,
    });

    if (!registrationResult.supportsRegistration) {
      recommendations.push(
        "⚠️  Cannot detect authenticator registration mechanisms from metadata. Manual verification required."
      );
    } else {
      this.log(
        context,
        `Found registration mechanisms: ${registrationResult.registrationMechanisms.join(", ")}`
      );
    }

    // Check 2: Authenticator binding
    this.log(context, "Checking authenticator binding...");
    const bindingResult = this.checkAuthenticatorBinding(metadata);
    Object.assign(complianceDetails, {
      binding: bindingResult,
    });

    if (!bindingResult.hasBindingEvidence) {
      recommendations.push(
        "⚠️  Cannot verify authenticator binding mechanisms. Ensure authenticators are cryptographically bound to user accounts."
      );
    }

    // Check 3: Authenticator expiration policies
    this.log(context, "Checking authenticator expiration policies...");
    const expirationResult = this.checkAuthenticatorExpiration(
      metadata,
      targetAAL
    );
    Object.assign(complianceDetails, {
      expiration: expirationResult,
    });

    if (!expirationResult.hasExpirationPolicy) {
      recommendations.push(
        "⚠️  Cannot detect authenticator expiration policies. NIST recommends time-limited authenticators for AAL2 and AAL3."
      );
    }

    // Check 4: Authenticator revocation
    this.log(context, "Checking authenticator revocation support...");
    const revocationResult = this.checkAuthenticatorRevocation(metadata);
    Object.assign(complianceDetails, {
      revocation: revocationResult,
    });

    if (!revocationResult.supportsRevocation) {
      criticalIssues.push(
        "❌ No authenticator revocation mechanisms detected. NIST requires ability to revoke compromised authenticators."
      );
    }

    // Check 5: Multiple authenticator support
    this.log(context, "Checking multiple authenticator support...");
    const multiAuthResult = this.checkMultipleAuthenticators(metadata);
    Object.assign(complianceDetails, {
      multiple_authenticators: multiAuthResult,
    });

    if (!multiAuthResult.supportsMultiple) {
      recommendations.push(
        "⚠️  Cannot verify support for multiple authenticators per user. This is recommended for backup and recovery."
      );
    }

    // Check 6: Authenticator status verification
    this.log(context, "Checking authenticator status verification...");
    const statusResult = this.checkAuthenticatorStatus(metadata);
    Object.assign(complianceDetails, {
      status_verification: statusResult,
    });

    if (!statusResult.hasStatusVerification) {
      recommendations.push(
        "⚠️  Cannot detect authenticator status verification. Ensure authenticator validity is checked before use."
      );
    }

    // Determine overall result
    if (criticalIssues.length > 0) {
      return this.fail(
        `Authenticator lifecycle management check FAILED for ${targetAAL}.\n\n${criticalIssues.join("\n")}${
          recommendations.length > 0
            ? "\n\n" + recommendations.join("\n")
            : ""
        }`,
        Severity.HIGH,
        this.getAuthenticatorLifecycleRemediation(targetAAL),
        complianceDetails
      );
    }

    if (recommendations.length > 0) {
      return this.warning(
        `Authenticator lifecycle management check passed with recommendations for ${targetAAL}.\n\n${recommendations.join("\n")}`,
        this.getAuthenticatorLifecycleRemediation(targetAAL),
        complianceDetails
      );
    }

    return this.pass(
      `Authenticator lifecycle management controls meet NIST requirements for ${targetAAL}.`,
      complianceDetails
    );
  }

  /**
   * Check authenticator registration support
   */
  private checkAuthenticatorRegistration(metadata: any): {
    supportsRegistration: boolean;
    registrationMechanisms: string[];
    details: string;
  } {
    const mechanisms: string[] = [];

    // Check for WebAuthn/FIDO2 registration support
    if (
      metadata.acr_values_supported?.some(
        (acr: string) =>
          acr.toLowerCase().includes("webauthn") ||
          acr.toLowerCase().includes("fido") ||
          acr.toLowerCase().includes("u2f")
      )
    ) {
      mechanisms.push("WebAuthn/FIDO2 registration");
    }

    // Check for device authorization flow (RFC 8628)
    if (metadata.device_authorization_endpoint) {
      mechanisms.push(
        `Device authorization (${metadata.device_authorization_endpoint})`
      );
    }

    // Check for client registration endpoint (dynamic client registration)
    if (metadata.registration_endpoint) {
      mechanisms.push(
        `Dynamic client registration (${metadata.registration_endpoint})`
      );
    }

    // Check for account management endpoints (non-standard)
    const accountEndpoints = [
      "account_management_uri",
      "user_management_endpoint",
      "credential_management_endpoint",
    ];
    for (const endpoint of accountEndpoints) {
      if (metadata[endpoint]) {
        mechanisms.push(`Account management (${metadata[endpoint]})`);
      }
    }

    return {
      supportsRegistration: mechanisms.length > 0,
      registrationMechanisms: mechanisms,
      details:
        mechanisms.length > 0
          ? `Detected: ${mechanisms.join(", ")}`
          : "No registration mechanisms detected in metadata",
    };
  }

  /**
   * Check authenticator binding support
   */
  private checkAuthenticatorBinding(metadata: any): {
    hasBindingEvidence: boolean;
    bindingMethods: string[];
    details: string;
  } {
    const methods: string[] = [];

    // Check for certificate-bound tokens (mTLS)
    if (
      metadata.tls_client_certificate_bound_access_tokens ||
      metadata.mtls_endpoint_aliases
    ) {
      methods.push("Certificate binding (mTLS)");
    }

    // Check for DPoP (token binding to key)
    if (
      metadata.dpop_signing_alg_values_supported ||
      metadata.dpop_algs_supported
    ) {
      methods.push("DPoP (key binding)");
    }

    // Check for WebAuthn support (credential binding)
    const amrValues = metadata.amr_values_supported || [];
    if (
      amrValues.some(
        (amr: string) =>
          amr === "hwk" || amr === "swk" || amr === "fpt" || amr === "sc"
      )
    ) {
      methods.push("Cryptographic authenticator binding (AMR)");
    }

    // Check for subject confirmation in assertions
    if (metadata.claims_supported?.includes("cnf")) {
      methods.push("Confirmation claim (cnf)");
    }

    return {
      hasBindingEvidence: methods.length > 0,
      bindingMethods: methods,
      details:
        methods.length > 0
          ? `Detected: ${methods.join(", ")}`
          : "No authenticator binding evidence in metadata",
    };
  }

  /**
   * Check authenticator expiration policies
   */
  private checkAuthenticatorExpiration(
    metadata: any,
    targetAAL: AALLevel
  ): {
    hasExpirationPolicy: boolean;
    expirationIndicators: string[];
    details: string;
  } {
    const indicators: string[] = [];

    // Check for credential lifetime fields (non-standard)
    const expirationFields = [
      "credential_max_lifetime",
      "authenticator_lifetime",
      "credential_validity_period",
    ];
    for (const field of expirationFields) {
      if (metadata[field] !== undefined) {
        indicators.push(`${field}: ${metadata[field]}`);
      }
    }

    // Check for certificate expiration (if mTLS is used)
    if (metadata.mtls_endpoint_aliases) {
      indicators.push("Certificate expiration (mTLS)");
    }

    // For AAL2 and AAL3, check for periodic reauthentication requirements
    if (targetAAL !== AALLevel.AAL1) {
      if (metadata.claims_supported?.includes("auth_time")) {
        indicators.push("Periodic reauthentication via auth_time");
      }
    }

    return {
      hasExpirationPolicy: indicators.length > 0,
      expirationIndicators: indicators,
      details:
        indicators.length > 0
          ? `Detected: ${indicators.join(", ")}`
          : "No explicit expiration policy detected in metadata",
    };
  }

  /**
   * Check authenticator revocation support
   */
  private checkAuthenticatorRevocation(metadata: any): {
    supportsRevocation: boolean;
    revocationMechanisms: string[];
    details: string;
  } {
    const mechanisms: string[] = [];

    // Check for token revocation endpoint (RFC 7009)
    if (metadata.revocation_endpoint) {
      mechanisms.push(
        `Token revocation (RFC 7009): ${metadata.revocation_endpoint}`
      );
    }

    // Check for session termination
    if (metadata.end_session_endpoint) {
      mechanisms.push(`Session termination: ${metadata.end_session_endpoint}`);
    }

    // Check for credential status mechanisms (similar to X.509 CRL/OCSP)
    if (metadata.credential_status_endpoint) {
      mechanisms.push(
        `Credential status: ${metadata.credential_status_endpoint}`
      );
    }

    // Check for back-channel logout (can revoke session)
    if (metadata.backchannel_logout_supported) {
      mechanisms.push("Back-channel logout");
    }

    return {
      supportsRevocation: mechanisms.length > 0,
      revocationMechanisms: mechanisms,
      details:
        mechanisms.length > 0
          ? `Detected: ${mechanisms.join(", ")}`
          : "No revocation mechanisms detected in metadata",
    };
  }

  /**
   * Check multiple authenticator support
   */
  private checkMultipleAuthenticators(metadata: any): {
    supportsMultiple: boolean;
    evidence: string[];
    details: string;
  } {
    const evidence: string[] = [];

    // Check for AMR claim (can include multiple authentication methods)
    if (metadata.claims_supported?.includes("amr")) {
      evidence.push("AMR claim (multiple methods supported)");
    }

    // Check for multiple ACR values (indicates multiple authentication levels)
    if ((metadata.acr_values_supported?.length || 0) > 1) {
      evidence.push(
        `Multiple ACR values (${metadata.acr_values_supported.length} levels)`
      );
    }

    // Check for step-up authentication support
    if (metadata.prompt_values_supported?.includes("login")) {
      evidence.push("Step-up authentication (prompt=login)");
    }

    // Check for WebAuthn (naturally supports multiple credentials)
    if (
      metadata.acr_values_supported?.some(
        (acr: string) =>
          acr.toLowerCase().includes("webauthn") ||
          acr.toLowerCase().includes("fido")
      )
    ) {
      evidence.push("WebAuthn/FIDO2 (multi-credential support)");
    }

    return {
      supportsMultiple: evidence.length > 0,
      evidence,
      details:
        evidence.length > 0
          ? `Evidence: ${evidence.join(", ")}`
          : "No clear evidence of multiple authenticator support",
    };
  }

  /**
   * Check authenticator status verification
   */
  private checkAuthenticatorStatus(metadata: any): {
    hasStatusVerification: boolean;
    mechanisms: string[];
    details: string;
  } {
    const mechanisms: string[] = [];

    // Check for credential status list or endpoint
    if (metadata.credential_status_list || metadata.credential_status_endpoint) {
      mechanisms.push("Credential status verification");
    }

    // Check for auth_time claim (can verify recent authentication)
    if (metadata.claims_supported?.includes("auth_time")) {
      mechanisms.push("Authentication timestamp verification (auth_time)");
    }

    // Check for introspection endpoint (can verify token/authenticator status)
    if (metadata.introspection_endpoint) {
      mechanisms.push(
        `Token introspection: ${metadata.introspection_endpoint}`
      );
    }

    // Check for userinfo endpoint (can verify user/authenticator status)
    if (metadata.userinfo_endpoint) {
      mechanisms.push(`UserInfo endpoint: ${metadata.userinfo_endpoint}`);
    }

    return {
      hasStatusVerification: mechanisms.length > 0,
      mechanisms,
      details:
        mechanisms.length > 0
          ? `Detected: ${mechanisms.join(", ")}`
          : "No status verification mechanisms detected",
    };
  }

  /**
   * Generate comprehensive remediation guidance for authenticator lifecycle
   */
  private getAuthenticatorLifecycleRemediation(targetAAL: AALLevel): string {
    const aalRequirements: Record<AALLevel, string> = {
      [AALLevel.AAL1]:
        "Memorized secrets (passwords) or single-factor OTP authenticators",
      [AALLevel.AAL2]:
        "Multi-factor authentication with cryptographic authenticators (TOTP, SMS + password, etc.)",
      [AALLevel.AAL3]:
        "Hardware-based cryptographic authenticators (FIDO2, Smart Cards, HSM)",
    };

    return `
To implement NIST-compliant authenticator lifecycle management for ${targetAAL}:

## 1. Authenticator Registration/Enrollment

**Required**: ${aalRequirements[targetAAL]}

### WebAuthn/FIDO2 Registration Example:

\`\`\`json
// Metadata
{
  "acr_values_supported": [
    "urn:nist:800-63-3:aal:${targetAAL === AALLevel.AAL1 ? "1" : targetAAL === AALLevel.AAL2 ? "2" : "3"}",
    "webauthn"
  ],
  "claims_supported": ["acr", "amr", "auth_time"]
}
\`\`\`

\`\`\`javascript
// Client-side registration
const credential = await navigator.credentials.create({
  publicKey: {
    challenge: new Uint8Array([/* server challenge */]),
    rp: { name: "Example Corp", id: "example.com" },
    user: {
      id: new Uint8Array([/* user ID */]),
      name: "user@example.com",
      displayName: "User Name"
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },  // ES256
      { type: "public-key", alg: -257 } // RS256
    ],
    authenticatorSelection: {
      authenticatorAttachment: "${targetAAL === AALLevel.AAL3 ? "cross-platform" : "platform or cross-platform"}",
      userVerification: "required",
      requireResidentKey: ${targetAAL === AALLevel.AAL3 ? "true" : "false"}
    },
    timeout: 60000,
    attestation: "${targetAAL === AALLevel.AAL3 ? "direct" : "none"}"
  }
});
\`\`\`

## 2. Authenticator Binding

Cryptographically bind authenticators to user accounts:

### Implementation Checklist:

- [ ] **Store credential ID**: Link WebAuthn credential ID to user account
- [ ] **Verify credential ownership**: Challenge-response during authentication
- [ ] **Track credential metadata**: Registration time, last use, device info
- [ ] **Implement credential attestation**: Verify authenticator authenticity (AAL3)

\`\`\`json
// Database schema example
{
  "user_id": "123456",
  "credentials": [
    {
      "credential_id": "base64_encoded_credential_id",
      "public_key": "base64_encoded_public_key",
      "counter": 42,
      "created_at": "2025-01-01T00:00:00Z",
      "last_used": "2025-10-21T12:00:00Z",
      "device_name": "YubiKey 5 NFC",
      "aaguid": "...",
      "attestation_format": "packed"
    }
  ]
}
\`\`\`

## 3. Authenticator Expiration Policies

${
  targetAAL !== AALLevel.AAL1
    ? `
**${targetAAL} Requirement**: Periodic reauthentication required

### Implementation:

\`\`\`javascript
// Check auth_time claim on each request
const now = Math.floor(Date.now() / 1000);
const authTime = idToken.auth_time;
const maxAge = ${targetAAL === AALLevel.AAL2 ? "43200" : "43200"}; // ${targetAAL === AALLevel.AAL2 ? "12 hours" : "12 hours"}

if (now - authTime > maxAge) {
  // Require reauthentication
  redirectToLogin({ prompt: 'login', max_age: 0 });
}
\`\`\`
`
    : `
**AAL1**: No specific expiration requirements, but periodic password changes recommended

- Recommend password expiration: 90-365 days
- Support credential rotation without service interruption
`
}

### Credential Rotation:

\`\`\`json
// Metadata (non-standard extension)
{
  "credential_max_lifetime": ${targetAAL === AALLevel.AAL3 ? "31536000" : "63072000"}, // ${targetAAL === AALLevel.AAL3 ? "1 year" : "2 years"} in seconds
  "credential_renewal_endpoint": "https://provider.com/credentials/renew"
}
\`\`\`

## 4. Authenticator Revocation

**Critical**: Provide immediate revocation capabilities

### Token Revocation Endpoint (RFC 7009):

\`\`\`json
// Metadata
{
  "revocation_endpoint": "https://provider.com/oauth/revoke",
  "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
}
\`\`\`

\`\`\`bash
# Revoke token
POST https://provider.com/oauth/revoke
Content-Type: application/x-www-form-urlencoded

token=abc123...&
token_type_hint=access_token&
client_id=...&
client_secret=...
\`\`\`

### Credential Management API:

\`\`\`javascript
// Server-side credential revocation
app.delete('/api/credentials/:credentialId', async (req, res) => {
  const { userId } = req.user;
  const { credentialId } = req.params;

  await database.removeCredential(userId, credentialId);
  await revokeAllAssociatedTokens(userId, credentialId);

  // Notify user
  await sendEmail(user.email, 'Authenticator removed');

  res.status(204).send();
});
\`\`\`

## 5. Multiple Authenticator Support

**Recommended**: Allow users to register multiple authenticators for backup

### Implementation:

\`\`\`javascript
// List all registered authenticators
app.get('/api/credentials', async (req, res) => {
  const { userId } = req.user;
  const credentials = await database.getCredentials(userId);

  res.json({
    credentials: credentials.map(cred => ({
      id: cred.credential_id,
      name: cred.device_name,
      created_at: cred.created_at,
      last_used: cred.last_used,
      type: cred.authenticator_type
    }))
  });
});

// Require at least 2 authenticators for critical accounts
const MIN_AUTHENTICATORS = ${targetAAL === AALLevel.AAL3 ? "2" : "1"};
\`\`\`

## 6. Authenticator Status Verification

Verify authenticator validity before accepting authentication:

### Implementation:

\`\`\`javascript
async function verifyAuthenticatorStatus(credentialId) {
  const credential = await database.getCredential(credentialId);

  // Check if revoked
  if (credential.revoked) {
    throw new Error('Credential has been revoked');
  }

  // Check expiration
  const now = Date.now();
  if (credential.expires_at && now > credential.expires_at) {
    throw new Error('Credential has expired');
  }

  // Check last use (detect dormant credentials)
  const maxDormantPeriod = 90 * 24 * 60 * 60 * 1000; // 90 days
  if (now - credential.last_used > maxDormantPeriod) {
    // Require additional verification
    return { status: 'dormant', requireStepUp: true };
  }

  return { status: 'active' };
}
\`\`\`

## Security Considerations

1. **Secure Storage**: Encrypt credential data at rest
2. **Audit Logging**: Log all credential lifecycle events (registration, use, revocation)
3. **User Notifications**: Alert users when credentials are added/removed
4. **Rate Limiting**: Prevent credential enumeration attacks
5. **Backup Codes**: Provide recovery mechanism if all authenticators are lost
6. **Account Recovery**: Secure process for adding new authenticator after lockout

## References

- NIST SP 800-63B Section 6: https://pages.nist.gov/800-63-3/sp800-63b.html#sec6
- WebAuthn Level 2: https://www.w3.org/TR/webauthn-2/
- RFC 7009 (Token Revocation): https://datatracker.ietf.org/doc/html/rfc7009
- RFC 8628 (Device Flow): https://datatracker.ietf.org/doc/html/rfc8628
`.trim();
  }
}
