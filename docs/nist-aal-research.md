# NIST 800-63B AAL Research Findings

> **Research Date**: 2025-10-16
> **Purpose**: Understanding NIST Authentication Assurance Levels and their implementation in OAuth 2.0/OIDC

---

## Executive Summary

This document consolidates research findings on NIST 800-63B Authentication Assurance Levels (AAL), their requirements, and how they map to OAuth 2.0/OpenID Connect implementations. This research will guide the implementation of AAL compliance checks in OAuth Guardian.

### Key Findings

1. **NIST defines 3 AAL levels** with increasing authentication strength requirements
2. **OAuth/OIDC use ACR and AMR claims** to communicate authentication context
3. **No standardized ACR values exist** - each provider defines their own
4. **Metadata discovery is limited** - not all providers expose ACR/AMR support
5. **Session management requirements differ** by AAL level

---

## NIST 800-63B Authentication Assurance Levels

### AAL1 - Basic Assurance

**Definition**: Provides basic confidence that the claimant controls an authenticator bound to the subscriber account.

**Authentication Requirements**:
- Either single-factor OR multi-factor authentication
- Wide range of available authentication technologies permitted
- Password-based authentication acceptable

**Session Management Requirements**:
- **Reauthentication timeout**: SHOULD be no more than **30 days**
- **Inactivity timeout**: MAY be applied (optional)
- No specific idle timeout requirement

**Use Cases**:
- Low-risk applications
- Public-facing services with minimal PII
- Services with limited access to sensitive data

---

### AAL2 - High Assurance

**Definition**: Provides high confidence that the claimant controls authenticators bound to the subscriber account.

**Authentication Requirements**:
- **MUST** use multi-factor authentication
- Two distinct authentication factors required
- At least one factor must be cryptographic (approved cryptographic techniques)
- Can use either:
  - A multi-factor authenticator (combined device), OR
  - A combination of two separate single-factor authenticators

**Approved Authenticators** (examples):
- Multi-factor cryptographic device (e.g., smart card with PIN)
- Multi-factor OTP device (hardware/software)
- Single-factor cryptographic device + memorized secret (password)
- Single-factor OTP device + memorized secret

**Session Management Requirements**:
- **Reauthentication timeout**: SHOULD be no more than **12 hours** (24 hours maximum)
- **Inactivity timeout**: SHOULD be no more than **1 hour** (30 minutes preferred)
- Reauthentication may use single factor if approved

**Key Differences from AAL1**:
- MFA is mandatory
- Cryptographic methods required
- Shorter session timeouts
- Idle timeout enforcement recommended

---

### AAL3 - Very High Assurance

**Definition**: Provides very high confidence that the claimant controls authenticators bound to the subscriber account.

**Authentication Requirements**:
- **MUST** use hardware-based cryptographic authenticator
- Private key must be **non-exportable** (hardware-protected)
- **Phishing-resistant** authentication required
- Verifier impersonation resistance mandatory
- Proof of possession of a key through cryptographic protocol
- Plus either an activation factor (biometric, PIN) or password

**Approved Authenticators**:
- Multi-factor cryptographic hardware device (e.g., FIDO2/WebAuthn security key)
- Single-factor cryptographic hardware device + memorized secret
- Hardware security module (HSM) based authentication

**Session Management Requirements**:
- **Reauthentication timeout**: SHALL be no more than **12 hours**
- **Inactivity timeout**: SHOULD be no more than **15 minutes**
- **Critical**: Reauthentication at AAL3 requires the same rigor as initial authentication (cannot downgrade to single-factor)

**Key Differences from AAL2**:
- Hardware-based authenticators mandatory
- Phishing resistance required (FIDO2, WebAuthn)
- Stricter idle timeout (15 min vs 1 hour)
- No downgrade allowed for reauthentication

---

## OAuth 2.0 / OpenID Connect Implementation

### ACR (Authentication Context Class Reference)

**Definition**: A string value that identifies the authentication context class that the authentication performed satisfied.

**Purpose**: Communicates the **strength** or **level** of authentication to relying parties.

**Characteristics**:
- Optional claim in ID tokens (`acr` claim)
- Can be requested via `acr_values` parameter in authorization requests
- Values are URIs or strings agreed upon between client and provider
- **No official standardized values** (except "0" for insufficient)

**Example ACR Values**:
```
# NIST AAL Format (common pattern)
urn:akamai-ic:nist:800-63-3:aal:1
urn:akamai-ic:nist:800-63-3:aal:2
urn:akamai-ic:nist:800-63-3:aal:3

# Okta Format
urn:okta:loa:1fa:any    # Single-factor
urn:okta:loa:2fa:any    # Two-factor
phr                     # Phishing-resistant
phrh                    # Phishing-resistant hardware

# Open Banking Brasil
urn:brasil:openbanking:loa2  # Single-factor
urn:brasil:openbanking:loa3  # Multi-factor
```

**Metadata Discovery**:
- OIDC Discovery includes `acr_values_supported` field (OPTIONAL)
- Returns JSON array of supported ACR values
- Many providers do not expose this field

**How It Works**:
1. Client requests authentication with `acr_values` parameter
2. Authorization server authenticates user according to requested ACR
3. ID token includes `acr` claim with the ACR value satisfied
4. Client validates the `acr` claim meets requirements

---

### AMR (Authentication Method Reference)

**Definition**: An array of strings identifying the authentication methods used during authentication.

**Purpose**: Communicates **how** the user authenticated (specific methods used).

**Characteristics**:
- Optional claim in ID tokens (`amr` claim)
- Array of strings (can have multiple values)
- Values defined in RFC 8176
- Provides granular details about authentication process

**Standard AMR Values** (from RFC 8176):

**Multi-Factor**:
- `mfa` - Multiple-factor authentication
- `mca` - Multiple-channel authentication

**Hardware/Software Tokens**:
- `hwk` - Hardware-secured key (proof of possession)
- `swk` - Software-secured key (proof of possession)
- `sc` - Smart card
- `otp` - One-time password (TOTP/HOTP)

**Biometric Methods**:
- `fpt` - Fingerprint biometric
- `face` - Facial recognition
- `iris` - Iris scan
- `retina` - Retina scan
- `vbm` - Voice biometric

**Basic Methods**:
- `pwd` - Password
- `pin` - Personal identification number
- `sms` - SMS-based OTP
- `tel` - Telephone call verification

**Example AMR Claims**:
```json
{
  "amr": ["pwd", "mfa"]           // Password + MFA
}

{
  "amr": ["pwd", "otp"]           // Password + OTP
}

{
  "amr": ["hwk", "pin"]           // Hardware key + PIN (AAL3)
}

{
  "amr": ["fido", "face"]         // FIDO2 + biometric
}
```

**Metadata Discovery**:
- Not typically exposed in OAuth 2.0 metadata (RFC 8414)
- Some OIDC providers expose `amr_values_supported` (non-standard)
- Usually documented in provider-specific documentation

---

### ACR vs AMR: Key Differences

| Aspect | ACR | AMR |
|--------|-----|-----|
| **What it represents** | Authentication strength/level | Specific methods used |
| **Format** | Single string (URI or value) | Array of strings |
| **Standardization** | No official values (provider-specific) | RFC 8176 defines values |
| **Abstraction level** | High-level (business policy) | Low-level (technical details) |
| **Example** | `urn:nist:aal:2` | `["pwd", "otp"]` |
| **Use case** | "Did authentication meet policy X?" | "How exactly did they authenticate?" |

**Relationship**:
- ACR defines the **policy requirement** (e.g., AAL2 compliance)
- AMR describes the **implementation** (e.g., password + TOTP)
- One ACR level can be satisfied by multiple AMR combinations
- ACR is used for access control decisions
- AMR is used for audit logging and detailed analysis

---

## Provider-Specific Implementations

### Microsoft Entra ID (Azure AD)

**NIST AAL Support**: Full support for AAL1, AAL2, and AAL3

**ACR Values**:
- Not explicitly documented in public docs
- Likely follows custom Microsoft format

**AMR Values for MFA** (documented):
```json
{
  "amr": ["face", "fido", "fpt", "hwk", "iris", "otp",
          "pop", "retina", "sc", "sms", "swk", "tel", "vbm"]
}
```

**MFA Validation**:
- Checks for `amr` claim containing MFA-related values
- Validates that authentication method differs from first factor
- ACR value: `["possessionorinherence"]` for MFA

**AAL3 Requirements**:
- Multi-factor cryptographic hardware authenticator
- Phishing-resistant (FIDO2/WebAuthn recommended)
- Hardware security module (HSM) backed

**FIPS 140 Compliance**:
- Uses Windows FIPS 140 Level 1 validated cryptographic module
- Meets NIST verifier requirements

**Documentation**:
- [Achieve NIST AAL2](https://learn.microsoft.com/en-us/azure/active-directory/standards/nist-authenticator-assurance-level-2)
- [Achieve NIST AAL3](https://learn.microsoft.com/en-us/azure/active-directory/standards/nist-authenticator-assurance-level-3)

---

### Okta

**NIST AAL Support**: Supports AAL levels through custom ACR values

**ACR Values** (documented):
- `urn:okta:loa:1fa:any` - Single-factor authentication (AAL1)
- `urn:okta:loa:2fa:any` - Two-factor authentication (AAL2)
- `phr` - Phishing-resistant factors (FIDO2, WebAuthn)
- `phrh` - Phishing-resistant hardware-protected factors (AAL3)

**Step-Up Authentication**:
- Supports dynamic ACR value requests
- Can request higher assurance mid-session
- Maps ACR values to authentication policies

**AMR Claims Mapping**:
- Configurable AMR claims from external IdPs
- Supports standard AMR values (sms, mfa, pwd, etc.)
- Can customize AMR claim mappings per org

**Authentication Policies**:
- WIC (Workforce Identity Cloud) authentication policies
- Maps ACR values to policy requirements
- Supports custom assurance levels

**Documentation**:
- [Step-up Authentication Using ACR Values](https://developer.okta.com/docs/guides/step-up-authentication/main/)
- [Configure AMR Claims Mapping](https://developer.okta.com/docs/guides/configure-amr-claims-mapping/main/)

---

### Google OAuth / Google Identity

**NIST AAL Support**: Limited public documentation

**ACR Values**:
- Not publicly documented
- Likely supports custom Google-specific values
- May support standard NIST AAL URN format

**AMR Values**:
- Not extensively documented in public APIs
- Standard RFC 8176 values likely supported
- MFA methods include: pwd, otp, sms

**Advanced Protection Program**:
- Enforces AAL3-level security
- Requires hardware security keys (FIDO2)
- Phishing-resistant authentication

**Note**: Google's OIDC implementation focuses more on standard claims rather than exposing ACR/AMR extensively in public documentation.

---

### Login.gov (US Government)

**NIST AAL Support**: Explicitly designed for NIST compliance

**ACR Values** (documented):
- Standard NIST AAL URN format expected
- Government-focused implementation
- Strict compliance with NIST 800-63B

**Note**: Login.gov is a reference implementation for NIST-compliant authentication in government contexts.

---

## OAuth 2.0 / OIDC Metadata Fields

### RFC 8414: OAuth 2.0 Authorization Server Metadata

**Discovery Endpoint**:
```
/.well-known/oauth-authorization-server
```

**Relevant Metadata Fields**:

| Field | Type | Description | AAL Relevance |
|-------|------|-------------|---------------|
| `issuer` | String | Authorization server identifier | Provider identification |
| `authorization_endpoint` | String | URL for authorization requests | Required for all AALs |
| `token_endpoint` | String | URL for token requests | Required for all AALs |
| `token_endpoint_auth_methods_supported` | Array | Client auth methods supported | Client authentication validation |
| `code_challenge_methods_supported` | Array | PKCE methods (S256, plain) | Security enhancement |

**Note**: RFC 8414 does NOT include ACR or AMR fields - those come from OIDC Discovery.

---

### OpenID Connect Discovery

**Discovery Endpoint**:
```
/.well-known/openid-configuration
```

**Additional Metadata Fields**:

| Field | Type | Description | AAL Relevance |
|-------|------|-------------|---------------|
| `acr_values_supported` | Array | OPTIONAL. List of ACR values supported | ⭐ **Primary AAL detection** |
| `claims_supported` | Array | Claims available in ID token/UserInfo | Check for `acr`, `amr` support |
| `userinfo_endpoint` | String | UserInfo endpoint URL | Additional user info |
| `id_token_signing_alg_values_supported` | Array | Signing algorithms for ID tokens | Cryptographic validation |

**Example Discovery Response**:
```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oauth/authorize",
  "token_endpoint": "https://auth.example.com/oauth/token",
  "acr_values_supported": [
    "urn:nist:aal:1",
    "urn:nist:aal:2",
    "urn:nist:aal:3"
  ],
  "claims_supported": [
    "sub", "iss", "aud", "exp", "iat",
    "acr", "amr", "auth_time"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256", "RS384", "RS512"
  ]
}
```

**Key Points**:
- `acr_values_supported` is OPTIONAL - many providers omit it
- Presence of `acr` and `amr` in `claims_supported` indicates claim support
- Most providers don't expose exhaustive ACR value lists in metadata

---

## Implementation Strategy for OAuth Guardian

### Detection Approach (Multi-Layered)

**Layer 1: Metadata Discovery** (Automated)
1. Fetch `/.well-known/openid-configuration` or `/.well-known/oauth-authorization-server`
2. Check for `acr_values_supported` field
3. Check `claims_supported` for `acr` and `amr`
4. Analyze supported ACR values for NIST AAL patterns

**Layer 2: Pattern Matching** (Heuristic)
1. Look for common AAL URN patterns:
   - `urn:*:nist:*:aal:*`
   - `urn:*:loa:*` (Level of Assurance)
   - `phr`, `phrh` (phishing-resistant)
2. Detect MFA-related ACR values (contains `2fa`, `mfa`, `multi`)
3. Identify single-factor patterns (`1fa`, `password`, etc.)

**Layer 3: Provider-Specific Knowledge** (Database)
1. Maintain mapping of known providers to their ACR formats
2. Map common providers (Google, Microsoft, Okta, Auth0) to AAL levels
3. Allow user configuration for custom provider mappings

**Layer 4: Manual Validation Guidance** (Fallback)
1. When automated detection fails, provide guidance
2. Instruct users how to find ACR values in their provider's docs
3. Suggest testing with actual authentication flows
4. Provide configuration override options

---

### Check Implementation Plan

#### Check 1: AAL Level Detection (Base Check)

**ID**: `nist-aal-support`

**What It Checks**:
- Discovers OIDC metadata
- Looks for `acr_values_supported` field
- Analyzes ACR values for AAL indicators
- Determines which AAL levels are supported

**Result Statuses**:
- **PASS**: AAL levels explicitly declared in metadata
- **WARNING**: No AAL metadata found, provider may support but not advertise
- **INFO**: Provider uses custom ACR values (list them)
- **SKIP**: Not an OIDC provider (no metadata endpoint)

**Remediation**:
- Implement OIDC Discovery with `acr_values_supported`
- Document supported AAL levels
- Follow NIST 800-63B guidelines for ACR value naming

---

#### Check 2: AAL1 Compliance

**ID**: `nist-aal1-compliance`

**What It Checks**:
- Single-factor OR multi-factor authentication available
- Password-based authentication acceptable
- Session timeout ≤ 30 days (if discoverable)
- Basic authentication endpoint security (HTTPS)

**Detection Methods**:
- Check for AAL1-related ACR values
- Look for `response_types_supported` including `code`
- Verify authorization endpoint is HTTPS

**Result Statuses**:
- **PASS**: AAL1 requirements met
- **FAIL**: Missing basic authentication support
- **WARNING**: Cannot verify session timeout (not in metadata)

---

#### Check 3: AAL2 Compliance

**ID**: `nist-aal2-compliance`

**What It Checks**:
- Multi-factor authentication support
- Cryptographic authentication method available
- Session timeout ≤ 12 hours (preferred)
- Idle timeout ≤ 1 hour (recommended)
- Two distinct authentication factors

**Detection Methods**:
- Check for AAL2-related ACR values (`urn:*:aal:2`, `2fa`, `mfa`)
- Look for MFA-related AMR values in claims_supported
- Check for OTP, TOTP, hardware token support

**Result Statuses**:
- **PASS**: AAL2 requirements met (MFA + crypto methods)
- **FAIL**: No MFA support detected
- **WARNING**: MFA support unclear (manual verification needed)

---

#### Check 4: AAL3 Compliance

**ID**: `nist-aal3-compliance`

**What It Checks**:
- Hardware-based cryptographic authenticator required
- Phishing-resistant authentication (FIDO2/WebAuthn)
- Non-exportable private keys
- Session timeout ≤ 12 hours
- Idle timeout ≤ 15 minutes
- No downgrade for reauthentication

**Detection Methods**:
- Check for AAL3-related ACR values (`urn:*:aal:3`, `phrh`)
- Look for FIDO2/WebAuthn support indicators
- Check for `hwk` (hardware key) in AMR values
- Look for phishing-resistant authenticator claims

**Result Statuses**:
- **PASS**: AAL3 requirements met (hardware + phishing-resistant)
- **FAIL**: No hardware authenticator support
- **WARNING**: Phishing resistance cannot be verified

---

#### Check 5: Session Management

**ID**: `nist-session-management`

**What It Checks**:
- Session timeout configuration per AAL level
- Idle timeout enforcement
- Reauthentication requirements
- Session binding mechanisms
- Session termination endpoints

**Detection Methods**:
- Check token expiration claims (`exp`, `iat`)
- Look for refresh token support
- Check for session management endpoints
- Analyze token lifetime values

**Result Statuses**:
- **PASS**: Session management meets NIST requirements
- **WARNING**: Session timeouts cannot be verified (server-side config)
- **INFO**: Token lifetime detected (list values)

---

### Configuration Schema

**Extend `oauth-guardian.config.yml`**:

```yaml
nist:
  # Target AAL level for compliance checking
  targetAAL: AAL2  # AAL1, AAL2, or AAL3

  # Session management validation
  sessionManagement:
    enabled: true
    enforceTimeouts: true  # Fail if timeouts exceed NIST limits

  # Authenticator lifecycle checks
  authenticatorLifecycle:
    enabled: false  # AAL2/AAL3 only

  # Custom ACR value mappings (for providers not following standards)
  acrMappings:
    "custom:acr:basic": "AAL1"
    "custom:acr:strong": "AAL2"
    "custom:acr:veryhigh": "AAL3"

  # Provider-specific overrides
  providerOverrides:
    okta:
      aal1: "urn:okta:loa:1fa:any"
      aal2: "urn:okta:loa:2fa:any"
      aal3: "phrh"
```

---

### Validation Matrix

**AAL Level Determination Logic**:

| Detected Indicators | AAL Level | Confidence |
|---------------------|-----------|------------|
| ACR contains `aal:3`, `phrh`, or FIDO2 | AAL3 | High |
| ACR contains `aal:2`, `2fa`, `mfa` | AAL2 | High |
| ACR contains `aal:1`, `1fa` | AAL1 | High |
| AMR contains `hwk` + `pin`/biometric | AAL3 | Medium |
| AMR contains `pwd` + `otp`/`sms` | AAL2 | Medium |
| AMR contains only `pwd` | AAL1 | High |
| No ACR/AMR metadata found | Unknown | N/A |

---

## Challenges and Limitations

### Challenge 1: Lack of Standardized ACR Values

**Problem**: No official NIST AAL ACR value standard exists

**Impact**:
- Each provider uses different ACR value formats
- Pattern matching becomes heuristic, not definitive
- False positives/negatives possible

**Mitigation**:
- Build database of known provider ACR mappings
- Allow user configuration for custom mappings
- Provide "unknown" status rather than incorrect assessment
- Offer manual validation guidance

---

### Challenge 2: Metadata Limitations

**Problem**: Most providers don't expose `acr_values_supported` in metadata

**Impact**:
- Automated detection not possible for many providers
- Cannot discover supported AAL levels programmatically
- Relies on documentation or manual testing

**Mitigation**:
- Gracefully handle missing metadata
- Return WARNING instead of FAIL
- Guide users to provider documentation
- Support configuration overrides

---

### Challenge 3: Session Management is Server-Side

**Problem**: Session timeout configuration is not exposed in OAuth metadata

**Impact**:
- Cannot automatically verify session timeout compliance
- Token expiration (`exp`) is not the same as session timeout
- Server-side session management is opaque to clients

**Mitigation**:
- Analyze token lifetime as proxy (with caveats)
- Check for refresh token support
- Provide guidance for manual verification
- Document limitation in check results

---

### Challenge 4: Dynamic vs Static Authentication

**Problem**: Authentication level can change during session (step-up authentication)

**Impact**:
- Initial authentication may be AAL1
- Step-up to AAL2/AAL3 mid-session
- Metadata shows capabilities, not current state

**Mitigation**:
- Focus on supported capabilities (what's available)
- Note that runtime verification requires actual authentication flow
- Suggest integration testing for complete validation

---

### Challenge 5: AMR Value Ambiguity

**Problem**: Same AMR value can satisfy different AAL levels depending on context

**Example**: `otp` could be:
- Software TOTP (AAL2 when combined with password)
- Hardware OTP device (AAL2/AAL3 depending on implementation)

**Mitigation**:
- Use AMR as supplementary evidence, not primary
- Require multiple indicators for higher confidence
- Document assumptions in check results

---

## Testing Strategy

### Real-World Provider Testing

**Phase 1: Major Providers**
1. Google OAuth / Google Identity
   - Test OIDC Discovery
   - Check for ACR/AMR support
   - Validate metadata fields

2. Microsoft Entra ID (Azure AD)
   - Test AAL compliance documentation
   - Verify AMR values
   - Check NIST mapping

3. Okta
   - Test custom ACR values
   - Verify step-up authentication
   - Validate AMR claims mapping

4. Auth0
   - Test metadata exposure
   - Check ACR/AMR support
   - Verify customization options

**Phase 2: Government/High-Security Providers**
1. Login.gov (US Government)
   - Reference NIST implementation
   - Validate compliance claims

**Phase 3: Open Source Identity Providers**
1. Keycloak
2. ORY Hydra
3. Authelia

---

### Mock Server Testing

**Create test fixtures for**:
1. Provider with full NIST AAL support (ideal case)
2. Provider with custom ACR values (mapping required)
3. Provider with no ACR metadata (fallback case)
4. Provider with AMR only (no ACR)
5. Provider with neither ACR nor AMR

**Test Cases**:
- ✅ AAL3 provider correctly identified
- ✅ AAL2 provider correctly identified
- ✅ AAL1 provider correctly identified
- ✅ Unknown provider returns WARNING (not FAIL)
- ✅ Custom ACR mapping works
- ✅ Graceful degradation when metadata missing
- ✅ Session timeout validation (when available)

---

## References

### NIST Standards
- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [NIST 800-63-4 Authentication Assurance Levels](https://pages.nist.gov/800-63-4/sp800-63b/aal/)
- [NIST AAL Implementation Resources](https://pages.nist.gov/800-63-3-Implementation-Resources/63B/AAL/)

### OAuth/OIDC Specifications
- [RFC 8176 - Authentication Method Reference Values](https://www.rfc-editor.org/rfc/rfc8176.html)
- [RFC 8414 - OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Extended Authentication Profile (EAP) ACR Values](https://openid.net/specs/openid-connect-eap-acr-values-1_0.html)

### Provider Documentation
- [Microsoft Entra NIST AAL Documentation](https://learn.microsoft.com/en-us/entra/standards/nist-about-authenticator-assurance-levels)
- [Okta Step-Up Authentication Guide](https://developer.okta.com/docs/guides/step-up-authentication/main/)
- [Okta AMR Claims Mapping](https://developer.okta.com/docs/guides/configure-amr-claims-mapping/main/)

---

## Next Steps

1. ✅ Complete research (this document)
2. ⏭️ Create NIST check base class (`src/checks/nist/base-nist-check.ts`)
3. ⏭️ Implement AAL detection check (`src/checks/nist/aal-detection.ts`)
4. ⏭️ Implement AAL1 compliance check (`src/checks/nist/aal1-compliance.ts`)
5. ⏭️ Implement AAL2 compliance check (`src/checks/nist/aal2-compliance.ts`)
6. ⏭️ Implement AAL3 compliance check (`src/checks/nist/aal3-compliance.ts`)
7. ⏭️ Implement session management check (`src/checks/nist/session-management.ts`)
8. ⏭️ Create provider ACR mapping database
9. ⏭️ Write comprehensive unit tests
10. ⏭️ Test against real OAuth providers

---

**Document Status**: ✅ Complete
**Last Updated**: 2025-10-16
**Next Action**: Begin implementation with AAL detection check
