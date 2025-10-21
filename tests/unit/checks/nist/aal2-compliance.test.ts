/**
 * AAL2 Compliance Check Tests
 *
 * Tests NIST SP 800-63B Authentication Assurance Level 2 (AAL2) compliance validation.
 * AAL2 requires multi-factor authentication with at least one cryptographic factor.
 */

import { describe, it, expect, beforeEach } from "vitest";
import MockAdapter from "axios-mock-adapter";
import axios from "axios";
import { AAL2ComplianceCheck } from "../../../../src/checks/nist/aal2-compliance.js";
import { HttpClient } from "../../../../src/auditor/http-client.js";
import { CheckStatus, CheckContext, Severity } from "../../../../src/types/index.js";

describe("AAL2ComplianceCheck", () => {
  let check: AAL2ComplianceCheck;
  let httpClient: HttpClient;
  let mockAxios: MockAdapter;

  beforeEach(() => {
    check = new AAL2ComplianceCheck();
    httpClient = new HttpClient({ timeout: 5000 });
    if (mockAxios) {
      mockAxios.reset();
    } else {
      mockAxios = new MockAdapter(axios);
    }
  });

  const createContext = (targetUrl: string): CheckContext => ({
    targetUrl,
    httpClient,
    logger: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} },
    config: {
      targetUrl,
      checks: { enabled: [] },
      reporting: { format: "terminal", output: "", verbose: false, includeRemediation: true },
    },
  });

  // ==================== Test Metadata Fixtures ====================

  /**
   * Full AAL2 compliance - all requirements met
   */
  const fullAAL2Metadata = {
    issuer: "https://example.com",
    authorization_endpoint: "https://example.com/oauth/authorize",
    token_endpoint: "https://example.com/oauth/token",
    response_types_supported: ["code", "id_token", "code id_token"],
    claims_supported: ["sub", "iss", "aud", "exp", "acr", "amr", "auth_time"],
    acr_values_supported: [
      "urn:nist:800-63-3:aal:2",
      "urn:nist:800-63-3:aal:1",
    ],
    code_challenge_methods_supported: ["S256"],
  };

  /**
   * OAuth-only provider (no OIDC) - fails AAL2
   */
  const oauthOnlyMetadata = {
    issuer: "https://example.com",
    authorization_endpoint: "https://example.com/oauth/authorize",
    token_endpoint: "https://example.com/oauth/token",
    response_types_supported: ["code"],  // No id_token
    code_challenge_methods_supported: ["S256"],
  };

  /**
   * OIDC provider but missing AAL2 support
   */
  const noAAL2Metadata = {
    issuer: "https://example.com",
    authorization_endpoint: "https://example.com/oauth/authorize",
    token_endpoint: "https://example.com/oauth/token",
    response_types_supported: ["code", "id_token"],
    claims_supported: ["sub", "iss", "acr", "auth_time"],
    acr_values_supported: ["urn:nist:800-63-3:aal:1"],  // Only AAL1
  };

  /**
   * HTTP endpoints (insecure) - critical failure
   */
  const httpEndpointsMetadata = {
    issuer: "https://example.com",
    authorization_endpoint: "http://example.com/oauth/authorize",  // HTTP!
    token_endpoint: "http://example.com/oauth/token",  // HTTP!
    response_types_supported: ["code", "id_token"],
    claims_supported: ["sub", "acr", "amr", "auth_time"],
    acr_values_supported: ["urn:nist:800-63-3:aal:2"],
  };

  /**
   * Missing auth_time claim - critical for session management
   */
  const noAuthTimeMetadata = {
    issuer: "https://example.com",
    authorization_endpoint: "https://example.com/oauth/authorize",
    token_endpoint: "https://example.com/oauth/token",
    response_types_supported: ["code", "id_token"],
    claims_supported: ["sub", "iss", "acr"],  // No auth_time
    acr_values_supported: ["urn:nist:800-63-3:aal:2"],
  };

  /**
   * Missing AMR claim - recommended but not critical
   */
  const noAMRMetadata = {
    issuer: "https://example.com",
    authorization_endpoint: "https://example.com/oauth/authorize",
    token_endpoint: "https://example.com/oauth/token",
    response_types_supported: ["code", "id_token"],
    claims_supported: ["sub", "iss", "acr", "auth_time"],  // No amr
    acr_values_supported: ["urn:nist:800-63-3:aal:2"],
  };

  /**
   * No ACR values advertised
   */
  const noACRMetadata = {
    issuer: "https://example.com",
    authorization_endpoint: "https://example.com/oauth/authorize",
    token_endpoint: "https://example.com/oauth/token",
    response_types_supported: ["code", "id_token"],
    claims_supported: ["sub", "iss", "auth_time"],
    // No acr_values_supported field
  };

  /**
   * MFA indicators present (alternative AAL2 patterns)
   */
  const mfaIndicatorsMetadata = {
    issuer: "https://example.com",
    authorization_endpoint: "https://example.com/oauth/authorize",
    token_endpoint: "https://example.com/oauth/token",
    response_types_supported: ["code", "id_token"],
    claims_supported: ["sub", "acr", "amr", "auth_time"],
    acr_values_supported: ["mfa", "2fa", "totp"],  // MFA patterns
    code_challenge_methods_supported: ["S256"],
  };

  // ==================== Basic Check Metadata Tests ====================

  it("should have correct check metadata", () => {
    expect(check.id).toBe("nist-aal2-compliance");
    expect(check.name).toBe("NIST AAL2 Compliance");
    expect(check.category).toBe("nist");
    expect(check.defaultSeverity).toBe(Severity.HIGH);
    expect(check.description).toContain("AAL2");
    expect(check.description).toContain("multi-factor");
  });

  // ==================== Metadata Discovery Tests ====================

  it("should warn when metadata discovery fails", async () => {
    const context = createContext("https://example.com");

    mockAxios.onGet("https://example.com/.well-known/openid-configuration").reply(404);
    mockAxios.onGet("https://example.com/.well-known/oauth-authorization-server").reply(404);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.WARNING);
    expect(result.message).toContain("Unable to discover OAuth metadata");
    expect(result.remediation).toContain("RFC 8414");
  });

  // ==================== Full Compliance Tests ====================

  it("should pass for full AAL2 compliance", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, fullAAL2Metadata);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.PASS);
    expect(result.message).toContain("AAL2 compliance check PASSED");
    expect(result.message).toContain("HTTPS enforced");
    expect(result.message).toContain("OpenID Connect provider");
    expect(result.message).toContain("AAL2 support advertised");
    expect(result.message).toContain("auth_time");

    // Validate metadata
    expect(result.metadata?.https_enforced).toBe(true);
    expect(result.metadata?.oidc_provider).toBe(true);
    expect(result.metadata?.aal2_advertised).toBe(true);
    expect(result.metadata?.auth_time_supported).toBe(true);
  });

  it("should pass with warning when AMR claim is missing", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, noAMRMetadata);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.WARNING);
    expect(result.message).toContain("passed with recommendations");
    expect(result.message).toContain("AMR");
    expect(result.remediation).toContain("Authentication Method Reference");

    expect(result.metadata?.aal2_advertised).toBe(true);
    expect(result.metadata?.auth_time_supported).toBe(true);
    expect(result.metadata?.amr_claim_supported).toBe(false);
  });

  // ==================== Critical Failure Tests ====================

  it("should fail when provider is not OIDC", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(404);
    mockAxios
      .onGet("https://example.com/.well-known/oauth-authorization-server")
      .reply(200, oauthOnlyMetadata);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.FAIL);
    expect(result.severity).toBe(Severity.HIGH);
    expect(result.message).toContain("Not an OpenID Connect provider");
    expect(result.message).toContain("multi-factor authentication context");

    expect(result.metadata?.oidc_provider).toBe(false);
    expect(result.remediation).toContain("Implement OpenID Connect");
  });

  it("should fail when HTTPS is not enforced", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, httpEndpointsMetadata);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.FAIL);
    expect(result.severity).toBe(Severity.HIGH);
    expect(result.message).toContain("HTTPS not enforced");
    expect(result.message).toContain("http://example.com/oauth/authorize");
    expect(result.message).toContain("http://example.com/oauth/token");

    expect(result.metadata?.https_enforced).toBe(false);
    expect(result.metadata?.insecure_endpoints).toContain("http://example.com/oauth/authorize");
    expect(result.metadata?.insecure_endpoints).toContain("http://example.com/oauth/token");
    expect(result.remediation).toContain("Enable HTTPS");
    expect(result.remediation).toContain("TLS 1.2");
  });

  it("should fail when AAL2 is not advertised", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, noAAL2Metadata);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.FAIL);
    expect(result.severity).toBe(Severity.HIGH);
    expect(result.message).toContain("does not advertise AAL2 support");
    expect(result.message).toContain("multi-factor authentication");

    expect(result.metadata?.aal2_advertised).toBe(false);
    expect(result.remediation).toContain("acr_values_supported");
    expect(result.remediation).toContain("urn:nist:800-63-3:aal:2");
  });

  it("should fail when auth_time claim is missing", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, noAuthTimeMetadata);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.FAIL);
    expect(result.severity).toBe(Severity.HIGH);
    expect(result.message).toContain("auth_time claim not advertised");
    expect(result.message).toContain("session timeout enforcement");

    expect(result.metadata?.auth_time_supported).toBe(false);
    expect(result.remediation).toContain("authentication event timestamping");
    expect(result.remediation).toContain("12-hour maximum");
  });

  // ==================== Multiple Issues Tests ====================

  it("should report multiple critical issues together", async () => {
    const context = createContext("https://example.com");

    const multipleIssuesMetadata = {
      issuer: "https://example.com",
      authorization_endpoint: "http://example.com/oauth/authorize",  // HTTP
      token_endpoint: "https://example.com/oauth/token",
      response_types_supported: ["code", "id_token"],
      claims_supported: ["sub", "iss"],  // No auth_time
      acr_values_supported: ["urn:nist:800-63-3:aal:1"],  // No AAL2
    };

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, multipleIssuesMetadata);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.FAIL);
    expect(result.message).toContain("HTTPS not enforced");
    expect(result.message).toContain("does not advertise AAL2");
    expect(result.message).toContain("auth_time");

    expect(result.metadata?.https_enforced).toBe(false);
    expect(result.metadata?.aal2_advertised).toBe(false);
    expect(result.metadata?.auth_time_supported).toBe(false);
  });

  // ==================== ACR Detection Tests ====================

  it("should detect AAL2 from alternative MFA patterns", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, mfaIndicatorsMetadata);

    const result = await check.execute(context);

    // Should detect MFA patterns as AAL2 support
    expect(result.status).not.toBe(CheckStatus.FAIL);
    expect(result.metadata?.aal2_advertised).toBe(true);
    expect(result.metadata?.acr_values).toContain("mfa");
    expect(result.metadata?.acr_values).toContain("2fa");
    expect(result.metadata?.acr_values).toContain("totp");
  });

  it("should handle unknown ACR values gracefully", async () => {
    const context = createContext("https://example.com");

    const customACRMetadata = {
      issuer: "https://example.com",
      authorization_endpoint: "https://example.com/oauth/authorize",
      token_endpoint: "https://example.com/oauth/token",
      response_types_supported: ["code", "id_token"],
      claims_supported: ["sub", "acr", "amr", "auth_time"],
      acr_values_supported: ["custom-level-1", "custom-level-2"],  // Unknown patterns
    };

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, customACRMetadata);

    const result = await check.execute(context);

    // Should warn about inability to determine AAL2 support
    expect(result.status).toBe(CheckStatus.WARNING);
    expect(result.message).toContain("Unable to determine AAL2 support");
    expect(result.metadata?.aal2_advertised).toBe("unknown");
  });

  // ==================== MFA Indicators Tests ====================

  it("should detect MFA indicators from ACR values", async () => {
    const context = createContext("https://example.com");

    const withMFAIndicators = {
      ...fullAAL2Metadata,
      acr_values_supported: [
        "urn:nist:800-63-3:aal:2",
        "phr",  // Okta phishing-resistant
        "totp",
        "otp",
      ],
    };

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, withMFAIndicators);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.PASS);
    expect(result.metadata?.mfa_indicators?.hasIndicators).toBe(true);
    expect(result.metadata?.mfa_indicators?.indicators).toContain("ACR value: phr");
  });

  it("should detect PKCE as MFA indicator", async () => {
    const context = createContext("https://example.com");

    const withPKCE = {
      ...fullAAL2Metadata,
      code_challenge_methods_supported: ["S256"],
    };

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, withPKCE);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.PASS);
    expect(result.metadata?.mfa_indicators?.hasIndicators).toBe(true);
    expect(result.metadata?.mfa_indicators?.indicators).toContain("PKCE support (often used with WebAuthn)");
  });

  it("should recommend MFA improvements when no indicators found", async () => {
    const context = createContext("https://example.com");

    const noMFAIndicators = {
      issuer: "https://example.com",
      authorization_endpoint: "https://example.com/oauth/authorize",
      token_endpoint: "https://example.com/oauth/token",
      response_types_supported: ["code", "id_token"],
      claims_supported: ["sub", "acr", "auth_time"],
      acr_values_supported: ["custom-strong"],  // Custom ACR without MFA patterns
      // No PKCE, no MFA-specific ACR values
    };

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, noMFAIndicators);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.WARNING);
    expect(result.message).toContain("passed with recommendations");
    expect(result.message).toContain("No multi-factor authentication indicators");
    expect(result.metadata?.mfa_indicators?.hasIndicators).toBe(false);
  });

  // ==================== Remediation Guidance Tests ====================

  it("should provide comprehensive remediation for failed checks", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, noAAL2Metadata);

    const result = await check.execute(context);

    expect(result.remediation).toBeDefined();
    expect(result.remediation).toContain("Critical Fixes Required");
    expect(result.remediation).toContain("multi-factor authentication");
    expect(result.remediation).toContain("Session Management Requirements");
    expect(result.remediation).toContain("12 hours");
    expect(result.remediation).toContain("30 minutes");
    expect(result.remediation).toContain("FIDO2/WebAuthn");
  });

  it("should include session timeout requirements in pass message", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, fullAAL2Metadata);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.PASS);
    expect(result.message).toContain("Maximum session duration: 12 hours");
    expect(result.message).toContain("Idle timeout: 30 minutes (preferred) or 60 minutes (maximum)");
    expect(result.message).toContain("Reauthentication required for sensitive operations");
  });

  // ==================== Edge Cases ====================

  it("should handle missing response_types_supported", async () => {
    const context = createContext("https://example.com");

    const missingResponseTypes = {
      issuer: "https://example.com",
      authorization_endpoint: "https://example.com/oauth/authorize",
      token_endpoint: "https://example.com/oauth/token",
      // No response_types_supported
      claims_supported: ["sub", "acr", "auth_time"],
      acr_values_supported: ["urn:nist:800-63-3:aal:2"],
    };

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, missingResponseTypes);

    const result = await check.execute(context);

    // Should treat as non-OIDC provider
    expect(result.status).toBe(CheckStatus.FAIL);
    expect(result.message).toContain("Not an OpenID Connect provider");
  });

  it("should handle empty acr_values_supported array", async () => {
    const context = createContext("https://example.com");

    const emptyACR = {
      issuer: "https://example.com",
      authorization_endpoint: "https://example.com/oauth/authorize",
      token_endpoint: "https://example.com/oauth/token",
      response_types_supported: ["code", "id_token"],
      claims_supported: ["sub", "acr", "amr", "auth_time"],
      acr_values_supported: [],  // Empty array
    };

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, emptyACR);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.WARNING);
    expect(result.message).toContain("Unable to determine AAL2 support");
    expect(result.metadata?.aal2_advertised).toBe("unknown");
  });

  it("should validate metadata structure correctly", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, fullAAL2Metadata);

    const result = await check.execute(context);

    // Validate metadata structure
    expect(result.metadata).toHaveProperty("issuer", "https://example.com");
    expect(result.metadata).toHaveProperty("https_enforced");
    expect(result.metadata).toHaveProperty("oidc_provider");
    expect(result.metadata).toHaveProperty("aal2_advertised");
    expect(result.metadata).toHaveProperty("acr_values");
    expect(result.metadata).toHaveProperty("auth_time_supported");
    expect(result.metadata).toHaveProperty("amr_claim_supported");
    expect(result.metadata).toHaveProperty("mfa_indicators");
  });
});
