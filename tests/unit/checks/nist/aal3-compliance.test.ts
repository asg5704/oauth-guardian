/**
 * AAL3 Compliance Check Tests
 *
 * Tests NIST SP 800-63B Authentication Assurance Level 3 (AAL3) compliance validation.
 * AAL3 requires hardware-based cryptographic authenticators with phishing resistance.
 */

import { describe, it, expect, beforeEach } from "vitest";
import MockAdapter from "axios-mock-adapter";
import axios from "axios";
import { AAL3ComplianceCheck } from "../../../../src/checks/nist/aal3-compliance.js";
import { HttpClient } from "../../../../src/auditor/http-client.js";
import { CheckStatus, CheckContext, Severity } from "../../../../src/types/index.js";

describe("AAL3ComplianceCheck", () => {
  let check: AAL3ComplianceCheck;
  let httpClient: HttpClient;
  let mockAxios: MockAdapter;

  beforeEach(() => {
    check = new AAL3ComplianceCheck();
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
   * Full AAL3 compliance - all requirements met
   */
  const fullAAL3Metadata = {
    issuer: "https://example.com",
    authorization_endpoint: "https://example.com/oauth/authorize",
    token_endpoint: "https://example.com/oauth/token",
    response_types_supported: ["code", "id_token", "code id_token"],
    claims_supported: ["sub", "iss", "aud", "exp", "acr", "amr", "auth_time"],
    acr_values_supported: [
      "urn:nist:800-63-3:aal:3",
      "urn:nist:800-63-3:aal:2",
      "urn:nist:800-63-3:aal:1",
      "phrh", // Phishing-resistant hardware
    ],
    code_challenge_methods_supported: ["S256"],
  };

  /**
   * OAuth-only provider (no OIDC) - fails AAL3
   */
  const oauthOnlyMetadata = {
    issuer: "https://example.com",
    authorization_endpoint: "https://example.com/oauth/authorize",
    token_endpoint: "https://example.com/oauth/token",
    response_types_supported: ["code"],  // No id_token
    code_challenge_methods_supported: ["S256"],
  };

  /**
   * OIDC provider but missing AAL3 support
   */
  const noAAL3Metadata = {
    issuer: "https://example.com",
    authorization_endpoint: "https://example.com/oauth/authorize",
    token_endpoint: "https://example.com/oauth/token",
    response_types_supported: ["code", "id_token"],
    claims_supported: ["sub", "iss", "acr", "amr", "auth_time"],
    acr_values_supported: [
      "urn:nist:800-63-3:aal:2",
      "urn:nist:800-63-3:aal:1",
    ],  // Only AAL1 and AAL2
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
    acr_values_supported: ["urn:nist:800-63-3:aal:3"],
  };

  /**
   * Missing auth_time claim - critical for session management
   */
  const noAuthTimeMetadata = {
    issuer: "https://example.com",
    authorization_endpoint: "https://example.com/oauth/authorize",
    token_endpoint: "https://example.com/oauth/token",
    response_types_supported: ["code", "id_token"],
    claims_supported: ["sub", "iss", "acr", "amr"],  // No auth_time
    acr_values_supported: ["urn:nist:800-63-3:aal:3"],
    code_challenge_methods_supported: ["S256"],
  };

  /**
   * Missing AMR claim - critical for AAL3
   */
  const noAMRMetadata = {
    issuer: "https://example.com",
    authorization_endpoint: "https://example.com/oauth/authorize",
    token_endpoint: "https://example.com/oauth/token",
    response_types_supported: ["code", "id_token"],
    claims_supported: ["sub", "iss", "acr", "auth_time"],  // No amr
    acr_values_supported: ["urn:nist:800-63-3:aal:3"],
    code_challenge_methods_supported: ["S256"],
  };

  /**
   * No hardware authenticator indicators
   */
  const noHardwareIndicators = {
    issuer: "https://example.com",
    authorization_endpoint: "https://example.com/oauth/authorize",
    token_endpoint: "https://example.com/oauth/token",
    response_types_supported: ["code", "id_token"],
    claims_supported: ["sub", "acr", "amr", "auth_time"],
    acr_values_supported: ["custom-strong"],  // No hardware patterns
    // No PKCE S256
  };

  /**
   * FIDO2/WebAuthn indicators
   */
  const fido2Metadata = {
    issuer: "https://example.com",
    authorization_endpoint: "https://example.com/oauth/authorize",
    token_endpoint: "https://example.com/oauth/token",
    response_types_supported: ["code", "id_token"],
    claims_supported: ["sub", "acr", "amr", "auth_time"],
    acr_values_supported: ["webauthn", "fido2", "u2f", "urn:nist:800-63-3:aal:3"],
    code_challenge_methods_supported: ["S256"],
  };

  /**
   * No phishing resistance indicators
   */
  const noPhishingResistance = {
    issuer: "https://example.com",
    authorization_endpoint: "https://example.com/oauth/authorize",
    token_endpoint: "https://example.com/oauth/token",
    response_types_supported: ["code", "id_token"],
    claims_supported: ["sub", "acr", "amr", "auth_time"],
    acr_values_supported: ["urn:nist:800-63-3:aal:3"],
    code_challenge_methods_supported: ["S256"],
    // No explicit phishing-resistant indicators like "phr", "phrh"
  };

  // ==================== Basic Check Metadata Tests ====================

  it("should have correct check metadata", () => {
    expect(check.id).toBe("nist-aal3-compliance");
    expect(check.name).toBe("NIST AAL3 Compliance");
    expect(check.category).toBe("nist");
    expect(check.defaultSeverity).toBe(Severity.CRITICAL);
    expect(check.description).toContain("AAL3");
    expect(check.description).toContain("hardware-based");
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

  it("should pass for full AAL3 compliance", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, fullAAL3Metadata);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.PASS);
    expect(result.message).toContain("AAL3 compliance check PASSED");
    expect(result.message).toContain("HTTPS enforced");
    expect(result.message).toContain("OpenID Connect provider");
    expect(result.message).toContain("AAL3 support advertised");
    expect(result.message).toContain("Hardware cryptographic authenticator");
    expect(result.message).toContain("auth_time");
    expect(result.message).toContain("AMR claim");
    expect(result.message).toContain("Phishing-resistant");

    // Validate metadata
    expect(result.metadata?.https_enforced).toBe(true);
    expect(result.metadata?.oidc_provider).toBe(true);
    expect(result.metadata?.aal3_advertised).toBe(true);
    expect(result.metadata?.auth_time_supported).toBe(true);
    expect(result.metadata?.amr_claim_supported).toBe(true);
  });

  it("should pass with warning when phishing resistance indicators are missing", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, noPhishingResistance);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.WARNING);
    expect(result.message).toContain("passed with recommendations");
    expect(result.message).toContain("phishing-resistant authentication indicators");
    expect(result.remediation).toContain("phishing resistance");

    expect(result.metadata?.aal3_advertised).toBe(true);
    expect(result.metadata?.auth_time_supported).toBe(true);
    expect(result.metadata?.amr_claim_supported).toBe(true);
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
    expect(result.severity).toBe(Severity.CRITICAL);
    expect(result.message).toContain("Not an OpenID Connect provider");
    expect(result.message).toContain("hardware authenticator verification");

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
    expect(result.severity).toBe(Severity.CRITICAL);
    expect(result.message).toContain("HTTPS not enforced");
    expect(result.message).toContain("http://example.com/oauth/authorize");
    expect(result.message).toContain("http://example.com/oauth/token");

    expect(result.metadata?.https_enforced).toBe(false);
    expect(result.metadata?.insecure_endpoints).toContain("http://example.com/oauth/authorize");
    expect(result.metadata?.insecure_endpoints).toContain("http://example.com/oauth/token");
    expect(result.remediation).toContain("Enable HTTPS");
    expect(result.remediation).toContain("TLS 1.2");
  });

  it("should fail when AAL3 is not advertised", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, noAAL3Metadata);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.FAIL);
    expect(result.severity).toBe(Severity.CRITICAL);
    expect(result.message).toContain("does not advertise AAL3 support");
    expect(result.message).toContain("hardware-based cryptographic authenticators");

    expect(result.metadata?.aal3_advertised).toBe(false);
    expect(result.remediation).toContain("acr_values_supported");
    expect(result.remediation).toContain("urn:nist:800-63-3:aal:3");
  });

  it("should fail when auth_time claim is missing", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, noAuthTimeMetadata);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.FAIL);
    expect(result.severity).toBe(Severity.CRITICAL);
    expect(result.message).toContain("auth_time claim not advertised");
    expect(result.message).toContain("session timeout enforcement");
    expect(result.message).toContain("15-minute idle");

    expect(result.metadata?.auth_time_supported).toBe(false);
    expect(result.remediation).toContain("authentication event timestamping");
  });

  it("should fail when AMR claim is missing", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, noAMRMetadata);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.FAIL);
    expect(result.severity).toBe(Severity.CRITICAL);
    expect(result.message).toContain("AMR (Authentication Method Reference) claim not advertised");
    expect(result.message).toContain("hardware cryptographic authenticator usage");

    expect(result.metadata?.amr_claim_supported).toBe(false);
    expect(result.remediation).toContain("AMR (Authentication Method Reference)");
    expect(result.remediation).toContain("hwk");
  });

  it("should fail when no hardware authenticator indicators are present", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, noHardwareIndicators);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.FAIL);
    expect(result.severity).toBe(Severity.CRITICAL);
    expect(result.message).toContain("No hardware authenticator indicators");
    expect(result.message).toContain("FIDO2/WebAuthn");

    expect(result.metadata?.hardware_auth_indicators?.hasIndicators).toBe(false);
    expect(result.remediation).toContain("hardware-based cryptographic authentication");
    expect(result.remediation).toContain("FIDO2");
  });

  // ==================== Multiple Issues Tests ====================

  it("should report multiple critical issues together", async () => {
    const context = createContext("https://example.com");

    const multipleIssuesMetadata = {
      issuer: "https://example.com",
      authorization_endpoint: "http://example.com/oauth/authorize",  // HTTP
      token_endpoint: "https://example.com/oauth/token",
      response_types_supported: ["code", "id_token"],
      claims_supported: ["sub", "iss"],  // No auth_time, no amr
      acr_values_supported: ["urn:nist:800-63-3:aal:1"],  // No AAL3
      // No hardware indicators
    };

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, multipleIssuesMetadata);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.FAIL);
    expect(result.message).toContain("HTTPS not enforced");
    expect(result.message).toContain("does not advertise AAL3");
    expect(result.message).toContain("auth_time");
    expect(result.message).toContain("AMR");
    expect(result.message).toContain("hardware authenticator indicators");

    expect(result.metadata?.https_enforced).toBe(false);
    expect(result.metadata?.aal3_advertised).toBe(false);
    expect(result.metadata?.auth_time_supported).toBe(false);
    expect(result.metadata?.amr_claim_supported).toBe(false);
  });

  // ==================== Hardware Authenticator Detection Tests ====================

  it("should detect AAL3 from standard ACR value", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, fullAAL3Metadata);

    const result = await check.execute(context);

    expect(result.status).not.toBe(CheckStatus.FAIL);
    expect(result.metadata?.aal3_advertised).toBe(true);
    expect(result.metadata?.acr_values).toContain("urn:nist:800-63-3:aal:3");
  });

  it("should detect hardware authenticators from FIDO2/WebAuthn patterns", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, fido2Metadata);

    const result = await check.execute(context);

    // Should detect FIDO2/WebAuthn patterns as AAL3 support
    expect(result.status).not.toBe(CheckStatus.FAIL);
    expect(result.metadata?.hardware_auth_indicators?.hasIndicators).toBe(true);
    expect(result.metadata?.hardware_auth_indicators?.indicators).toContain("ACR value: webauthn");
    expect(result.metadata?.hardware_auth_indicators?.indicators).toContain("ACR value: fido2");
  });

  it("should detect PKCE S256 as hardware auth indicator", async () => {
    const context = createContext("https://example.com");

    const withPKCE = {
      ...fullAAL3Metadata,
      code_challenge_methods_supported: ["S256"],
    };

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, withPKCE);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.PASS);
    expect(result.metadata?.hardware_auth_indicators?.hasIndicators).toBe(true);
    expect(result.metadata?.hardware_auth_indicators?.indicators).toContain("PKCE S256 support (required for FIDO2)");
  });

  it("should detect Okta phishing-resistant hardware (phrh) pattern", async () => {
    const context = createContext("https://example.com");

    const oktaMetadata = {
      ...fullAAL3Metadata,
      acr_values_supported: ["phrh", "phr"],  // Okta patterns
    };

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, oktaMetadata);

    const result = await check.execute(context);

    expect(result.status).not.toBe(CheckStatus.FAIL);
    expect(result.metadata?.hardware_auth_indicators?.hasIndicators).toBe(true);
    expect(result.metadata?.hardware_auth_indicators?.indicators).toContain("ACR value: phrh");
  });

  // ==================== Phishing Resistance Tests ====================

  it("should detect phishing resistance indicators", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, fullAAL3Metadata);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.PASS);
    expect(result.metadata?.phishing_resistant_indicators).toBeDefined();
    expect(result.metadata?.phishing_resistant_indicators).toContain("phrh");
  });

  it("should recommend phishing resistance improvements when indicators missing", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, noPhishingResistance);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.WARNING);
    expect(result.message).toContain("phishing-resistant authentication indicators");
    expect(result.remediation).toContain("phishing resistance");
    expect(result.remediation).toContain("user verification");
  });

  // ==================== Remediation Guidance Tests ====================

  it("should provide comprehensive remediation for failed checks", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, noAAL3Metadata);

    const result = await check.execute(context);

    expect(result.remediation).toBeDefined();
    expect(result.remediation).toContain("Critical Fixes Required");
    expect(result.remediation).toContain("hardware-based cryptographic authentication");
    expect(result.remediation).toContain("FIDO2/WebAuthn");
    expect(result.remediation).toContain("Smart Cards");
    expect(result.remediation).toContain("Session Management Requirements");
    expect(result.remediation).toContain("12 hours");
    expect(result.remediation).toContain("15 minutes");
  });

  it("should include WebAuthn implementation example in remediation", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, noHardwareIndicators);

    const result = await check.execute(context);

    expect(result.remediation).toContain("navigator.credentials.create");
    expect(result.remediation).toContain("authenticatorSelection");
    expect(result.remediation).toContain("cross-platform");
    expect(result.remediation).toContain("userVerification");
  });

  it("should include AMR examples for hardware keys in remediation", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, noAMRMetadata);

    const result = await check.execute(context);

    expect(result.remediation).toContain("hwk");
    expect(result.remediation).toContain("sc");
    expect(result.remediation).toContain("Hardware key");
    expect(result.remediation).toContain("Smart card");
  });

  it("should include session timeout requirements in pass message", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, fullAAL3Metadata);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.PASS);
    expect(result.message).toContain("Maximum session duration: 12 hours");
    expect(result.message).toContain("Idle timeout: 15 minutes maximum");
    expect(result.message).toContain("bound to hardware authenticator");
  });

  // ==================== Edge Cases ====================

  it("should handle missing response_types_supported", async () => {
    const context = createContext("https://example.com");

    const missingResponseTypes = {
      issuer: "https://example.com",
      authorization_endpoint: "https://example.com/oauth/authorize",
      token_endpoint: "https://example.com/oauth/token",
      // No response_types_supported
      claims_supported: ["sub", "acr", "amr", "auth_time"],
      acr_values_supported: ["urn:nist:800-63-3:aal:3"],
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

    expect(result.status).toBe(CheckStatus.FAIL);
    expect(result.message).toContain("Unable to determine AAL3 support");
    expect(result.metadata?.aal3_advertised).toBe("unknown");
  });

  it("should validate metadata structure correctly", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, fullAAL3Metadata);

    const result = await check.execute(context);

    // Validate metadata structure
    expect(result.metadata).toHaveProperty("issuer", "https://example.com");
    expect(result.metadata).toHaveProperty("https_enforced");
    expect(result.metadata).toHaveProperty("oidc_provider");
    expect(result.metadata).toHaveProperty("aal3_advertised");
    expect(result.metadata).toHaveProperty("acr_values");
    expect(result.metadata).toHaveProperty("auth_time_supported");
    expect(result.metadata).toHaveProperty("amr_claim_supported");
    expect(result.metadata).toHaveProperty("hardware_auth_indicators");
    expect(result.metadata).toHaveProperty("phishing_resistant_indicators");
  });

  it("should handle case-insensitive pattern matching", async () => {
    const context = createContext("https://example.com");

    const mixedCaseMetadata = {
      issuer: "https://example.com",
      authorization_endpoint: "https://example.com/oauth/authorize",
      token_endpoint: "https://example.com/oauth/token",
      response_types_supported: ["code", "id_token"],
      claims_supported: ["sub", "acr", "amr", "auth_time"],
      acr_values_supported: ["FIDO2", "WebAuthn", "AAL3"],  // Mixed case
      code_challenge_methods_supported: ["S256"],
    };

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, mixedCaseMetadata);

    const result = await check.execute(context);

    // Should detect patterns regardless of case
    expect(result.status).not.toBe(CheckStatus.FAIL);
    expect(result.metadata?.hardware_auth_indicators?.hasIndicators).toBe(true);
  });
});
