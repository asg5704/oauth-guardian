/**
 * Unit tests for NIST AAL1 Compliance Check
 */

import { describe, it, expect, beforeEach } from "vitest";
import MockAdapter from "axios-mock-adapter";
import axios from "axios";
import { AAL1ComplianceCheck } from "../../../../src/checks/nist/aal1-compliance.js";
import { HttpClient } from "../../../../src/auditor/http-client.js";
import { CheckStatus, CheckContext, Severity } from "../../../../src/types/index.js";

describe("AAL1ComplianceCheck", () => {
  let check: AAL1ComplianceCheck;
  let httpClient: HttpClient;
  let mockAxios: MockAdapter;

  beforeEach(() => {
    check = new AAL1ComplianceCheck();
    httpClient = new HttpClient({ timeout: 5000 });
    mockAxios = new MockAdapter(axios);
  });

  const createContext = (targetUrl: string): CheckContext => ({
    targetUrl,
    httpClient,
    logger: {
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {},
    },
    config: {
      targetUrl,
      checks: { enabled: [] },
      reporting: {
        format: "terminal",
        output: "",
        verbose: false,
        includeRemediation: true,
      },
    },
  });

  describe("Metadata Discovery", () => {
    it("should return warning when metadata discovery fails", async () => {
      const targetUrl = "https://example.com";
      const context = createContext(targetUrl);

      // Mock failed discovery
      mockAxios
        .onGet("https://example.com/.well-known/oauth-authorization-server")
        .reply(404);
      mockAxios
        .onGet("https://example.com/.well-known/openid-configuration")
        .reply(404);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).toContain("Unable to discover OAuth metadata");
      expect(result.remediation).toContain("RFC 8414");
    });
  });

  describe("HTTPS Enforcement", () => {
    it("should fail when endpoints use HTTP instead of HTTPS", async () => {
      const targetUrl = "https://example.com";
      const context = createContext(targetUrl);

      // Mock metadata with HTTP endpoints
      mockAxios
        .onGet("https://example.com/.well-known/openid-configuration")
        .reply(200, {
          issuer: "https://example.com",
          authorization_endpoint: "http://example.com/oauth/authorize", // HTTP!
          token_endpoint: "https://example.com/oauth/token",
          response_types_supported: ["code", "id_token"],
          claims_supported: ["sub", "iss", "acr", "auth_time"],
          acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        });

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.FAIL);
      expect(result.severity).toBe(Severity.MEDIUM);
      expect(result.message).toContain("HTTPS not enforced");
      expect(result.message).toContain("http://example.com/oauth/authorize");
      expect(result.remediation).toContain("Enable HTTPS");
      expect(result.metadata?.https_enforced).toBe(false);
    });

    it("should pass when all endpoints use HTTPS", async () => {
      const targetUrl = "https://example.com";
      const context = createContext(targetUrl);

      // Mock metadata with all HTTPS endpoints
      mockAxios
        .onGet("https://example.com/.well-known/openid-configuration")
        .reply(200, {
          issuer: "https://example.com",
          authorization_endpoint: "https://example.com/oauth/authorize",
          token_endpoint: "https://example.com/oauth/token",
          response_types_supported: ["code", "id_token"],
          claims_supported: ["sub", "iss", "acr", "auth_time"],
          acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        });

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.metadata?.https_enforced).toBe(true);
    });
  });

  describe("OIDC Provider Detection", () => {
    it("should warn when provider is OAuth-only (not OIDC)", async () => {
      const targetUrl = "https://example.com";
      const context = createContext(targetUrl);

      // Mock OAuth-only metadata (no id_token support)
      mockAxios
        .onGet("https://example.com/.well-known/openid-configuration")
        .reply(404);
      mockAxios
        .onGet("https://example.com/.well-known/oauth-authorization-server")
        .reply(200, {
          issuer: "https://example.com",
          authorization_endpoint: "https://example.com/oauth/authorize",
          token_endpoint: "https://example.com/oauth/token",
          response_types_supported: ["code"], // No id_token
        });

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).toContain("OpenID Connect");
      expect(result.metadata?.oidc_provider).toBe(false);
    });

    it("should recognize OIDC provider by id_token support", async () => {
      const targetUrl = "https://example.com";
      const context = createContext(targetUrl);

      // Mock OIDC metadata
      mockAxios
        .onGet("https://example.com/.well-known/openid-configuration")
        .reply(200, {
          issuer: "https://example.com",
          authorization_endpoint: "https://example.com/oauth/authorize",
          token_endpoint: "https://example.com/oauth/token",
          response_types_supported: ["code", "id_token"],
          claims_supported: ["sub", "iss"],
        });

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.WARNING); // Warning due to missing AAL1 advertising
      expect(result.metadata?.oidc_provider).toBe(true);
    });
  });

  describe("AAL1 Support Detection", () => {
    it("should pass when AAL1 is explicitly advertised", async () => {
      const targetUrl = "https://example.com";
      const context = createContext(targetUrl);

      mockAxios
        .onGet("https://example.com/.well-known/openid-configuration")
        .reply(200, {
          issuer: "https://example.com",
          authorization_endpoint: "https://example.com/oauth/authorize",
          token_endpoint: "https://example.com/oauth/token",
          response_types_supported: ["code", "id_token"],
          claims_supported: ["sub", "iss", "acr", "auth_time"],
          acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        });

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.metadata?.aal1_advertised).toBe(true);
      expect(result.metadata?.acr_values).toContain("urn:nist:800-63-3:aal:1");
    });

    it("should warn when AAL1 is not advertised in ACR values", async () => {
      const targetUrl = "https://example.com";
      const context = createContext(targetUrl);

      mockAxios
        .onGet("https://example.com/.well-known/openid-configuration")
        .reply(200, {
          issuer: "https://example.com",
          authorization_endpoint: "https://example.com/oauth/authorize",
          token_endpoint: "https://example.com/oauth/token",
          response_types_supported: ["code", "id_token"],
          claims_supported: ["sub", "iss", "acr"],
          acr_values_supported: ["urn:nist:800-63-3:aal:2", "urn:nist:800-63-3:aal:3"], // AAL2/3 only
        });

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).toContain("does not advertise AAL1 support");
      expect(result.metadata?.aal1_advertised).toBe(false);
    });

    it("should warn when ACR values are not advertised at all", async () => {
      const targetUrl = "https://example.com";
      const context = createContext(targetUrl);

      mockAxios
        .onGet("https://example.com/.well-known/openid-configuration")
        .reply(200, {
          issuer: "https://example.com",
          authorization_endpoint: "https://example.com/oauth/authorize",
          token_endpoint: "https://example.com/oauth/token",
          response_types_supported: ["code", "id_token"],
          claims_supported: ["sub", "iss", "acr"],
          // No acr_values_supported
        });

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).toContain("Unable to determine AAL support");
      expect(result.metadata?.aal1_advertised).toBe("unknown");
    });
  });

  describe("auth_time Support", () => {
    it("should pass when auth_time claim is supported", async () => {
      const targetUrl = "https://example.com";
      const context = createContext(targetUrl);

      mockAxios
        .onGet("https://example.com/.well-known/openid-configuration")
        .reply(200, {
          issuer: "https://example.com",
          authorization_endpoint: "https://example.com/oauth/authorize",
          token_endpoint: "https://example.com/oauth/token",
          response_types_supported: ["code", "id_token"],
          claims_supported: ["sub", "iss", "acr", "auth_time"],
          acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        });

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.metadata?.auth_time_supported).toBe(true);
      expect(result.message).toContain("auth_time");
    });

    it("should warn when auth_time claim is not supported", async () => {
      const targetUrl = "https://example.com";
      const context = createContext(targetUrl);

      mockAxios
        .onGet("https://example.com/.well-known/openid-configuration")
        .reply(200, {
          issuer: "https://example.com",
          authorization_endpoint: "https://example.com/oauth/authorize",
          token_endpoint: "https://example.com/oauth/token",
          response_types_supported: ["code", "id_token"],
          claims_supported: ["sub", "iss", "acr"], // No auth_time
          acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        });

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).toContain("auth_time");
      expect(result.metadata?.auth_time_supported).toBe(false);
    });
  });

  describe("Full Compliance Scenarios", () => {
    it("should pass with full AAL1 compliance", async () => {
      const targetUrl = "https://example.com";
      const context = createContext(targetUrl);

      mockAxios
        .onGet("https://example.com/.well-known/openid-configuration")
        .reply(200, {
          issuer: "https://example.com",
          authorization_endpoint: "https://example.com/oauth/authorize",
          token_endpoint: "https://example.com/oauth/token",
          response_types_supported: ["code", "id_token"],
          claims_supported: ["sub", "iss", "acr", "amr", "auth_time"],
          acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        });

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.message).toContain("AAL1 compliance check PASSED");
      expect(result.message).toContain("HTTPS enforced");
      expect(result.message).toContain("OpenID Connect");
      expect(result.message).toContain("AAL1 support advertised");
      expect(result.message).toContain("auth_time");
    });

    it("should warn with partial compliance (missing auth_time)", async () => {
      const targetUrl = "https://example.com";
      const context = createContext(targetUrl);

      mockAxios
        .onGet("https://example.com/.well-known/openid-configuration")
        .reply(200, {
          issuer: "https://example.com",
          authorization_endpoint: "https://example.com/oauth/authorize",
          token_endpoint: "https://example.com/oauth/token",
          response_types_supported: ["code", "id_token"],
          claims_supported: ["sub", "iss", "acr"], // Missing auth_time
          acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        });

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).toContain("passed with recommendations");
      expect(result.message).toContain("auth_time");
    });

    it("should handle multiple insecure endpoints", async () => {
      const targetUrl = "https://example.com";
      const context = createContext(targetUrl);

      mockAxios
        .onGet("https://example.com/.well-known/openid-configuration")
        .reply(200, {
          issuer: "https://example.com",
          authorization_endpoint: "http://example.com/oauth/authorize", // HTTP
          token_endpoint: "http://example.com/oauth/token", // HTTP
          response_types_supported: ["code", "id_token"],
          claims_supported: ["sub", "iss"],
        });

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.FAIL);
      expect(result.message).toContain("http://example.com/oauth/authorize");
      expect(result.message).toContain("http://example.com/oauth/token");
      expect(result.metadata?.insecure_endpoints).toHaveLength(2);
    });
  });

  describe("Remediation Guidance", () => {
    it("should provide HTTPS remediation when endpoints are insecure", async () => {
      const targetUrl = "https://example.com";
      const context = createContext(targetUrl);

      mockAxios
        .onGet("https://example.com/.well-known/openid-configuration")
        .reply(200, {
          issuer: "https://example.com",
          authorization_endpoint: "http://example.com/oauth/authorize",
          token_endpoint: "https://example.com/oauth/token",
          response_types_supported: ["code", "id_token"],
        });

      const result = await check.execute(context);

      expect(result.remediation).toContain("Enable HTTPS");
      expect(result.remediation).toContain("TLS 1.2 or higher");
    });

    it("should provide OIDC implementation guidance when needed", async () => {
      const targetUrl = "https://example.com";
      const context = createContext(targetUrl);

      mockAxios
        .onGet("https://example.com/.well-known/oauth-authorization-server")
        .reply(200, {
          issuer: "https://example.com",
          authorization_endpoint: "https://example.com/oauth/authorize",
          token_endpoint: "https://example.com/oauth/token",
          response_types_supported: ["code"], // No OIDC
        });

      const result = await check.execute(context);

      expect(result.remediation).toContain("Implement OpenID Connect");
      expect(result.remediation).toContain("/.well-known/openid-configuration");
    });

    it("should provide ACR implementation guidance when needed", async () => {
      const targetUrl = "https://example.com";
      const context = createContext(targetUrl);

      mockAxios
        .onGet("https://example.com/.well-known/openid-configuration")
        .reply(200, {
          issuer: "https://example.com",
          authorization_endpoint: "https://example.com/oauth/authorize",
          token_endpoint: "https://example.com/oauth/token",
          response_types_supported: ["code", "id_token"],
          claims_supported: ["sub", "iss"],
          // No ACR values
        });

      const result = await check.execute(context);

      expect(result.remediation).toContain("Advertise AAL1 support");
      expect(result.remediation).toContain("acr_values_supported");
      expect(result.remediation).toContain("urn:nist:800-63-3:aal:1");
    });
  });

  describe("Check Metadata", () => {
    it("should have correct check properties", () => {
      expect(check.id).toBe("nist-aal1-compliance");
      expect(check.name).toBe("NIST AAL1 Compliance");
      expect(check.category).toBe("nist"); // CheckCategory.NIST value is lowercase
      expect(check.defaultSeverity).toBe(Severity.MEDIUM);
      expect(check.description).toContain("AAL1");
    });
  });
});
