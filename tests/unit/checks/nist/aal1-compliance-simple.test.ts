/**
 * Simplified AAL1 Compliance Tests
 * Testing core functionality with realistic scenarios
 */

import { describe, it, expect, beforeEach } from "vitest";
import MockAdapter from "axios-mock-adapter";
import axios from "axios";
import { AAL1ComplianceCheck } from "../../../../src/checks/nist/aal1-compliance.js";
import { HttpClient } from "../../../../src/auditor/http-client.js";
import { CheckStatus, CheckContext, Severity } from "../../../../src/types/index.js";

describe("AAL1ComplianceCheck - Simplified", () => {
  let check: AAL1ComplianceCheck;
  let httpClient: HttpClient;
  let mockAxios: MockAdapter;

  beforeEach(() => {
    check = new AAL1ComplianceCheck();
    httpClient = new HttpClient({ timeout: 5000 });
    if (mockAxios) {
      mockAxios.reset();  // Reset existing mock
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

  // Full compliance - ideal scenario
  const fullComplianceMetadata = {
    issuer: "https://example.com",
    authorization_endpoint: "https://example.com/oauth/authorize",
    token_endpoint: "https://example.com/oauth/token",
    response_types_supported: ["code", "id_token", "token"],
    claims_supported: ["sub", "iss", "aud", "exp", "acr", "amr", "auth_time"],
    acr_values_supported: ["urn:nist:800-63-3:aal:1", "urn:nist:800-63-3:aal:2"],
  };

  // OAuth-only (no OIDC)
  const oauthOnlyMetadata = {
    issuer: "https://example.com",
    authorization_endpoint: "https://example.com/oauth/authorize",
    token_endpoint: "https://example.com/oauth/token",
    response_types_supported: ["code"],  // No id_token
  };

  // HTTP endpoints (critical failure)
  const httpEndpointsMetadata = {
    issuer: "https://example.com",
    authorization_endpoint: "http://example.com/oauth/authorize",  // HTTP!
    token_endpoint: "https://example.com/oauth/token",
    response_types_supported: ["code", "id_token"],
    claims_supported: ["sub", "acr", "auth_time"],
    acr_values_supported: ["urn:nist:800-63-3:aal:1"],
  };

  it("should validate complete AAL1 metadata correctly", async () => {
    const context = createContext("https://example.com");

    // Minimal metadata that meets all AAL1 requirements
    const minimalAAL1Metadata = {
      issuer: "https://example.com",
      authorization_endpoint: "https://example.com/oauth/authorize",
      token_endpoint: "https://example.com/oauth/token",
      response_types_supported: ["code", "id_token"],  // OIDC provider
      claims_supported: ["sub", "iss", "acr", "auth_time"],  // Has auth_time
      acr_values_supported: ["urn:nist:800-63-3:aal:1"],  // AAL1 only
    };

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, minimalAAL1Metadata);

    const result = await check.execute(context);

    // Should not fail for complete metadata
    expect(result.status).not.toBe(CheckStatus.FAIL);
    expect(result.status).not.toBe(CheckStatus.ERROR);

    // Should have analyzed all the metadata correctly
    if (result.metadata) {
      expect(result.metadata.oidc_provider).toBe(true);
      expect(result.metadata.aal1_advertised).toBe(true);
      expect(result.metadata.auth_time_supported).toBe(true);
    }
  });

  it("should warn for OAuth-only provider", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(404);
    mockAxios
      .onGet("https://example.com/.well-known/oauth-authorization-server")
      .reply(200, oauthOnlyMetadata);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.WARNING);
    expect(result.message).toContain("OpenID Connect");
    expect(result.metadata?.oidc_provider).toBe(false);
  });

  it("should fail for HTTP endpoints", async () => {
    const context = createContext("https://example.com");

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, httpEndpointsMetadata);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.FAIL);
    expect(result.severity).toBe(Severity.MEDIUM);
    expect(result.message).toContain("HTTPS not enforced");
    expect(result.message).toContain("http://example.com/oauth/authorize");
    expect(result.metadata?.https_enforced).toBe(false);
  });

  it("should warn when missing AAL1 advertisement", async () => {
    const context = createContext("https://example.com");

    const noAalMetadata = {
      issuer: "https://example.com",
      authorization_endpoint: "https://example.com/oauth/authorize",
      token_endpoint: "https://example.com/oauth/token",
      response_types_supported: ["code", "id_token"],
      claims_supported: ["sub", "iss", "acr", "auth_time"],
      acr_values_supported: ["urn:nist:800-63-3:aal:2"],  // Only AAL2, no AAL1
    };

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, noAalMetadata);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.WARNING);
    expect(result.message).toContain("does not advertise AAL1");
    expect(result.metadata?.aal1_advertised).toBe(false);
  });

  it("should warn when missing auth_time", async () => {
    const context = createContext("https://example.com");

    const noAuthTimeMetadata = {
      issuer: "https://example.com",
      authorization_endpoint: "https://example.com/oauth/authorize",
      token_endpoint: "https://example.com/oauth/token",
      response_types_supported: ["code", "id_token"],
      claims_supported: ["sub", "iss", "acr"],  // No auth_time
      acr_values_supported: ["urn:nist:800-63-3:aal:1"],
    };

    mockAxios
      .onGet("https://example.com/.well-known/openid-configuration")
      .reply(200, noAuthTimeMetadata);

    const result = await check.execute(context);

    expect(result.status).toBe(CheckStatus.WARNING);
    expect(result.message).toContain("auth_time");
    expect(result.metadata?.auth_time_supported).toBe(false);
  });

  it("should have correct check metadata", () => {
    expect(check.id).toBe("nist-aal1-compliance");
    expect(check.name).toBe("NIST AAL1 Compliance");
    expect(check.category).toBe("nist");
    expect(check.defaultSeverity).toBe(Severity.MEDIUM);
  });
});
