/**
 * Tests for AALDetectionCheck
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { AALDetectionCheck } from "../../../../src/checks/nist/aal-detection.js";
import {
  CheckStatus,
  CheckContext,
} from "../../../../src/types/index.js";
import MockAdapter from "axios-mock-adapter";
import axios from "axios";
import { HttpClient } from "../../../../src/auditor/http-client.js";

describe("AALDetectionCheck", () => {
  let check: AALDetectionCheck;
  let mockAxios: MockAdapter;
  let httpClient: HttpClient;
  let context: CheckContext;

  beforeEach(() => {
    check = new AALDetectionCheck();
    mockAxios = new MockAdapter(axios);

    const logger = {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    };

    httpClient = new HttpClient({ verbose: false, timeout: 5000 }, logger);

    context = {
      targetUrl: "https://auth.example.com",
      httpClient,
      logger,
    };
  });

  describe("Metadata Discovery Failures", () => {
    it("should return warning when metadata discovery fails", async () => {
      // Mock failed discovery
      mockAxios
        .onGet("https://auth.example.com/.well-known/openid-configuration")
        .reply(404);
      mockAxios
        .onGet("https://auth.example.com/.well-known/oauth-authorization-server")
        .reply(404);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).toContain("Unable to discover OAuth metadata");
      expect(result.remediation).toContain("RFC 8414");
      expect(result.remediation).toContain("OpenID Connect Discovery");
    });
  });

  describe("OAuth-only Providers (Not OIDC)", () => {
    it("should skip check for OAuth-only providers", async () => {
      const metadata = {
        issuer: "https://auth.example.com",
        authorization_endpoint: "https://auth.example.com/authorize",
        token_endpoint: "https://auth.example.com/token",
        response_types_supported: ["code", "token"],
      };

      mockAxios
        .onGet("https://auth.example.com/.well-known/openid-configuration")
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.SKIPPED);
      expect(result.message).toContain("not an OpenID Connect provider");
      expect(result.message).toContain("NIST AAL compliance requires OIDC");
    });
  });

  describe("OIDC Providers Without ACR Support", () => {
    it("should warn when ACR/AMR claims are not supported", async () => {
      const metadata = {
        issuer: "https://auth.example.com",
        authorization_endpoint: "https://auth.example.com/authorize",
        token_endpoint: "https://auth.example.com/token",
        response_types_supported: ["code", "id_token"],
        claims_supported: ["sub", "iss", "aud", "exp", "iat"],
      };

      mockAxios
        .onGet("https://auth.example.com/.well-known/openid-configuration")
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).toContain("Unable to determine AAL support");
      expect(result.message).toContain("does not advertise ACR or AMR claim support");
      expect(result.remediation).toContain("acr_values_supported");
      expect(result.metadata?.acr_claim_supported).toBe(false);
      expect(result.metadata?.amr_claim_supported).toBe(false);
    });

    it("should warn when ACR claim is supported but no acr_values_supported", async () => {
      const metadata = {
        issuer: "https://auth.example.com",
        authorization_endpoint: "https://auth.example.com/authorize",
        token_endpoint: "https://auth.example.com/token",
        response_types_supported: ["code", "id_token"],
        claims_supported: ["sub", "iss", "aud", "exp", "iat", "acr"],
      };

      mockAxios
        .onGet("https://auth.example.com/.well-known/openid-configuration")
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).toContain("Unable to determine AAL support");
      expect(result.message).toContain("supports ACR claims");
      expect(result.message).toContain("does not advertise specific ACR values");
      expect(result.message).toContain("manual verification");
      expect(result.metadata?.acr_claim_supported).toBe(true);
      expect(result.metadata?.amr_claim_supported).toBe(false);
    });

    it("should warn when AMR claim is supported but no acr_values_supported", async () => {
      const metadata = {
        issuer: "https://auth.example.com",
        authorization_endpoint: "https://auth.example.com/authorize",
        token_endpoint: "https://auth.example.com/token",
        response_types_supported: ["code", "id_token"],
        claims_supported: ["sub", "iss", "aud", "exp", "iat", "amr"],
      };

      mockAxios
        .onGet("https://auth.example.com/.well-known/openid-configuration")
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).toContain("supports AMR claims");
      expect(result.metadata?.acr_claim_supported).toBe(false);
      expect(result.metadata?.amr_claim_supported).toBe(true);
    });

    it("should warn when both ACR and AMR claims are supported but no acr_values_supported", async () => {
      const metadata = {
        issuer: "https://auth.example.com",
        authorization_endpoint: "https://auth.example.com/authorize",
        token_endpoint: "https://auth.example.com/token",
        response_types_supported: ["code", "id_token"],
        claims_supported: ["sub", "iss", "aud", "exp", "iat", "acr", "amr"],
      };

      mockAxios
        .onGet("https://auth.example.com/.well-known/openid-configuration")
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).toContain("supports ACR and AMR claims");
      expect(result.metadata?.acr_claim_supported).toBe(true);
      expect(result.metadata?.amr_claim_supported).toBe(true);
    });
  });

  describe("OIDC Providers With Standard NIST ACR Values", () => {
    it("should detect all three AAL levels with high confidence", async () => {
      const metadata = {
        issuer: "https://auth.example.com",
        authorization_endpoint: "https://auth.example.com/authorize",
        token_endpoint: "https://auth.example.com/token",
        response_types_supported: ["code", "id_token", "code id_token"],
        acr_values_supported: [
          "urn:nist:800-63-3:aal:1",
          "urn:nist:800-63-3:aal:2",
          "urn:nist:800-63-3:aal:3",
        ],
        claims_supported: ["sub", "iss", "aud", "exp", "iat", "acr", "amr"],
      };

      mockAxios
        .onGet("https://auth.example.com/.well-known/openid-configuration")
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.message).toContain("NIST AAL support detected");
      expect(result.message).toContain("high confidence");
      expect(result.message).toContain("AAL1");
      expect(result.message).toContain("AAL2");
      expect(result.message).toContain("AAL3");
      expect(result.message).toContain("Highest AAL: AAL3");
      expect(result.metadata?.highest_aal).toBe("AAL3");
      expect(result.metadata?.supported_aals).toEqual(["AAL1", "AAL2", "AAL3"]);
      expect(result.metadata?.confidence).toBe("high");
    });

    it("should detect AAL2 as highest level", async () => {
      const metadata = {
        issuer: "https://auth.example.com",
        authorization_endpoint: "https://auth.example.com/authorize",
        token_endpoint: "https://auth.example.com/token",
        response_types_supported: ["code", "id_token"],
        acr_values_supported: [
          "urn:nist:800-63-3:aal:1",
          "urn:nist:800-63-3:aal:2",
        ],
        claims_supported: ["sub", "iss", "aud", "exp", "iat", "acr"],
      };

      mockAxios
        .onGet("https://auth.example.com/.well-known/openid-configuration")
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.message).toContain("Highest AAL: AAL2");
      expect(result.metadata?.highest_aal).toBe("AAL2");
      expect(result.metadata?.supported_aals).toEqual(["AAL1", "AAL2"]);
    });

    it("should detect only AAL1 support", async () => {
      const metadata = {
        issuer: "https://auth.example.com",
        authorization_endpoint: "https://auth.example.com/authorize",
        token_endpoint: "https://auth.example.com/token",
        response_types_supported: ["code", "id_token"],
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        claims_supported: ["sub", "iss", "aud", "exp", "iat", "acr"],
      };

      mockAxios
        .onGet("https://auth.example.com/.well-known/openid-configuration")
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.message).toContain("Highest AAL: AAL1");
      expect(result.metadata?.highest_aal).toBe("AAL1");
      expect(result.metadata?.supported_aals).toEqual(["AAL1"]);
    });
  });

  describe("OIDC Providers With Okta-Style ACR Values", () => {
    it("should detect Okta AAL support", async () => {
      const metadata = {
        issuer: "https://auth.example.com",
        authorization_endpoint: "https://auth.example.com/oauth2/v1/authorize",
        token_endpoint: "https://auth.example.com/oauth2/v1/token",
        response_types_supported: ["code", "id_token", "code id_token"],
        acr_values_supported: [
          "urn:okta:loa:1fa:any",
          "urn:okta:loa:2fa:any",
          "phr",
          "phrh",
        ],
        claims_supported: ["sub", "iss", "aud", "exp", "iat", "acr", "amr"],
      };

      mockAxios
        .onGet("https://auth.example.com/.well-known/openid-configuration")
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.message).toContain("NIST AAL support detected");
      expect(result.message).toContain("Highest AAL: AAL3");
      expect(result.metadata?.highest_aal).toBe("AAL3");
      expect(result.metadata?.supported_aals).toContain("AAL1");
      expect(result.metadata?.supported_aals).toContain("AAL2");
      expect(result.metadata?.supported_aals).toContain("AAL3");
    });
  });

  describe("OIDC Providers With MFA Patterns", () => {
    it("should detect MFA support patterns", async () => {
      const metadata = {
        issuer: "https://auth.example.com",
        authorization_endpoint: "https://auth.example.com/authorize",
        token_endpoint: "https://auth.example.com/token",
        response_types_supported: ["code", "id_token"],
        acr_values_supported: ["basic", "mfa", "2fa"],
        claims_supported: ["sub", "iss", "aud", "exp", "iat", "acr"],
      };

      mockAxios
        .onGet("https://auth.example.com/.well-known/openid-configuration")
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.message).toContain("AAL1");
      expect(result.message).toContain("AAL2");
      expect(result.metadata?.supported_aals).toContain("AAL1");
      expect(result.metadata?.supported_aals).toContain("AAL2");
    });
  });

  describe("OIDC Providers With Custom/Unmapped ACR Values", () => {
    it("should pass with medium confidence when some values are unmapped", async () => {
      const metadata = {
        issuer: "https://auth.example.com",
        authorization_endpoint: "https://auth.example.com/authorize",
        token_endpoint: "https://auth.example.com/token",
        response_types_supported: ["code", "id_token"],
        acr_values_supported: [
          "urn:nist:800-63-3:aal:2",
          "custom:level:high",
          "internal:auth:v2",
        ],
        claims_supported: ["sub", "iss", "aud", "exp", "iat", "acr"],
      };

      mockAxios
        .onGet("https://auth.example.com/.well-known/openid-configuration")
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.message).toContain("medium confidence");
      expect(result.message).toContain("AAL2");
      expect(result.message).toContain("could not be mapped");
      expect(result.message).toContain("custom:level:high");
      expect(result.message).toContain("internal:auth:v2");
      expect(result.metadata?.highest_aal).toBe("AAL2");
      expect(result.metadata?.unmapped_acr_values).toEqual([
        "custom:level:high",
        "internal:auth:v2",
      ]);
      expect(result.metadata?.confidence).toBe("medium");
    });
  });

  describe("Check Metadata", () => {
    it("should have correct check properties", () => {
      expect(check.id).toBe("nist-aal-detection");
      expect(check.name).toBe("NIST AAL Support Detection");
      expect(check.category).toBe("nist");
      expect(check.description).toContain("NIST Authentication Assurance Levels");
    });

    it("should include NIST and OIDC references", () => {
      expect(check["references"]).toContain(
        "https://pages.nist.gov/800-63-3/sp800-63b.html"
      );
      expect(check["references"]).toContain(
        "https://openid.net/specs/openid-connect-core-1_0.html#IDToken"
      );
    });
  });
});
