/**
 * Unit tests for NIST Session Management Check
 */

import { describe, it, expect, beforeEach } from "vitest";
import MockAdapter from "axios-mock-adapter";
import axios from "axios";
import { SessionManagementCheck } from "../../src/checks/nist/session-mgmt.js";
import { HttpClient } from "../../src/auditor/http-client.js";
import { CheckContext, CheckStatus } from "../../src/types/index.js";
import { defaultConfig } from "../../src/config/defaults.js";

describe("SessionManagementCheck", () => {
  let check: SessionManagementCheck;
  let httpClient: HttpClient;
  let context: CheckContext;
  let mockAxios: MockAdapter;

  beforeEach(() => {
    check = new SessionManagementCheck();
    httpClient = new HttpClient({ verbose: false });
    context = {
      targetUrl: "https://provider.example.com",
      httpClient,
      logger: { log: () => {}, error: () => {}, debug: () => {} },
      config: defaultConfig,
    };
    mockAxios = new MockAdapter(axios);
  });

  describe("metadata discovery failures", () => {
    it("should return WARNING when metadata discovery fails", async () => {
      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/oauth-authorization-server"
        )
        .reply(404)
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(404);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).toContain("Unable to discover OAuth metadata");
    });
  });

  describe("session termination", () => {
    it("should FAIL when no session termination endpoint is available", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        claims_supported: ["sub", "iss"],
        // No end_session_endpoint, revocation_endpoint, or logout support
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.FAIL);
      expect(result.message).toContain("Session management check FAILED");
      expect(result.message).toContain(
        "No session termination endpoint detected"
      );
    });

    it("should PASS when end_session_endpoint is available", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        end_session_endpoint: "https://provider.example.com/logout",
        claims_supported: ["sub", "iss", "auth_time"],
        prompt_values_supported: ["none", "login"],
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.WARNING); // Still warnings for other checks
      expect(result.message).not.toContain(
        "No session termination endpoint detected"
      );
    });

    it("should PASS when revocation_endpoint is available", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        revocation_endpoint: "https://provider.example.com/revoke",
        claims_supported: ["sub", "iss", "auth_time"],
        prompt_values_supported: ["none", "login"],
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).not.toContain(
        "No session termination endpoint detected"
      );
    });

    it("should detect back-channel logout support", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        backchannel_logout_supported: true,
        claims_supported: ["sub", "iss", "auth_time"],
        prompt_values_supported: ["none", "login"],
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.metadata?.session_termination).toMatchObject({
        hasLogoutEndpoint: true,
        supportsBackChannelLogout: true,
      });
    });
  });

  describe("reauthentication support", () => {
    it("should detect prompt=login support", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        prompt_values_supported: ["none", "login", "consent"],
        end_session_endpoint: "https://provider.example.com/logout",
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        claims_supported: ["sub", "iss"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.reauthentication).toMatchObject({
        supportsPromptLogin: true,
      });
    });

    it("should detect auth_time claim support for max_age", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        claims_supported: ["sub", "iss", "auth_time"],
        end_session_endpoint: "https://provider.example.com/logout",
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.reauthentication).toMatchObject({
        supportsAuthTime: true,
        supportsMaxAge: true,
      });
    });

    it("should warn when no reauthentication mechanisms are detected", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        end_session_endpoint: "https://provider.example.com/logout",
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        claims_supported: ["sub", "iss"],
        // No prompt_values_supported or auth_time
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).toContain(
        "No reauthentication mechanisms detected"
      );
    });
  });

  describe("session binding", () => {
    it("should detect PKCE support", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        code_challenge_methods_supported: ["S256"],
        end_session_endpoint: "https://provider.example.com/logout",
        claims_supported: ["sub", "iss", "auth_time"],
        prompt_values_supported: ["none", "login"],
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.session_binding).toMatchObject({
        hasBindingSupport: true,
        bindingMethods: ["PKCE (authorization code binding)"],
      });
    });

    it("should detect DPoP support", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        dpop_signing_alg_values_supported: ["ES256", "RS256"],
        end_session_endpoint: "https://provider.example.com/logout",
        claims_supported: ["sub", "iss", "auth_time"],
        prompt_values_supported: ["none", "login"],
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.session_binding).toMatchObject({
        hasBindingSupport: true,
        bindingMethods: ["DPoP (token binding)"],
      });
    });

    it("should detect mTLS support", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        tls_client_certificate_bound_access_tokens: true,
        mtls_endpoint_aliases: {
          token_endpoint: "https://mtls.provider.example.com/token",
        },
        end_session_endpoint: "https://provider.example.com/logout",
        claims_supported: ["sub", "iss", "auth_time"],
        prompt_values_supported: ["none", "login"],
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.session_binding?.hasBindingSupport).toBe(true);
      expect(result.metadata?.session_binding?.bindingMethods).toContain(
        "mTLS (certificate-bound tokens)"
      );
    });
  });

  describe("AAL level detection", () => {
    it("should detect AAL1 as target level", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        end_session_endpoint: "https://provider.example.com/logout",
        claims_supported: ["sub", "iss", "auth_time"],
        prompt_values_supported: ["none", "login"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.target_aal).toBe("AAL1");
    });

    it("should detect AAL2 as target level when available", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        acr_values_supported: [
          "urn:nist:800-63-3:aal:1",
          "urn:nist:800-63-3:aal:2",
        ],
        end_session_endpoint: "https://provider.example.com/logout",
        claims_supported: ["sub", "iss", "auth_time"],
        prompt_values_supported: ["none", "login"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.target_aal).toBe("AAL2");
    });

    it("should detect AAL3 as target level when available", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        acr_values_supported: [
          "urn:nist:800-63-3:aal:1",
          "urn:nist:800-63-3:aal:2",
          "urn:nist:800-63-3:aal:3",
        ],
        end_session_endpoint: "https://provider.example.com/logout",
        claims_supported: ["sub", "iss", "auth_time", "amr"],
        prompt_values_supported: ["none", "login"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.target_aal).toBe("AAL3");
    });
  });

  describe("comprehensive compliance", () => {
    it("should PASS when all session management controls are present", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        acr_values_supported: ["urn:nist:800-63-3:aal:2"],
        claims_supported: ["sub", "iss", "auth_time", "acr", "amr"],
        prompt_values_supported: ["none", "login", "consent"],
        end_session_endpoint: "https://provider.example.com/logout",
        revocation_endpoint: "https://provider.example.com/revoke",
        backchannel_logout_supported: true,
        code_challenge_methods_supported: ["S256"],
        dpop_signing_alg_values_supported: ["ES256"],
        session_max_lifetime: 43200, // 12 hours for AAL2
        idle_timeout: 3600, // 1 hour
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.message).toContain(
        "Session management controls meet NIST requirements"
      );
    });
  });

  describe("check metadata and remediation", () => {
    it("should include session termination details in metadata", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        end_session_endpoint: "https://provider.example.com/logout",
        revocation_endpoint: "https://provider.example.com/revoke",
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        claims_supported: ["sub", "iss", "auth_time"],
        prompt_values_supported: ["none", "login"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.session_termination?.endpoints).toContain(
        "end_session_endpoint: https://provider.example.com/logout"
      );
      expect(result.metadata?.session_termination?.endpoints).toContain(
        "revocation_endpoint: https://provider.example.com/revoke"
      );
    });

    it("should provide remediation guidance", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        claims_supported: ["sub", "iss"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.remediation).toBeDefined();
      expect(result.remediation).toContain("Session Timeout Configuration");
      expect(result.remediation).toContain("Session Binding");
      expect(result.remediation).toContain("Reauthentication");
      expect(result.remediation).toContain("Session Termination");
    });
  });
});
