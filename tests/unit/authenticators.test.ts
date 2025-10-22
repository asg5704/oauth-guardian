/**
 * Unit tests for NIST Authenticator Lifecycle Management Check
 */

import { describe, it, expect, beforeEach } from "vitest";
import MockAdapter from "axios-mock-adapter";
import axios from "axios";
import { AuthenticatorLifecycleCheck } from "../../src/checks/nist/authenticators.js";
import { HttpClient } from "../../src/auditor/http-client.js";
import { CheckContext, CheckStatus } from "../../src/types/index.js";
import { defaultConfig } from "../../src/config/defaults.js";

describe("AuthenticatorLifecycleCheck", () => {
  let check: AuthenticatorLifecycleCheck;
  let httpClient: HttpClient;
  let context: CheckContext;
  let mockAxios: MockAdapter;

  beforeEach(() => {
    check = new AuthenticatorLifecycleCheck();
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

  describe("authenticator revocation", () => {
    it("should FAIL when no revocation mechanisms are detected", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        claims_supported: ["sub", "iss"],
        // No revocation endpoint or session termination
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.FAIL);
      expect(result.message).toContain(
        "Authenticator lifecycle management check FAILED"
      );
      expect(result.message).toContain(
        "No authenticator revocation mechanisms detected"
      );
    });

    it("should detect token revocation endpoint", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        revocation_endpoint: "https://provider.example.com/revoke",
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        claims_supported: ["sub", "iss"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.WARNING); // Still has recommendations
      expect(result.metadata?.revocation).toMatchObject({
        supportsRevocation: true,
        revocationMechanisms: expect.arrayContaining([
          expect.stringContaining("Token revocation"),
        ]),
      });
    });

    it("should detect session termination as revocation mechanism", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
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

      expect(result.metadata?.revocation?.supportsRevocation).toBe(true);
    });

    it("should detect back-channel logout", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        backchannel_logout_supported: true,
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        claims_supported: ["sub", "iss"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.revocation?.revocationMechanisms).toContain(
        "Back-channel logout"
      );
    });
  });

  describe("authenticator registration", () => {
    it("should detect WebAuthn/FIDO2 registration support", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        acr_values_supported: ["webauthn", "urn:nist:800-63-3:aal:3"],
        revocation_endpoint: "https://provider.example.com/revoke",
        claims_supported: ["sub", "iss"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.registration?.supportsRegistration).toBe(true);
      expect(
        result.metadata?.registration?.registrationMechanisms
      ).toContain("WebAuthn/FIDO2 registration");
    });

    it("should detect device authorization flow", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        device_authorization_endpoint:
          "https://provider.example.com/device_authorization",
        response_types_supported: ["code", "id_token"],
        revocation_endpoint: "https://provider.example.com/revoke",
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        claims_supported: ["sub", "iss"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(
        result.metadata?.registration?.registrationMechanisms
      ).toContain("Device authorization");
    });

    it("should detect dynamic client registration", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        registration_endpoint: "https://provider.example.com/register",
        response_types_supported: ["code", "id_token"],
        revocation_endpoint: "https://provider.example.com/revoke",
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        claims_supported: ["sub", "iss"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(
        result.metadata?.registration?.registrationMechanisms
      ).toContain("Dynamic client registration");
    });
  });

  describe("authenticator binding", () => {
    it("should detect mTLS binding", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        tls_client_certificate_bound_access_tokens: true,
        mtls_endpoint_aliases: {
          token_endpoint: "https://mtls.provider.example.com/token",
        },
        revocation_endpoint: "https://provider.example.com/revoke",
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        claims_supported: ["sub", "iss"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.binding?.hasBindingEvidence).toBe(true);
      expect(result.metadata?.binding?.bindingMethods).toContain(
        "Certificate binding (mTLS)"
      );
    });

    it("should detect DPoP binding", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        dpop_signing_alg_values_supported: ["ES256", "RS256"],
        revocation_endpoint: "https://provider.example.com/revoke",
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        claims_supported: ["sub", "iss"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.binding?.bindingMethods).toContain(
        "DPoP (key binding)"
      );
    });

    it("should detect confirmation claim (cnf)", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        revocation_endpoint: "https://provider.example.com/revoke",
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        claims_supported: ["sub", "iss", "cnf"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.binding?.bindingMethods).toContain(
        "Confirmation claim (cnf)"
      );
    });
  });

  describe("authenticator expiration", () => {
    it("should detect auth_time claim for periodic reauthentication", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        revocation_endpoint: "https://provider.example.com/revoke",
        acr_values_supported: ["urn:nist:800-63-3:aal:2"],
        claims_supported: ["sub", "iss", "auth_time"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.expiration?.expirationIndicators).toContain(
        "Periodic reauthentication via auth_time"
      );
    });

    it("should detect mTLS certificate expiration", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        revocation_endpoint: "https://provider.example.com/revoke",
        mtls_endpoint_aliases: {
          token_endpoint: "https://mtls.provider.example.com/token",
        },
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        claims_supported: ["sub", "iss"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.expiration?.expirationIndicators).toContain(
        "Certificate expiration (mTLS)"
      );
    });
  });

  describe("multiple authenticators", () => {
    it("should detect AMR claim support", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        revocation_endpoint: "https://provider.example.com/revoke",
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        claims_supported: ["sub", "iss", "amr"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.multiple_authenticators?.supportsMultiple).toBe(
        true
      );
      expect(result.metadata?.multiple_authenticators?.evidence).toContain(
        "AMR claim (multiple methods supported)"
      );
    });

    it("should detect multiple ACR values", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        revocation_endpoint: "https://provider.example.com/revoke",
        acr_values_supported: [
          "urn:nist:800-63-3:aal:1",
          "urn:nist:800-63-3:aal:2",
          "urn:nist:800-63-3:aal:3",
        ],
        claims_supported: ["sub", "iss"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.multiple_authenticators?.evidence).toContain(
        "Multiple ACR values (3 levels)"
      );
    });

    it("should detect WebAuthn multi-credential support", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        revocation_endpoint: "https://provider.example.com/revoke",
        acr_values_supported: ["webauthn", "fido2"],
        claims_supported: ["sub", "iss"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.multiple_authenticators?.evidence).toContain(
        "WebAuthn/FIDO2 (multi-credential support)"
      );
    });

    it("should detect step-up authentication support", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        revocation_endpoint: "https://provider.example.com/revoke",
        prompt_values_supported: ["none", "login", "consent"],
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        claims_supported: ["sub", "iss"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.multiple_authenticators?.evidence).toContain(
        "Step-up authentication (prompt=login)"
      );
    });
  });

  describe("authenticator status verification", () => {
    it("should detect introspection endpoint", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        revocation_endpoint: "https://provider.example.com/revoke",
        introspection_endpoint: "https://provider.example.com/introspect",
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        claims_supported: ["sub", "iss"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.status_verification?.hasStatusVerification).toBe(
        true
      );
      expect(result.metadata?.status_verification?.mechanisms).toContain(
        "Token introspection: https://provider.example.com/introspect"
      );
    });

    it("should detect userinfo endpoint", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        revocation_endpoint: "https://provider.example.com/revoke",
        userinfo_endpoint: "https://provider.example.com/userinfo",
        acr_values_supported: ["urn:nist:800-63-3:aal:1"],
        claims_supported: ["sub", "iss"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.status_verification?.mechanisms).toContain(
        "UserInfo endpoint: https://provider.example.com/userinfo"
      );
    });
  });

  describe("comprehensive compliance", () => {
    it("should PASS with comprehensive authenticator lifecycle support", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        acr_values_supported: [
          "webauthn",
          "urn:nist:800-63-3:aal:1",
          "urn:nist:800-63-3:aal:2",
          "urn:nist:800-63-3:aal:3",
        ],
        claims_supported: ["sub", "iss", "auth_time", "amr", "cnf"],
        prompt_values_supported: ["none", "login", "consent"],
        revocation_endpoint: "https://provider.example.com/revoke",
        end_session_endpoint: "https://provider.example.com/logout",
        introspection_endpoint: "https://provider.example.com/introspect",
        userinfo_endpoint: "https://provider.example.com/userinfo",
        dpop_signing_alg_values_supported: ["ES256"],
        tls_client_certificate_bound_access_tokens: true,
        device_authorization_endpoint:
          "https://provider.example.com/device_authorization",
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.message).toContain(
        "Authenticator lifecycle management controls meet NIST requirements"
      );
    });
  });

  describe("check metadata and remediation", () => {
    it("should include detailed metadata", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        revocation_endpoint: "https://provider.example.com/revoke",
        acr_values_supported: ["webauthn"],
        claims_supported: ["sub", "iss"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.metadata?.target_aal).toBeDefined();
      expect(result.metadata?.registration).toBeDefined();
      expect(result.metadata?.binding).toBeDefined();
      expect(result.metadata?.expiration).toBeDefined();
      expect(result.metadata?.revocation).toBeDefined();
      expect(result.metadata?.multiple_authenticators).toBeDefined();
      expect(result.metadata?.status_verification).toBeDefined();
    });

    it("should provide comprehensive remediation guidance", async () => {
      const metadata = {
        issuer: "https://provider.example.com",
        authorization_endpoint: "https://provider.example.com/authorize",
        token_endpoint: "https://provider.example.com/token",
        response_types_supported: ["code", "id_token"],
        acr_values_supported: ["urn:nist:800-63-3:aal:2"],
        claims_supported: ["sub", "iss"],
      };

      mockAxios
        .onGet(
          "https://provider.example.com/.well-known/openid-configuration"
        )
        .reply(200, metadata);

      const result = await check.execute(context);

      expect(result.remediation).toBeDefined();
      expect(result.remediation).toContain("Authenticator Registration");
      expect(result.remediation).toContain("Authenticator Binding");
      expect(result.remediation).toContain("Authenticator Expiration");
      expect(result.remediation).toContain("Authenticator Revocation");
      expect(result.remediation).toContain("Multiple Authenticator Support");
      expect(result.remediation).toContain("Status Verification");
    });
  });
});
