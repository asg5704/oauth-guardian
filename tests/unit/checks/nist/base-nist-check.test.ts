/**
 * Tests for BaseNISTCheck class
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  BaseNISTCheck,
  AALLevel,
  OAuthMetadata,
} from "../../../../src/checks/nist/base-nist-check.js";
import {
  CheckCategory,
  Severity,
  CheckContext,
  CheckResult,
} from "../../../../src/types/index.js";
import MockAdapter from "axios-mock-adapter";
import axios from "axios";
import { HttpClient } from "../../../../src/auditor/http-client.js";

// Concrete implementation of BaseNISTCheck for testing
class TestNISTCheck extends BaseNISTCheck {
  readonly id = "test-nist-check";
  readonly name = "Test NIST Check";
  readonly category = CheckCategory.NIST;
  readonly defaultSeverity = Severity.MEDIUM;
  readonly description = "Test NIST check for unit testing";

  async execute(context: CheckContext): Promise<CheckResult> {
    return this.pass("Test execution");
  }

  // Expose protected methods for testing
  public testAnalyzeACRValues(metadata: OAuthMetadata) {
    return this.analyzeACRValues(metadata);
  }

  public testAnalyzeAMRValues(metadata: OAuthMetadata) {
    return this.analyzeAMRValues(metadata);
  }

  public testDetectAALSupport(metadata: OAuthMetadata) {
    return this.detectAALSupport(metadata);
  }

  public testIsOIDCProvider(metadata: OAuthMetadata) {
    return this.isOIDCProvider(metadata);
  }

  public testIsHTTPSEnforced(metadata: OAuthMetadata) {
    return this.isHTTPSEnforced(metadata);
  }

  public testGetAALSessionTimeoutRequirement(aal: AALLevel) {
    return this.getAALSessionTimeoutRequirement(aal);
  }

  public testGetAALIdleTimeoutRequirement(aal: AALLevel) {
    return this.getAALIdleTimeoutRequirement(aal);
  }

  public testFormatAAL(aal: AALLevel) {
    return this.formatAAL(aal);
  }

  public testCreateMetadataWarning(error: string) {
    return this.createMetadataWarning(error);
  }

  public testGetACRRemediationGuidance(targetAAL: AALLevel) {
    return this.getACRRemediationGuidance(targetAAL);
  }
}

describe("BaseNISTCheck", () => {
  let check: TestNISTCheck;
  let mockAxios: MockAdapter;
  let httpClient: HttpClient;
  let context: CheckContext;

  beforeEach(() => {
    check = new TestNISTCheck();
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

  describe("analyzeACRValues", () => {
    it("should detect AAL3 from standard NIST URN format", () => {
      const metadata: OAuthMetadata = {
        acr_values_supported: [
          "urn:nist:800-63-3:aal:1",
          "urn:nist:800-63-3:aal:2",
          "urn:nist:800-63-3:aal:3",
        ],
      };

      const result = check.testAnalyzeACRValues(metadata);

      expect(result.hasACRSupport).toBe(true);
      expect(result.detectedAALs).toEqual([AALLevel.AAL1, AALLevel.AAL2, AALLevel.AAL3]);
      expect(result.confidence).toBe("high");
      expect(result.unmappedValues).toEqual([]);
    });

    it("should detect AAL2 from Okta-style ACR values", () => {
      const metadata: OAuthMetadata = {
        acr_values_supported: [
          "urn:okta:loa:1fa:any",
          "urn:okta:loa:2fa:any",
          "phr",
        ],
      };

      const result = check.testAnalyzeACRValues(metadata);

      expect(result.hasACRSupport).toBe(true);
      expect(result.detectedAALs).toContain(AALLevel.AAL1);
      expect(result.detectedAALs).toContain(AALLevel.AAL2);
      expect(result.confidence).toBe("high");
    });

    it("should detect AAL3 from Okta phrh value", () => {
      const metadata: OAuthMetadata = {
        acr_values_supported: ["phrh"],
      };

      const result = check.testAnalyzeACRValues(metadata);

      expect(result.hasACRSupport).toBe(true);
      expect(result.detectedAALs).toEqual([AALLevel.AAL3]);
      expect(result.confidence).toBe("high");
    });

    it("should detect multi-factor patterns", () => {
      const metadata: OAuthMetadata = {
        acr_values_supported: ["mfa", "multi-factor", "2fa"],
      };

      const result = check.testAnalyzeACRValues(metadata);

      expect(result.hasACRSupport).toBe(true);
      expect(result.detectedAALs).toEqual([AALLevel.AAL2]);
      expect(result.confidence).toBe("high");
    });

    it("should detect basic/low assurance patterns", () => {
      const metadata: OAuthMetadata = {
        acr_values_supported: ["basic", "low", "single-factor"],
      };

      const result = check.testAnalyzeACRValues(metadata);

      expect(result.hasACRSupport).toBe(true);
      expect(result.detectedAALs).toEqual([AALLevel.AAL1]);
      expect(result.confidence).toBe("high");
    });

    it("should handle unmapped ACR values", () => {
      const metadata: OAuthMetadata = {
        acr_values_supported: [
          "urn:nist:800-63-3:aal:2",
          "custom:unknown:value",
          "another-custom-value",
        ],
      };

      const result = check.testAnalyzeACRValues(metadata);

      expect(result.hasACRSupport).toBe(true);
      expect(result.detectedAALs).toContain(AALLevel.AAL2);
      expect(result.unmappedValues).toEqual([
        "custom:unknown:value",
        "another-custom-value",
      ]);
      expect(result.confidence).toBe("medium");
    });

    it("should return no support when acr_values_supported is missing", () => {
      const metadata: OAuthMetadata = {
        issuer: "https://auth.example.com",
      };

      const result = check.testAnalyzeACRValues(metadata);

      expect(result.hasACRSupport).toBe(false);
      expect(result.detectedAALs).toEqual([]);
      expect(result.confidence).toBe("low");
    });

    it("should return no support when acr_values_supported is empty", () => {
      const metadata: OAuthMetadata = {
        acr_values_supported: [],
      };

      const result = check.testAnalyzeACRValues(metadata);

      expect(result.hasACRSupport).toBe(false);
      expect(result.detectedAALs).toEqual([]);
      expect(result.confidence).toBe("low");
    });
  });

  describe("analyzeAMRValues", () => {
    it("should detect AMR support when claims_supported includes amr", () => {
      const metadata: OAuthMetadata = {
        claims_supported: ["sub", "iss", "aud", "amr", "acr"],
      };

      const result = check.testAnalyzeAMRValues(metadata);

      expect(result.amrValues).toEqual(["amr"]);
    });

    it("should return no support when claims_supported is missing", () => {
      const metadata: OAuthMetadata = {
        issuer: "https://auth.example.com",
      };

      const result = check.testAnalyzeAMRValues(metadata);

      expect(result.amrValues).toEqual([]);
      expect(result.supportsMFA).toBe(false);
      expect(result.supportsHardwareAuth).toBe(false);
    });

    it("should return no support when amr is not in claims_supported", () => {
      const metadata: OAuthMetadata = {
        claims_supported: ["sub", "iss", "aud", "acr"],
      };

      const result = check.testAnalyzeAMRValues(metadata);

      expect(result.amrValues).toEqual([]);
      expect(result.supportsMFA).toBe(false);
    });
  });

  describe("detectAALSupport", () => {
    it("should detect AAL3 as highest level", () => {
      const metadata: OAuthMetadata = {
        acr_values_supported: [
          "urn:nist:800-63-3:aal:1",
          "urn:nist:800-63-3:aal:2",
          "urn:nist:800-63-3:aal:3",
        ],
      };

      const result = check.testDetectAALSupport(metadata);

      expect(result.highestAAL).toBe(AALLevel.AAL3);
      expect(result.supportedAALs).toContain(AALLevel.AAL1);
      expect(result.supportedAALs).toContain(AALLevel.AAL2);
      expect(result.supportedAALs).toContain(AALLevel.AAL3);
      expect(result.canDetermine).toBe(true);
    });

    it("should detect AAL2 as highest level", () => {
      const metadata: OAuthMetadata = {
        acr_values_supported: ["urn:okta:loa:1fa:any", "urn:okta:loa:2fa:any"],
      };

      const result = check.testDetectAALSupport(metadata);

      expect(result.highestAAL).toBe(AALLevel.AAL2);
      expect(result.supportedAALs).toContain(AALLevel.AAL1);
      expect(result.supportedAALs).toContain(AALLevel.AAL2);
      expect(result.canDetermine).toBe(true);
    });

    it("should detect AAL1 only", () => {
      const metadata: OAuthMetadata = {
        acr_values_supported: ["basic", "low"],
      };

      const result = check.testDetectAALSupport(metadata);

      expect(result.highestAAL).toBe(AALLevel.AAL1);
      expect(result.supportedAALs).toEqual([AALLevel.AAL1]);
      expect(result.canDetermine).toBe(true);
    });

    it("should return undefined when AAL cannot be determined", () => {
      const metadata: OAuthMetadata = {
        issuer: "https://auth.example.com",
      };

      const result = check.testDetectAALSupport(metadata);

      expect(result.highestAAL).toBeUndefined();
      expect(result.supportedAALs).toEqual([]);
      expect(result.canDetermine).toBe(false);
    });
  });

  describe("isOIDCProvider", () => {
    it("should detect OIDC provider by id_token response type", () => {
      const metadata: OAuthMetadata = {
        response_types_supported: ["code", "id_token", "code id_token"],
      };

      const result = check.testIsOIDCProvider(metadata);

      expect(result).toBe(true);
    });

    it("should detect OIDC provider by compound response type", () => {
      const metadata: OAuthMetadata = {
        response_types_supported: ["code", "code id_token token"],
      };

      const result = check.testIsOIDCProvider(metadata);

      expect(result).toBe(true);
    });

    it("should return false for OAuth-only providers", () => {
      const metadata: OAuthMetadata = {
        response_types_supported: ["code", "token"],
      };

      const result = check.testIsOIDCProvider(metadata);

      expect(result).toBe(false);
    });

    it("should return false when response_types_supported is missing", () => {
      const metadata: OAuthMetadata = {
        issuer: "https://auth.example.com",
      };

      const result = check.testIsOIDCProvider(metadata);

      expect(result).toBe(false);
    });
  });

  describe("isHTTPSEnforced", () => {
    it("should pass when all endpoints use HTTPS", () => {
      const metadata: OAuthMetadata = {
        authorization_endpoint: "https://auth.example.com/authorize",
        token_endpoint: "https://auth.example.com/token",
      };

      const result = check.testIsHTTPSEnforced(metadata);

      expect(result.enforced).toBe(true);
      expect(result.insecureEndpoints).toEqual([]);
    });

    it("should fail when authorization endpoint uses HTTP", () => {
      const metadata: OAuthMetadata = {
        authorization_endpoint: "http://auth.example.com/authorize",
        token_endpoint: "https://auth.example.com/token",
      };

      const result = check.testIsHTTPSEnforced(metadata);

      expect(result.enforced).toBe(false);
      expect(result.insecureEndpoints).toContain(
        "http://auth.example.com/authorize"
      );
    });

    it("should fail when token endpoint uses HTTP", () => {
      const metadata: OAuthMetadata = {
        authorization_endpoint: "https://auth.example.com/authorize",
        token_endpoint: "http://auth.example.com/token",
      };

      const result = check.testIsHTTPSEnforced(metadata);

      expect(result.enforced).toBe(false);
      expect(result.insecureEndpoints).toContain("http://auth.example.com/token");
    });

    it("should handle missing endpoints", () => {
      const metadata: OAuthMetadata = {
        issuer: "https://auth.example.com",
      };

      const result = check.testIsHTTPSEnforced(metadata);

      expect(result.enforced).toBe(true);
      expect(result.insecureEndpoints).toEqual([]);
    });
  });

  describe("getAALSessionTimeoutRequirement", () => {
    it("should return 720 hours (30 days) for AAL1", () => {
      const timeout = check.testGetAALSessionTimeoutRequirement(AALLevel.AAL1);
      expect(timeout).toBe(720);
    });

    it("should return 12 hours for AAL2", () => {
      const timeout = check.testGetAALSessionTimeoutRequirement(AALLevel.AAL2);
      expect(timeout).toBe(12);
    });

    it("should return 12 hours for AAL3", () => {
      const timeout = check.testGetAALSessionTimeoutRequirement(AALLevel.AAL3);
      expect(timeout).toBe(12);
    });
  });

  describe("getAALIdleTimeoutRequirement", () => {
    it("should return undefined for AAL1 (no requirement)", () => {
      const timeout = check.testGetAALIdleTimeoutRequirement(AALLevel.AAL1);
      expect(timeout).toBeUndefined();
    });

    it("should return 60 minutes for AAL2", () => {
      const timeout = check.testGetAALIdleTimeoutRequirement(AALLevel.AAL2);
      expect(timeout).toBe(60);
    });

    it("should return 15 minutes for AAL3", () => {
      const timeout = check.testGetAALIdleTimeoutRequirement(AALLevel.AAL3);
      expect(timeout).toBe(15);
    });
  });

  describe("formatAAL", () => {
    it("should format AAL1 correctly", () => {
      const formatted = check.testFormatAAL(AALLevel.AAL1);
      expect(formatted).toContain("AAL1");
      expect(formatted).toContain("Basic Assurance");
    });

    it("should format AAL2 correctly", () => {
      const formatted = check.testFormatAAL(AALLevel.AAL2);
      expect(formatted).toContain("AAL2");
      expect(formatted).toContain("High Assurance");
    });

    it("should format AAL3 correctly", () => {
      const formatted = check.testFormatAAL(AALLevel.AAL3);
      expect(formatted).toContain("AAL3");
      expect(formatted).toContain("Very High Assurance");
    });
  });

  describe("createMetadataWarning", () => {
    it("should create a warning result with proper message", () => {
      const error = "OAuth metadata discovery failed";
      const result = check.testCreateMetadataWarning(error);

      expect(result.status).toBe("warning");
      expect(result.message).toContain(error);
      expect(result.message).toContain("Cannot automatically verify NIST AAL compliance");
      expect(result.remediation).toContain("RFC 8414");
      expect(result.remediation).toContain("OpenID Connect Discovery");
    });
  });

  describe("getACRRemediationGuidance", () => {
    it("should provide AAL1-specific guidance", () => {
      const guidance = check.testGetACRRemediationGuidance(AALLevel.AAL1);

      expect(guidance).toContain("AAL1");
      expect(guidance).toContain("Single-factor");
      expect(guidance).toContain("acr_values_supported");
      expect(guidance).toContain("NIST SP 800-63B");
    });

    it("should provide AAL2-specific guidance", () => {
      const guidance = check.testGetACRRemediationGuidance(AALLevel.AAL2);

      expect(guidance).toContain("AAL2");
      expect(guidance).toContain("Multi-factor");
      expect(guidance).toContain("cryptographic");
      expect(guidance).toContain("acr_values_supported");
    });

    it("should provide AAL3-specific guidance", () => {
      const guidance = check.testGetACRRemediationGuidance(AALLevel.AAL3);

      expect(guidance).toContain("AAL3");
      expect(guidance).toContain("Hardware-based");
      expect(guidance).toContain("phishing-resistant");
      expect(guidance).toContain("acr_values_supported");
    });
  });
});
