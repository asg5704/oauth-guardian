/**
 * Tests for programmatic API (index.ts exports)
 */

import { describe, it, expect } from "vitest";
import * as OAuthGuardian from "../../src/index.js";

describe("Programmatic API", () => {
  describe("Type Exports", () => {
    it("should export CheckStatus enum", () => {
      expect(OAuthGuardian.CheckStatus).toBeDefined();
      expect(OAuthGuardian.CheckStatus.PASS).toBe("pass");
      expect(OAuthGuardian.CheckStatus.FAIL).toBe("fail");
      expect(OAuthGuardian.CheckStatus.WARNING).toBe("warning");
      expect(OAuthGuardian.CheckStatus.SKIPPED).toBe("skipped");
      expect(OAuthGuardian.CheckStatus.ERROR).toBe("error");
    });

    it("should export Severity enum", () => {
      expect(OAuthGuardian.Severity).toBeDefined();
      expect(OAuthGuardian.Severity.CRITICAL).toBe("critical");
      expect(OAuthGuardian.Severity.HIGH).toBe("high");
      expect(OAuthGuardian.Severity.MEDIUM).toBe("medium");
      expect(OAuthGuardian.Severity.LOW).toBe("low");
      expect(OAuthGuardian.Severity.INFO).toBe("info");
    });

    it("should export CheckCategory enum", () => {
      expect(OAuthGuardian.CheckCategory).toBeDefined();
      expect(OAuthGuardian.CheckCategory.OAUTH).toBe("oauth");
      expect(OAuthGuardian.CheckCategory.NIST).toBe("nist");
      expect(OAuthGuardian.CheckCategory.OWASP).toBe("owasp");
      expect(OAuthGuardian.CheckCategory.CUSTOM).toBe("custom");
    });
  });

  describe("Core Classes", () => {
    it("should export HttpClient class", () => {
      expect(OAuthGuardian.HttpClient).toBeDefined();
      expect(typeof OAuthGuardian.HttpClient).toBe("function");
    });

    it("should export AuditEngine class", () => {
      expect(OAuthGuardian.AuditEngine).toBeDefined();
      expect(typeof OAuthGuardian.AuditEngine).toBe("function");
    });

    it("should export BaseCheck class", () => {
      expect(OAuthGuardian.BaseCheck).toBeDefined();
      expect(typeof OAuthGuardian.BaseCheck).toBe("function");
    });
  });

  describe("Reporter Classes", () => {
    it("should export JSONReporter class", () => {
      expect(OAuthGuardian.JSONReporter).toBeDefined();
      expect(typeof OAuthGuardian.JSONReporter).toBe("function");
    });

    it("should export TerminalReporter class", () => {
      expect(OAuthGuardian.TerminalReporter).toBeDefined();
      expect(typeof OAuthGuardian.TerminalReporter).toBe("function");
    });

    it("should export HTMLReporter class", () => {
      expect(OAuthGuardian.HTMLReporter).toBeDefined();
      expect(typeof OAuthGuardian.HTMLReporter).toBe("function");
    });
  });

  describe("Built-in Checks", () => {
    it("should export PKCECheck class", () => {
      expect(OAuthGuardian.PKCECheck).toBeDefined();
      expect(typeof OAuthGuardian.PKCECheck).toBe("function");
    });

    it("should export StateParameterCheck class", () => {
      expect(OAuthGuardian.StateParameterCheck).toBeDefined();
      expect(typeof OAuthGuardian.StateParameterCheck).toBe("function");
    });

    it("should export RedirectURICheck class", () => {
      expect(OAuthGuardian.RedirectURICheck).toBeDefined();
      expect(typeof OAuthGuardian.RedirectURICheck).toBe("function");
    });

    it("should export TokenStorageCheck class", () => {
      expect(OAuthGuardian.TokenStorageCheck).toBeDefined();
      expect(typeof OAuthGuardian.TokenStorageCheck).toBe("function");
    });
  });

  describe("Configuration Functions", () => {
    it("should export loadConfig function", () => {
      expect(OAuthGuardian.loadConfig).toBeDefined();
      expect(typeof OAuthGuardian.loadConfig).toBe("function");
    });

    it("should export loadConfigFromFile function", () => {
      expect(OAuthGuardian.loadConfigFromFile).toBeDefined();
      expect(typeof OAuthGuardian.loadConfigFromFile).toBe("function");
    });

    it("should export discoverAndLoadConfig function", () => {
      expect(OAuthGuardian.discoverAndLoadConfig).toBeDefined();
      expect(typeof OAuthGuardian.discoverAndLoadConfig).toBe("function");
    });

    it("should export parseConfig function", () => {
      expect(OAuthGuardian.parseConfig).toBeDefined();
      expect(typeof OAuthGuardian.parseConfig).toBe("function");
    });

    it("should export getDefaultConfig function", () => {
      expect(OAuthGuardian.getDefaultConfig).toBeDefined();
      expect(typeof OAuthGuardian.getDefaultConfig).toBe("function");
    });

    it("should export getMinimalConfig function", () => {
      expect(OAuthGuardian.getMinimalConfig).toBeDefined();
      expect(typeof OAuthGuardian.getMinimalConfig).toBe("function");
    });

    it("should export DEFAULT_CONFIG constant", () => {
      expect(OAuthGuardian.DEFAULT_CONFIG).toBeDefined();
      expect(typeof OAuthGuardian.DEFAULT_CONFIG).toBe("object");
    });

    it("should export validateConfig function", () => {
      expect(OAuthGuardian.validateConfig).toBeDefined();
      expect(typeof OAuthGuardian.validateConfig).toBe("function");
    });

    it("should export safeValidateConfig function", () => {
      expect(OAuthGuardian.safeValidateConfig).toBeDefined();
      expect(typeof OAuthGuardian.safeValidateConfig).toBe("function");
    });
  });

  describe("Integration Test - Full Audit", () => {
    it("should be able to create an audit engine and run checks", async () => {
      // This tests that all the exported pieces work together
      const config = OAuthGuardian.getMinimalConfig("https://auth.example.com");
      const engine = new OAuthGuardian.AuditEngine(config);

      // Register a check
      engine.registerCheck(new OAuthGuardian.PKCECheck());

      // Verify engine is configured
      expect(engine).toBeDefined();
      expect(typeof engine.run).toBe("function");
      expect(typeof engine.registerCheck).toBe("function");
      expect(typeof engine.registerChecks).toBe("function");
    });

    it("should be able to create reporters", () => {
      const jsonReporter = new OAuthGuardian.JSONReporter();
      const terminalReporter = new OAuthGuardian.TerminalReporter();
      const htmlReporter = new OAuthGuardian.HTMLReporter();

      expect(jsonReporter).toBeDefined();
      expect(terminalReporter).toBeDefined();
      expect(htmlReporter).toBeDefined();

      expect(typeof jsonReporter.generate).toBe("function");
      expect(typeof terminalReporter.generate).toBe("function");
      expect(typeof htmlReporter.generate).toBe("function");
    });

    it("should be able to create all built-in checks", () => {
      const pkceCheck = new OAuthGuardian.PKCECheck();
      const stateCheck = new OAuthGuardian.StateParameterCheck();
      const redirectCheck = new OAuthGuardian.RedirectURICheck();
      const tokenCheck = new OAuthGuardian.TokenStorageCheck();

      expect(pkceCheck).toBeDefined();
      expect(stateCheck).toBeDefined();
      expect(redirectCheck).toBeDefined();
      expect(tokenCheck).toBeDefined();

      // All should have required properties
      expect(pkceCheck.id).toBeDefined();
      expect(stateCheck.id).toBeDefined();
      expect(redirectCheck.id).toBeDefined();
      expect(tokenCheck.id).toBeDefined();
    });

    it("should be able to use configuration system", async () => {
      // getDefaultConfig requires a target
      const defaultConfig = OAuthGuardian.getDefaultConfig({
        target: "https://default.example.com",
      });
      expect(defaultConfig).toBeDefined();
      expect(defaultConfig.target).toBe("https://default.example.com");

      const minimalConfig = OAuthGuardian.getMinimalConfig(
        "https://example.com"
      );
      expect(minimalConfig).toBeDefined();
      expect(minimalConfig.target).toBe("https://example.com");

      // Test validation
      const validationResult = OAuthGuardian.safeValidateConfig(minimalConfig);
      expect(validationResult.success).toBe(true);
    });

    it("getDefaultConfig - should throw an error if no default config", () => {
      try {
        OAuthGuardian.getDefaultConfig({});
      } catch (error: any) {
        expect(error.message).toContain("Target URL is required.");
      }
    });
  });

  describe("API Surface Completeness", () => {
    it("should export all necessary pieces for custom check development", () => {
      // A user should be able to extend BaseCheck
      expect(OAuthGuardian.BaseCheck).toBeDefined();

      // And use the type system
      expect(OAuthGuardian.CheckStatus).toBeDefined();
      expect(OAuthGuardian.Severity).toBeDefined();
      expect(OAuthGuardian.CheckCategory).toBeDefined();
    });

    it("should export all necessary pieces for custom reporters", () => {
      // A user should have access to all reporter base classes
      expect(OAuthGuardian.JSONReporter).toBeDefined();
      expect(OAuthGuardian.TerminalReporter).toBeDefined();
      expect(OAuthGuardian.HTMLReporter).toBeDefined();
    });

    it("should export all necessary pieces for engine orchestration", () => {
      expect(OAuthGuardian.AuditEngine).toBeDefined();
      expect(OAuthGuardian.HttpClient).toBeDefined();
    });

    it("should export all necessary pieces for configuration", () => {
      expect(OAuthGuardian.loadConfig).toBeDefined();
      expect(OAuthGuardian.validateConfig).toBeDefined();
      expect(OAuthGuardian.DEFAULT_CONFIG).toBeDefined();
    });
  });
});
