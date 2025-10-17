import { describe, it, expect, beforeEach } from "vitest";
import { JSONReporter } from "../../../src/reporters/json-reporter.js";
import {
  Report,
  CheckStatus,
  Severity,
  CheckCategory,
} from "../../../src/types/index.js";
import { reportFixture } from "../../fixtures/mock-report.js";

describe("JSONReporter", () => {
  let mockReport: Report;

  beforeEach(() => {
    mockReport = reportFixture;
  });

  describe("constructor", () => {
    it("should create reporter with default options", () => {
      const reporter = new JSONReporter();
      expect(reporter).toBeInstanceOf(JSONReporter);
    });

    it("should create reporter with custom options", () => {
      const reporter = new JSONReporter({
        pretty: false,
        indent: 4,
        includeMetadata: false,
      });
      expect(reporter).toBeInstanceOf(JSONReporter);
    });
  });

  describe("generate()", () => {
    it("should generate valid JSON", () => {
      const reporter = new JSONReporter();
      const json = reporter.generate(mockReport);

      expect(() => JSON.parse(json)).not.toThrow();
    });

    it("should generate pretty-printed JSON by default", () => {
      const reporter = new JSONReporter();
      const json = reporter.generate(mockReport);

      expect(json).toContain("\n");
      expect(json).toContain("  ");
    });

    it("should generate compact JSON when pretty is false", () => {
      const reporter = new JSONReporter({ pretty: false });
      const json = reporter.generate(mockReport);

      expect(json).not.toContain("\n");
    });

    it("should use custom indent size", () => {
      const reporter = new JSONReporter({ indent: 4 });
      const json = reporter.generate(mockReport);

      expect(json).toContain("    "); // 4 spaces
    });

    it("should include all sections by default", () => {
      const reporter = new JSONReporter();
      const json = reporter.generate(mockReport);
      const parsed = JSON.parse(json);

      expect(parsed).toHaveProperty("metadata");
      expect(parsed).toHaveProperty("summary");
      expect(parsed).toHaveProperty("results");
      expect(parsed).toHaveProperty("findings");
      expect(parsed).toHaveProperty("compliance");
    });

    it("should exclude metadata when includeMetadata is false", () => {
      const reporter = new JSONReporter({ includeMetadata: false });
      const json = reporter.generate(mockReport);
      const parsed = JSON.parse(json);

      expect(parsed).not.toHaveProperty("metadata");
      expect(parsed).toHaveProperty("summary");
    });

    it("should exclude results when includeResults is false", () => {
      const reporter = new JSONReporter({ includeResults: false });
      const json = reporter.generate(mockReport);
      const parsed = JSON.parse(json);

      expect(parsed).not.toHaveProperty("results");
      expect(parsed).toHaveProperty("summary");
    });

    it("should exclude findings when includeFindings is false", () => {
      const reporter = new JSONReporter({ includeFindings: false });
      const json = reporter.generate(mockReport);
      const parsed = JSON.parse(json);

      expect(parsed).not.toHaveProperty("findings");
      expect(parsed).toHaveProperty("summary");
    });

    it("should exclude compliance when includeCompliance is false", () => {
      const reporter = new JSONReporter({ includeCompliance: false });
      const json = reporter.generate(mockReport);
      const parsed = JSON.parse(json);

      expect(parsed).not.toHaveProperty("compliance");
      expect(parsed).toHaveProperty("summary");
    });

    it("should always include summary", () => {
      const reporter = new JSONReporter({
        includeMetadata: false,
        includeResults: false,
        includeFindings: false,
        includeCompliance: false,
      });
      const json = reporter.generate(mockReport);
      const parsed = JSON.parse(json);

      expect(parsed).toHaveProperty("summary");
      expect(parsed.summary.totalChecks).toBe(4);
    });

    it("should sanitize dates to ISO strings", () => {
      const reporter = new JSONReporter();
      const json = reporter.generate(mockReport);
      const parsed = JSON.parse(json);

      expect(parsed.metadata.startTime).toBe("2025-01-01T00:00:00.000Z");
      expect(parsed.metadata.endTime).toBe("2025-01-01T00:00:01.000Z");
    });

    it("should include all check results", () => {
      const reporter = new JSONReporter();
      const json = reporter.generate(mockReport);
      const parsed = JSON.parse(json);

      expect(parsed.results).toHaveLength(4);
      expect(parsed.results[0].id).toBe("test-pass");
      expect(parsed.results[1].id).toBe("test-fail");
    });

    it("should include findings", () => {
      const reporter = new JSONReporter();
      const json = reporter.generate(mockReport);
      const parsed = JSON.parse(json);

      expect(parsed.findings).toHaveLength(2);
      expect(parsed.findings[0].check.status).toBe(CheckStatus.FAIL);
      expect(parsed.findings[1].check.status).toBe(CheckStatus.WARNING);
    });

    it("should include compliance scorecard", () => {
      const reporter = new JSONReporter();
      const json = reporter.generate(mockReport);
      const parsed = JSON.parse(json);

      expect(parsed.compliance).toHaveLength(1);
      expect(parsed.compliance[0].standard).toBe("OAuth 2.0 / RFC 6749");
      expect(parsed.compliance[0].compliancePercentage).toBe(50);
    });
  });

  describe("generateMinimal()", () => {
    it("should generate minimal JSON with only summary and basic metadata", () => {
      const reporter = new JSONReporter();
      const json = reporter.generateMinimal(mockReport);
      const parsed = JSON.parse(json);

      expect(parsed).toHaveProperty("summary");
      expect(parsed).toHaveProperty("metadata");
      expect(parsed.metadata).toHaveProperty("targetUrl");
      expect(parsed.metadata).toHaveProperty("executionTime");
      expect(parsed.metadata).toHaveProperty("version");
      expect(parsed).not.toHaveProperty("results");
      expect(parsed).not.toHaveProperty("findings");
      expect(parsed).not.toHaveProperty("compliance");
    });

    it("should respect pretty option in minimal report", () => {
      const reporter = new JSONReporter({ pretty: false });
      const json = reporter.generateMinimal(mockReport);

      expect(json).not.toContain("\n");
    });

    it("should include full summary in minimal report", () => {
      const reporter = new JSONReporter();
      const json = reporter.generateMinimal(mockReport);
      const parsed = JSON.parse(json);

      expect(parsed.summary.totalChecks).toBe(4);
      expect(parsed.summary.passed).toBe(2);
      expect(parsed.summary.failed).toBe(1);
      expect(parsed.summary.warnings).toBe(1);
      expect(parsed.summary.riskScore).toBe(20);
      expect(parsed.summary.compliancePercentage).toBe(50);
    });
  });

  describe("generateIssuesOnly()", () => {
    it("should generate JSON with only failures and warnings", () => {
      const reporter = new JSONReporter();
      const json = reporter.generateIssuesOnly(mockReport);
      const parsed = JSON.parse(json);

      expect(parsed).toHaveProperty("summary");
      expect(parsed).toHaveProperty("findings");
      expect(parsed).toHaveProperty("metadata");
      expect(parsed).not.toHaveProperty("results");
      expect(parsed).not.toHaveProperty("compliance");
    });

    it("should include only issue-related summary fields", () => {
      const reporter = new JSONReporter();
      const json = reporter.generateIssuesOnly(mockReport);
      const parsed = JSON.parse(json);

      expect(parsed.summary.failed).toBe(1);
      expect(parsed.summary.warnings).toBe(1);
      expect(parsed.summary.riskScore).toBe(20);
      expect(parsed.summary.compliancePercentage).toBe(50);
      expect(parsed.summary).not.toHaveProperty("totalChecks");
      expect(parsed.summary).not.toHaveProperty("passed");
    });

    it("should include all findings", () => {
      const reporter = new JSONReporter();
      const json = reporter.generateIssuesOnly(mockReport);
      const parsed = JSON.parse(json);

      expect(parsed.findings).toHaveLength(2);
      expect(parsed.findings[0].check.status).toBe(CheckStatus.FAIL);
      expect(parsed.findings[1].check.status).toBe(CheckStatus.WARNING);
    });

    it("should respect pretty option in issues-only report", () => {
      const reporter = new JSONReporter({ pretty: false });
      const json = reporter.generateIssuesOnly(mockReport);

      expect(json).not.toContain("\n");
    });
  });

  describe("edge cases", () => {
    it("should handle report with no findings", () => {
      const reportWithNoFindings: Report = {
        ...mockReport,
        findings: [],
      };

      const reporter = new JSONReporter();
      const json = reporter.generate(reportWithNoFindings);
      const parsed = JSON.parse(json);

      expect(parsed.findings).toEqual([]);
    });

    it("should handle report with no compliance data", () => {
      const reportWithNoCompliance: Report = {
        ...mockReport,
        compliance: [],
      };

      const reporter = new JSONReporter();
      const json = reporter.generate(reportWithNoCompliance);
      const parsed = JSON.parse(json);

      expect(parsed.compliance).toEqual([]);
    });

    it("should handle report with metadata containing special characters", () => {
      const reportWithSpecialChars: Report = {
        ...mockReport,
        metadata: {
          ...mockReport.metadata,
          targetUrl: 'https://example.com/path?query=value&special=<>&"',
        },
      };

      const reporter = new JSONReporter();
      const json = reporter.generate(reportWithSpecialChars);
      const parsed = JSON.parse(json);

      expect(parsed.metadata.targetUrl).toBe(
        'https://example.com/path?query=value&special=<>&"'
      );
    });

    it("should handle large reports efficiently", () => {
      const largeReport: Report = {
        ...mockReport,
        results: Array(1000).fill(mockReport.results[0]),
      };

      const reporter = new JSONReporter();
      const json = reporter.generate(largeReport);

      expect(() => JSON.parse(json)).not.toThrow();
    });
  });
});
