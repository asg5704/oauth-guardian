/**
 * HTML Reporter
 * Generates beautiful HTML reports from audit results
 */

import Handlebars from "handlebars";
import { readFile } from "fs/promises";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { Report } from "../types/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export interface HTMLReporterOptions {
  /**
   * Custom template path (optional)
   */
  templatePath?: string;

  /**
   * Include remediation guidance
   * @default true
   */
  includeRemediation?: boolean;
}

export class HTMLReporter {
  private options: Required<HTMLReporterOptions>;
  private template?: HandlebarsTemplateDelegate;

  constructor(options: HTMLReporterOptions = {}) {
    this.options = {
      templatePath:
        options.templatePath ??
        join(__dirname, "../../templates/html-report.hbs"),
      includeRemediation: options.includeRemediation ?? true,
    };

    this.registerHelpers();
  }

  /**
   * Register Handlebars helpers
   */
  private registerHelpers(): void {
    // Format date helper
    Handlebars.registerHelper("formatDate", (date: Date) => {
      if (!date) return "N/A";
      return new Date(date).toLocaleString("en-US", {
        year: "numeric",
        month: "long",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    });

    // Get risk class helper
    Handlebars.registerHelper("getRiskClass", (score: number) => {
      if (score >= 70) return "risk-high";
      if (score >= 40) return "risk-medium";
      return "risk-low";
    });

    // Get compliance class helper
    Handlebars.registerHelper("getComplianceClass", (percentage: number) => {
      if (percentage >= 80) return "risk-low";
      if (percentage >= 50) return "risk-medium";
      return "risk-high";
    });

    // Get compliance badge class helper
    Handlebars.registerHelper(
      "getComplianceBadgeClass",
      (percentage: number) => {
        if (percentage >= 80) return "compliance-high";
        if (percentage >= 50) return "compliance-medium";
        return "compliance-low";
      }
    );

    // Format remediation helper (convert newlines to <br> and preserve code blocks)
    Handlebars.registerHelper("formatRemediation", (text: string) => {
      if (!text) return "";

      // Convert code blocks to <pre> tags
      let formatted = text.replace(
        /```(\w+)?\n([\s\S]*?)```/g,
        "<pre>$2</pre>"
      );

      // Convert remaining newlines to <br>
      formatted = formatted.replace(/\n/g, "<br>");

      return new Handlebars.SafeString(formatted);
    });
  }

  /**
   * Load template from file
   */
  private async loadTemplate(): Promise<void> {
    if (this.template) return;

    try {
      const templateContent = await readFile(this.options.templatePath, "utf-8");
      this.template = Handlebars.compile(templateContent);
    } catch (error) {
      throw new Error(
        `Failed to load HTML template from ${this.options.templatePath}: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  /**
   * Generate HTML report
   */
  async generate(report: Report): Promise<string> {
    await this.loadTemplate();

    if (!this.template) {
      throw new Error("Template not loaded");
    }

    // Prepare data for template
    const templateData = {
      metadata: {
        targetUrl: report.metadata.targetUrl,
        startTime: report.metadata.startTime,
        endTime: report.metadata.endTime,
        executionTime: report.metadata.executionTime,
        version: report.metadata.version,
      },
      summary: {
        totalChecks: report.summary.totalChecks,
        passed: report.summary.passed,
        failed: report.summary.failed,
        warnings: report.summary.warnings,
        skipped: report.summary.skipped,
        compliancePercentage: report.summary.compliancePercentage,
        riskScore: report.summary.riskScore,
      },
      compliance: report.compliance,
      results: this.options.includeRemediation
        ? report.results
        : report.results.map((r) => ({
            ...r,
            remediation: undefined,
          })),
    };

    // Generate HTML
    return this.template(templateData);
  }

  /**
   * Generate HTML report synchronously (requires template to be preloaded)
   */
  generateSync(report: Report): string {
    if (!this.template) {
      throw new Error("Template not loaded. Call loadTemplate() first or use generate()");
    }

    // Prepare data for template
    const templateData = {
      metadata: {
        targetUrl: report.metadata.targetUrl,
        startTime: report.metadata.startTime,
        endTime: report.metadata.endTime,
        executionTime: report.metadata.executionTime,
        version: report.metadata.version,
      },
      summary: {
        totalChecks: report.summary.totalChecks,
        passed: report.summary.passed,
        failed: report.summary.failed,
        warnings: report.summary.warnings,
        skipped: report.summary.skipped,
        compliancePercentage: report.summary.compliancePercentage,
        riskScore: report.summary.riskScore,
      },
      compliance: report.compliance,
      results: this.options.includeRemediation
        ? report.results
        : report.results.map((r) => ({
            ...r,
            remediation: undefined,
          })),
    };

    // Generate HTML
    return this.template(templateData);
  }
}
