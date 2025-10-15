/**
 * Terminal Reporter
 * Generates colorized terminal output with tables and formatting
 */

import chalk from "chalk";
import Table from "cli-table3";
import { Report, CheckStatus } from "../types/index.js";

export interface TerminalReporterOptions {
  /**
   * Enable colored output
   * @default true
   */
  colors?: boolean;

  /**
   * Show verbose output including remediation
   * @default false
   */
  verbose?: boolean;

  /**
   * Use tables for check results
   * @default false
   */
  useTables?: boolean;

  /**
   * Show execution time
   * @default true
   */
  showExecutionTime?: boolean;
}

export class TerminalReporter {
  private options: Required<TerminalReporterOptions>;

  constructor(options: TerminalReporterOptions = {}) {
    this.options = {
      colors: options.colors ?? true,
      verbose: options.verbose ?? false,
      useTables: options.useTables ?? false,
      showExecutionTime: options.showExecutionTime ?? true,
    };

    // Disable chalk if colors are disabled
    if (!this.options.colors) {
      chalk.level = 0;
    }
  }

  /**
   * Generate terminal output for the report
   */
  generate(report: Report): string {
    const lines: string[] = [];

    // Header
    lines.push("");
    lines.push(chalk.bold("📊 Audit Results"));
    lines.push("");
    lines.push(chalk.gray("─".repeat(60)));
    lines.push("");

    // Summary
    lines.push(...this.generateSummary(report));

    // Check Results
    if (this.options.useTables) {
      lines.push(...this.generateTableResults(report));
    } else {
      lines.push(...this.generateListResults(report));
    }

    // Compliance Scorecards
    if (report.compliance.length > 0) {
      lines.push(...this.generateComplianceScorecard(report));
    }

    // Footer
    lines.push(chalk.gray("─".repeat(60)));
    if (this.options.showExecutionTime) {
      lines.push(chalk.gray(`Completed in ${report.metadata.executionTime}ms`));
    }
    lines.push("");

    return lines.join("\n");
  }

  /**
   * Generate summary section
   */
  private generateSummary(report: Report): string[] {
    const lines: string[] = [];
    const { summary } = report;

    lines.push(chalk.bold("Summary:"));
    lines.push(`  Total Checks:    ${summary.totalChecks}`);
    lines.push(`  ${chalk.green("✓")} Passed:        ${summary.passed}`);
    lines.push(`  ${chalk.red("✗")} Failed:        ${summary.failed}`);
    lines.push(`  ${chalk.yellow("⚠")} Warnings:      ${summary.warnings}`);
    lines.push(`  ${chalk.gray("○")} Skipped:       ${summary.skipped}`);
    lines.push("");
    lines.push(
      `  Compliance:      ${this.colorizeCompliance(
        summary.compliancePercentage
      )}%`
    );
    lines.push(
      `  Risk Score:      ${this.colorizeRiskScore(summary.riskScore)}/100`
    );
    lines.push("");

    return lines;
  }

  /**
   * Generate check results as a list
   */
  private generateListResults(report: Report): string[] {
    const lines: string[] = [];

    lines.push(chalk.bold("Check Results:"));
    lines.push("");

    for (const result of report.results) {
      const icon = this.getStatusIcon(result.status);
      const statusColor = this.getStatusColor(result.status);

      lines.push(`${icon} ${chalk.bold(result.name)}`);
      lines.push(`  ${chalk.gray(result.description)}`);

      if (result.message) {
        lines.push(`  ${statusColor(result.message)}`);
      }

      // Show remediation in verbose mode for failures and warnings
      if (
        this.options.verbose &&
        (result.status === CheckStatus.FAIL ||
          result.status === CheckStatus.WARNING) &&
        result.remediation
      ) {
        lines.push("");
        lines.push(`  ${chalk.bold("Remediation:")}`);
        const remediationLines = result.remediation.split("\n");
        remediationLines.forEach((line) => {
          lines.push(`  ${line}`);
        });
      }

      lines.push("");
    }

    return lines;
  }

  /**
   * Generate check results as a table
   */
  private generateTableResults(report: Report): string[] {
    const lines: string[] = [];

    lines.push(chalk.bold("Check Results:"));
    lines.push("");

    const table = new Table({
      head: [
        chalk.bold("Status"),
        chalk.bold("Check"),
        chalk.bold("Severity"),
        chalk.bold("Message"),
      ],
      colWidths: [10, 35, 12, 40],
      wordWrap: true,
      wrapOnWordBoundary: true,
    });

    for (const result of report.results) {
      const statusIcon = this.getStatusIcon(result.status);
      const severityText = result.severity || "-";
      const messagePreview =
        result.message && result.message.length > 100
          ? result.message.substring(0, 97) + "..."
          : result.message || "-";

      table.push([
        statusIcon,
        result.name,
        this.colorizeSeverity(severityText),
        messagePreview,
      ]);
    }

    lines.push(table.toString());
    lines.push("");

    return lines;
  }

  /**
   * Generate compliance scorecard section
   */
  private generateComplianceScorecard(report: Report): string[] {
    const lines: string[] = [];

    lines.push(chalk.bold("Compliance by Standard:"));
    lines.push("");

    const table = new Table({
      head: [
        chalk.white.bold("Standard"),
        chalk.white.bold("Checks"),
        chalk.green.bold("Passed"),
        chalk.red.bold("Failed"),
        chalk.white.bold("Compliance"),
      ],
      colWidths: [30, 10, 10, 10, 15],
    });

    for (const scorecard of report.compliance) {
      const complianceColor =
        scorecard.compliancePercentage >= 80
          ? chalk.green
          : scorecard.compliancePercentage >= 50
          ? chalk.yellow
          : chalk.red;

      table.push([
        scorecard.standard,
        scorecard.totalChecks.toString(),
        chalk.green(scorecard.passed.toString()),
        chalk.red(scorecard.failed > 0 ? scorecard.failed : 0),
        complianceColor(`${scorecard.compliancePercentage}%`),
      ]);
    }

    lines.push(table.toString());
    lines.push("");

    return lines;
  }

  /**
   * Get status icon for check result
   */
  private getStatusIcon(status: CheckStatus): string {
    switch (status) {
      case CheckStatus.PASS:
        return chalk.green("✓");
      case CheckStatus.FAIL:
        return chalk.red("✗");
      case CheckStatus.WARNING:
        return chalk.yellow("⚠");
      case CheckStatus.SKIPPED:
        return chalk.gray("○");
      case CheckStatus.ERROR:
        return chalk.red("✖");
      default:
        return " ";
    }
  }

  /**
   * Get color function for status
   */
  private getStatusColor(status: CheckStatus): typeof chalk {
    switch (status) {
      case CheckStatus.PASS:
        return chalk.green;
      case CheckStatus.FAIL:
        return chalk.red;
      case CheckStatus.WARNING:
        return chalk.yellow;
      case CheckStatus.SKIPPED:
        return chalk.gray;
      case CheckStatus.ERROR:
        return chalk.red;
      default:
        return chalk.white;
    }
  }

  /**
   * Colorize compliance percentage
   */
  private colorizeCompliance(percentage: number): string {
    if (percentage >= 80) {
      return chalk.green(percentage.toString());
    } else if (percentage >= 50) {
      return chalk.yellow(percentage.toString());
    } else {
      return chalk.red(percentage.toString());
    }
  }

  /**
   * Colorize risk score
   */
  private colorizeRiskScore(score: number): string {
    if (score >= 70) {
      return chalk.red(score.toString());
    } else if (score >= 40) {
      return chalk.yellow(score.toString());
    } else {
      return chalk.green(score.toString());
    }
  }

  /**
   * Colorize severity
   */
  private colorizeSeverity(severity: string): string {
    switch (severity.toLowerCase()) {
      case "critical":
        return chalk.red.bold(severity);
      case "high":
        return chalk.red(severity);
      case "medium":
        return chalk.yellow(severity);
      case "low":
        return chalk.blue(severity);
      case "info":
        return chalk.gray(severity);
      default:
        return severity;
    }
  }

  /**
   * Generate a compact summary (one-liner)
   */
  generateCompact(report: Report): string {
    const { summary } = report;
    return `✓ ${summary.passed} | ✗ ${summary.failed} | ⚠ ${summary.warnings} | Compliance: ${summary.compliancePercentage}% | Risk: ${summary.riskScore}/100`;
  }
}
