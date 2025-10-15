/**
 * JSON Reporter
 * Generates JSON format reports for programmatic consumption
 */

import { Report } from "../types/index.js";

export interface JSONReporterOptions {
  /**
   * Pretty print the JSON output
   * @default true
   */
  pretty?: boolean;

  /**
   * Indent size for pretty printing
   * @default 2
   */
  indent?: number;

  /**
   * Include metadata in the report
   * @default true
   */
  includeMetadata?: boolean;

  /**
   * Include check results in the report
   * @default true
   */
  includeResults?: boolean;

  /**
   * Include findings in the report
   * @default true
   */
  includeFindings?: boolean;

  /**
   * Include compliance scorecard in the report
   * @default true
   */
  includeCompliance?: boolean;
}

export class JSONReporter {
  private options: Required<JSONReporterOptions>;

  constructor(options: JSONReporterOptions = {}) {
    this.options = {
      pretty: options.pretty ?? true,
      indent: options.indent ?? 2,
      includeMetadata: options.includeMetadata ?? true,
      includeResults: options.includeResults ?? true,
      includeFindings: options.includeFindings ?? true,
      includeCompliance: options.includeCompliance ?? true,
    };
  }

  /**
   * Generate JSON report from audit results
   */
  generate(report: Report): string {
    const output = this.buildOutput(report);

    if (this.options.pretty) {
      return JSON.stringify(output, null, this.options.indent);
    }

    return JSON.stringify(output);
  }

  /**
   * Build the output object based on options
   */
  private buildOutput(report: Report): Record<string, unknown> {
    const output: Record<string, unknown> = {
      summary: report.summary, // Always include summary
    };

    if (this.options.includeMetadata) {
      output.metadata = this.sanitizeMetadata(report.metadata);
    }

    if (this.options.includeResults) {
      output.results = report.results;
    }

    if (this.options.includeFindings) {
      output.findings = report.findings;
    }

    if (this.options.includeCompliance) {
      output.compliance = report.compliance;
    }

    return output;
  }

  /**
   * Sanitize metadata to ensure JSON serializability
   */
  private sanitizeMetadata(metadata: Report["metadata"]): Record<string, unknown> {
    return {
      ...metadata,
      startTime: metadata.startTime.toISOString(),
      endTime: metadata.endTime.toISOString(),
    };
  }

  /**
   * Generate minimal JSON report with only summary
   */
  generateMinimal(report: Report): string {
    const minimal = {
      summary: report.summary,
      metadata: {
        targetUrl: report.metadata.targetUrl,
        executionTime: report.metadata.executionTime,
        version: report.metadata.version,
      },
    };

    if (this.options.pretty) {
      return JSON.stringify(minimal, null, this.options.indent);
    }

    return JSON.stringify(minimal);
  }

  /**
   * Generate JSON report with only failures and warnings
   */
  generateIssuesOnly(report: Report): string {
    const issues = {
      summary: {
        failed: report.summary.failed,
        warnings: report.summary.warnings,
        riskScore: report.summary.riskScore,
        compliancePercentage: report.summary.compliancePercentage,
      },
      findings: report.findings,
      metadata: {
        targetUrl: report.metadata.targetUrl,
        executionTime: report.metadata.executionTime,
      },
    };

    if (this.options.pretty) {
      return JSON.stringify(issues, null, this.options.indent);
    }

    return JSON.stringify(issues);
  }
}
