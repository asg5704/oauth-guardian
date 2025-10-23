/**
 * Audit Engine
 * Orchestrates the execution of security checks and aggregates results
 */

import { HttpClient } from "./http-client.js";
import { BaseCheck } from "../checks/base-check.js";
import {
  AuditorConfig,
  CheckResult,
  CheckContext,
  Report,
  AuditSummary,
  ComplianceScorecard,
  NISTAALCompliance,
  Finding,
  Severity,
  CheckStatus,
  CheckCategory,
} from "../types/index.js";

export class AuditEngine {
  private config: AuditorConfig;
  private httpClient: HttpClient;
  private checks: BaseCheck[] = [];
  private logger?: CheckContext["logger"];

  constructor(config: AuditorConfig) {
    this.config = config;
    this.httpClient = new HttpClient({
      timeout: config.timeout,
      userAgent: config.userAgent,
      headers: config.headers,
      verbose: config.verbose,
    });

    if (config.verbose) {
      this.setupLogger();
    }
  }

  /**
   * Set up a simple console logger
   */
  private setupLogger(): void {
    this.logger = {
      debug: (message: string, ...args: unknown[]) =>
        console.debug(`[DEBUG] ${message}`, ...args),
      info: (message: string, ...args: unknown[]) =>
        console.info(`[INFO] ${message}`, ...args),
      warn: (message: string, ...args: unknown[]) =>
        console.warn(`[WARN] ${message}`, ...args),
      error: (message: string, ...args: unknown[]) =>
        console.error(`[ERROR] ${message}`, ...args),
    };
  }

  /**
   * Register a security check to be executed
   */
  registerCheck(check: BaseCheck): void {
    this.checks.push(check);
  }

  /**
   * Register multiple security checks
   */
  registerChecks(checks: BaseCheck[]): void {
    this.checks.push(...checks);
  }

  /**
   * Run all registered checks and generate a report
   */
  async run(): Promise<Report> {
    const startTime = new Date();
    this.logger?.info(`Starting audit of ${this.config.target}`);
    this.logger?.info(`Registered checks: ${this.checks.length}`);

    // Filter checks based on configuration
    const checksToRun = this.filterChecks();
    this.logger?.info(`Checks to run after filtering: ${checksToRun.length}`);

    // Create check context
    const context: CheckContext = {
      targetUrl: this.config.target,
      config: this.config as unknown as Record<string, unknown>,
      httpClient: this.httpClient,
      logger: this.logger,
    };

    // Run all checks
    const results: CheckResult[] = [];
    for (const check of checksToRun) {
      this.logger?.info(`Running check: ${check.name} (${check.id})`);
      try {
        const result = await check.run(context);
        results.push(result);
        this.logger?.info(
          `Check completed: ${check.id} - Status: ${result.status}`
        );
      } catch (error) {
        this.logger?.error(`Check failed with error: ${check.id}`, error);
        // Even if a check throws, we continue with others
        results.push({
          id: check.id,
          name: check.name,
          category: check.category,
          status: CheckStatus.ERROR,
          description: check.description,
          message: `Check execution failed: ${error instanceof Error ? error.message : String(error)}`,
          timestamp: new Date(),
        });
      }
    }

    const endTime = new Date();
    const executionTime = endTime.getTime() - startTime.getTime();

    this.logger?.info(`Audit completed in ${executionTime}ms`);

    // Generate report
    const report = this.generateReport(results, startTime, endTime, executionTime);
    return report;
  }

  /**
   * Filter checks based on configuration
   */
  private filterChecks(): BaseCheck[] {
    let filtered = [...this.checks];

    if (!this.config.checks) {
      return filtered;
    }

    // Filter by included checks
    if (this.config.checks.include && this.config.checks.include.length > 0) {
      filtered = filtered.filter((check) =>
        this.config.checks!.include!.includes(check.id)
      );
    }

    // Filter by excluded checks
    if (this.config.checks.exclude && this.config.checks.exclude.length > 0) {
      filtered = filtered.filter(
        (check) => !this.config.checks!.exclude!.includes(check.id)
      );
    }

    // Filter by categories
    if (this.config.checks.categories && this.config.checks.categories.length > 0) {
      filtered = filtered.filter((check) =>
        this.config.checks!.categories!.includes(check.category)
      );
    }

    return filtered;
  }

  /**
   * Generate audit report from check results
   */
  private generateReport(
    results: CheckResult[],
    startTime: Date,
    endTime: Date,
    executionTime: number
  ): Report {
    const summary = this.generateSummary(results);
    const findings = this.generateFindings(results);
    const compliance = this.generateComplianceScorecard(results);
    const nist = this.generateNISTAALCompliance(results);

    return {
      metadata: {
        targetUrl: this.config.target,
        startTime,
        endTime,
        executionTime,
        version: "0.1.0", // TODO: Get from package.json
        config: this.config as unknown as Record<string, unknown>,
      },
      summary,
      results,
      findings,
      compliance,
      nist,
    };
  }

  /**
   * Generate audit summary statistics
   */
  private generateSummary(results: CheckResult[]): AuditSummary {
    const summary: AuditSummary = {
      totalChecks: results.length,
      passed: 0,
      failed: 0,
      warnings: 0,
      skipped: 0,
      errors: 0,
      bySeverity: {
        [Severity.CRITICAL]: 0,
        [Severity.HIGH]: 0,
        [Severity.MEDIUM]: 0,
        [Severity.LOW]: 0,
        [Severity.INFO]: 0,
      },
      byCategory: {
        [CheckCategory.OAUTH]: 0,
        [CheckCategory.NIST]: 0,
        [CheckCategory.OWASP]: 0,
        [CheckCategory.CUSTOM]: 0,
      },
      riskScore: 0,
      compliancePercentage: 0,
    };

    // Count by status
    for (const result of results) {
      switch (result.status) {
        case CheckStatus.PASS:
          summary.passed++;
          break;
        case CheckStatus.FAIL:
          summary.failed++;
          if (result.severity) {
            summary.bySeverity[result.severity]++;
          }
          break;
        case CheckStatus.WARNING:
          summary.warnings++;
          if (result.severity) {
            summary.bySeverity[result.severity]++;
          }
          break;
        case CheckStatus.SKIPPED:
          summary.skipped++;
          break;
        case CheckStatus.ERROR:
          summary.errors++;
          break;
      }

      // Count by category
      summary.byCategory[result.category]++;
    }

    // Calculate compliance percentage
    const totalRelevant = summary.totalChecks - summary.skipped - summary.errors;
    summary.compliancePercentage =
      totalRelevant > 0 ? Math.round((summary.passed / totalRelevant) * 100) : 0;

    // Calculate risk score (0-100, higher is worse)
    const criticalWeight = 10;
    const highWeight = 5;
    const mediumWeight = 3;
    const lowWeight = 1;

    const weightedRisk =
      summary.bySeverity[Severity.CRITICAL] * criticalWeight +
      summary.bySeverity[Severity.HIGH] * highWeight +
      summary.bySeverity[Severity.MEDIUM] * mediumWeight +
      summary.bySeverity[Severity.LOW] * lowWeight;

    // Normalize to 0-100 scale (cap at 100)
    summary.riskScore = Math.min(100, Math.round(weightedRisk * 2));

    return summary;
  }

  /**
   * Generate findings (failed checks and warnings)
   */
  private generateFindings(results: CheckResult[]): Finding[] {
    return results
      .filter(
        (result) =>
          result.status === CheckStatus.FAIL ||
          result.status === CheckStatus.WARNING
      )
      .map((result) => ({
        check: result,
      }));
  }

  /**
   * Generate compliance scorecards by category
   */
  private generateComplianceScorecard(
    results: CheckResult[]
  ): ComplianceScorecard[] {
    const scorecard: ComplianceScorecard[] = [];

    // Group results by category
    const categories = new Set(results.map((r) => r.category));

    for (const category of categories) {
      const categoryResults = results.filter((r) => r.category === category);
      const totalChecks = categoryResults.length;
      const passed = categoryResults.filter(
        (r) => r.status === CheckStatus.PASS
      ).length;
      const failed = categoryResults.filter(
        (r) => r.status === CheckStatus.FAIL
      ).length;
      const compliancePercentage =
        totalChecks > 0 ? Math.round((passed / totalChecks) * 100) : 0;

      scorecard.push({
        standard: this.getCategoryName(category),
        category,
        totalChecks,
        passed,
        failed,
        compliancePercentage,
        compliant: failed === 0,
      });
    }

    return scorecard;
  }

  /**
   * Get human-readable category name
   */
  private getCategoryName(category: CheckCategory): string {
    switch (category) {
      case CheckCategory.OAUTH:
        return "OAuth 2.0 / RFC 6749";
      case CheckCategory.NIST:
        return "NIST 800-63B";
      case CheckCategory.OWASP:
        return "OWASP Top 10";
      case CheckCategory.CUSTOM:
        return "Custom Checks";
      default:
        return category;
    }
  }

  /**
   * Generate NIST AAL-specific compliance metrics
   */
  private generateNISTAALCompliance(
    results: CheckResult[]
  ): NISTAALCompliance | undefined {
    // Filter for NIST AAL checks
    const aalChecks = results.filter((r) =>
      r.category === CheckCategory.NIST &&
      (r.id.includes("aal1") || r.id.includes("aal2") || r.id.includes("aal3"))
    );

    // If no AAL checks were run, return undefined
    if (aalChecks.length === 0) {
      return undefined;
    }

    // Helper function to calculate compliance for an AAL level
    const calculateAALCompliance = (aalLevel: string) => {
      const levelChecks = results.filter(
        (r) => r.id === `nist-${aalLevel}-compliance`
      );

      if (levelChecks.length === 0) {
        return {
          evaluated: false,
          compliant: false,
          compliancePercentage: 0,
          passed: 0,
          failed: 0,
          warnings: 0,
        };
      }

      const check = levelChecks[0];
      if (!check) {
        return {
          evaluated: false,
          compliant: false,
          compliancePercentage: 0,
          passed: 0,
          failed: 0,
          warnings: 0,
        };
      }

      const passed = check.status === CheckStatus.PASS ? 1 : 0;
      const failed = check.status === CheckStatus.FAIL ? 1 : 0;
      const warnings = check.status === CheckStatus.WARNING ? 1 : 0;

      return {
        evaluated: true,
        compliant: check.status === CheckStatus.PASS,
        compliancePercentage: passed === 1 ? 100 : 0,
        passed,
        failed,
        warnings,
      };
    };

    const aal1 = calculateAALCompliance("aal1");
    const aal2 = calculateAALCompliance("aal2");
    const aal3 = calculateAALCompliance("aal3");

    // Determine highest AAL achieved
    let highestAAL: "AAL1" | "AAL2" | "AAL3" | "None" = "None";
    if (aal3.compliant) {
      highestAAL = "AAL3";
    } else if (aal2.compliant) {
      highestAAL = "AAL2";
    } else if (aal1.compliant) {
      highestAAL = "AAL1";
    }

    // Calculate overall NIST compliance
    const evaluatedLevels = [aal1, aal2, aal3].filter((aal) => aal.evaluated);
    const totalPassed = evaluatedLevels.reduce((sum, aal) => sum + aal.passed, 0);
    const totalChecks = evaluatedLevels.length;
    const overallCompliance =
      totalChecks > 0 ? Math.round((totalPassed / totalChecks) * 100) : 0;

    return {
      aal1,
      aal2,
      aal3,
      highestAAL,
      overallCompliance,
    };
  }

  /**
   * Check if report has failures at or above the specified severity
   */
  hasFailures(report: Report, minSeverity: Severity = Severity.CRITICAL): boolean {
    const severityOrder = [
      Severity.INFO,
      Severity.LOW,
      Severity.MEDIUM,
      Severity.HIGH,
      Severity.CRITICAL,
    ];

    const minSeverityIndex = severityOrder.indexOf(minSeverity);

    return report.findings.some((finding) => {
      if (!finding.check.severity) return false;
      const findingSeverityIndex = severityOrder.indexOf(finding.check.severity);
      return findingSeverityIndex >= minSeverityIndex;
    });
  }
}
