import { CheckResult, Severity, CheckCategory } from "./check.js";

/**
 * Individual finding in the audit report
 */
export interface Finding {
  /** Check result that generated this finding */
  check: CheckResult;

  /** Impact description */
  impact?: string;

  /** Affected components or endpoints */
  affected?: string[];
}

/**
 * Summary statistics for the audit
 */
export interface AuditSummary {
  /** Total number of checks executed */
  totalChecks: number;

  /** Number of passed checks */
  passed: number;

  /** Number of failed checks */
  failed: number;

  /** Number of warnings */
  warnings: number;

  /** Number of skipped checks */
  skipped: number;

  /** Number of checks that errored */
  errors: number;

  /** Findings by severity */
  bySeverity: {
    [Severity.CRITICAL]: number;
    [Severity.HIGH]: number;
    [Severity.MEDIUM]: number;
    [Severity.LOW]: number;
    [Severity.INFO]: number;
  };

  /** Findings by category */
  byCategory: {
    [CheckCategory.OAUTH]: number;
    [CheckCategory.NIST]: number;
    [CheckCategory.OWASP]: number;
    [CheckCategory.CUSTOM]: number;
  };

  /** Overall risk score (0-100) */
  riskScore: number;

  /** Compliance percentage (0-100) */
  compliancePercentage: number;
}

/**
 * Compliance scorecard for a specific standard
 */
export interface ComplianceScorecard {
  /** Standard name (e.g., "OAuth 2.0", "NIST AAL2") */
  standard: string;

  /** Category */
  category: CheckCategory;

  /** Total checks for this standard */
  totalChecks: number;

  /** Passed checks */
  passed: number;

  /** Failed checks */
  failed: number;

  /** Compliance percentage */
  compliancePercentage: number;

  /** Whether the standard is met */
  compliant: boolean;
}

/**
 * NIST AAL-specific compliance metrics
 */
export interface NISTAALCompliance {
  /** AAL1 compliance status */
  aal1: {
    /** Whether AAL1 checks were run */
    evaluated: boolean;
    /** Whether AAL1 requirements are met */
    compliant: boolean;
    /** Compliance percentage */
    compliancePercentage: number;
    /** Number of passed checks */
    passed: number;
    /** Number of failed checks */
    failed: number;
    /** Number of warnings */
    warnings: number;
  };

  /** AAL2 compliance status */
  aal2: {
    /** Whether AAL2 checks were run */
    evaluated: boolean;
    /** Whether AAL2 requirements are met */
    compliant: boolean;
    /** Compliance percentage */
    compliancePercentage: number;
    /** Number of passed checks */
    passed: number;
    /** Number of failed checks */
    failed: number;
    /** Number of warnings */
    warnings: number;
  };

  /** AAL3 compliance status */
  aal3: {
    /** Whether AAL3 checks were run */
    evaluated: boolean;
    /** Whether AAL3 requirements are met */
    compliant: boolean;
    /** Compliance percentage */
    compliancePercentage: number;
    /** Number of passed checks */
    passed: number;
    /** Number of failed checks */
    failed: number;
    /** Number of warnings */
    warnings: number;
  };

  /** Highest AAL level achieved */
  highestAAL: "AAL1" | "AAL2" | "AAL3" | "None";

  /** Overall NIST compliance percentage */
  overallCompliance: number;
}

/**
 * Main audit report
 */
export interface Report {
  /** Report metadata */
  metadata: {
    /** Target URL audited */
    targetUrl: string;

    /** Timestamp when audit started */
    startTime: Date;

    /** Timestamp when audit completed */
    endTime: Date;

    /** Total execution time in milliseconds */
    executionTime: number;

    /** Tool version */
    version: string;

    /** Configuration used */
    config?: Record<string, unknown>;
  };

  /** Summary statistics */
  summary: AuditSummary;

  /** All check results */
  results: CheckResult[];

  /** Findings (failed checks and warnings) */
  findings: Finding[];

  /** Compliance scorecards */
  compliance: ComplianceScorecard[];

  /** NIST AAL-specific compliance metrics */
  nist?: NISTAALCompliance;

  /** Recommendations for improvement */
  recommendations?: string[];
}

/**
 * Export format options for reports
 */
export interface ReportExportOptions {
  /** Include full check results */
  includeResults?: boolean;

  /** Include remediation guidance */
  includeRemediation?: boolean;

  /** Include metadata */
  includeMetadata?: boolean;

  /** Pretty-print JSON */
  pretty?: boolean;

  /** Include charts (for HTML) */
  includeCharts?: boolean;
}
