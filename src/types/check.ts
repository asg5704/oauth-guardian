/**
 * Severity levels for security findings
 */
export enum Severity {
  CRITICAL = "critical",
  HIGH = "high",
  MEDIUM = "medium",
  LOW = "low",
  INFO = "info",
}

/**
 * Status of a check execution
 */
export enum CheckStatus {
  PASS = "pass",
  FAIL = "fail",
  WARNING = "warning",
  SKIPPED = "skipped",
  ERROR = "error",
}

/**
 * Category of the security check
 */
export enum CheckCategory {
  OAUTH = "oauth",
  NIST = "nist",
  OWASP = "owasp",
  CUSTOM = "custom",
}

/**
 * Result of a single security check
 */
export interface CheckResult {
  /** Unique identifier for the check */
  id: string;

  /** Human-readable name of the check */
  name: string;

  /** Category this check belongs to */
  category: CheckCategory;

  /** Status of the check execution */
  status: CheckStatus;

  /** Severity level if the check failed */
  severity?: Severity;

  /** Detailed description of what was checked */
  description: string;

  /** Details about the finding (for failures) */
  message?: string;

  /** Remediation guidance */
  remediation?: string;

  /** Reference URLs for more information */
  references?: string[];

  /** Additional metadata */
  metadata?: Record<string, unknown>;

  /** Timestamp when the check was executed */
  timestamp: Date;

  /** Execution time in milliseconds */
  executionTime?: number;
}

/**
 * Context passed to each check during execution
 */
export interface CheckContext {
  /** Target URL being audited */
  targetUrl: string;

  /** Configuration for this check */
  config?: Record<string, unknown>;

  /** Shared HTTP client instance */
  httpClient?: unknown; // Will be replaced with actual HTTP client type

  /** Logger instance */
  logger?: {
    debug: (message: string, ...args: unknown[]) => void;
    info: (message: string, ...args: unknown[]) => void;
    warn: (message: string, ...args: unknown[]) => void;
    error: (message: string, ...args: unknown[]) => void;
  };
}
