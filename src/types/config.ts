import { Severity, CheckCategory } from "./check.js";

/**
 * OAuth-specific check configuration
 */
export interface OAuthCheckConfig {
  /** Require PKCE implementation */
  pkce?: boolean | "error" | "warning";

  /** Require state parameter */
  state?: boolean | "error" | "warning";

  /** Check redirect URI validation */
  redirectUri?: boolean | "error" | "warning";

  /** Analyze token storage security */
  tokenStorage?: boolean | "error" | "warning";

  /** Check token lifecycle management */
  tokenLifecycle?: boolean | "error" | "warning";

  /** Validate scope enforcement */
  scopes?: boolean | "error" | "warning";

  /** Check client authentication */
  clientAuth?: boolean | "error" | "warning";
}

/**
 * NIST 800-63B check configuration
 */
export interface NISTCheckConfig {
  /** Target Authentication Assurance Level */
  assuranceLevel?: "AAL1" | "AAL2" | "AAL3";

  /** Check session management */
  sessionManagement?: boolean;

  /** Check authenticator lifecycle */
  authenticators?: boolean;
}

/**
 * OWASP check configuration
 */
export interface OWASPCheckConfig {
  /** Minimum severity threshold to report */
  severityThreshold?: Severity;

  /** Check for injection vulnerabilities */
  injection?: boolean;

  /** Check logging and monitoring */
  logging?: boolean;

  /** Check for broken access control */
  accessControl?: boolean;
}

/**
 * Report format options
 */
export enum ReportFormat {
  JSON = "json",
  HTML = "html",
  MARKDOWN = "markdown",
  CSV = "csv",
  SARIF = "sarif",
  TERMINAL = "terminal",
}

/**
 * Reporting configuration
 */
export interface ReportingConfig {
  /** Output format */
  format?: ReportFormat | ReportFormat[];

  /** Output file path (stdout if not specified) */
  output?: string;

  /** Fail CI/CD pipeline on this severity level */
  failOn?: Severity;

  /** Include remediation guidance in reports */
  includeRemediation?: boolean;

  /** Include metadata in reports */
  includeMetadata?: boolean;
}

/**
 * Check filtering configuration
 */
export interface CheckFilterConfig {
  /** Include only these checks (by ID) */
  include?: string[];

  /** Exclude these checks (by ID) */
  exclude?: string[];

  /** Include only these categories */
  categories?: CheckCategory[];
}

/**
 * Main auditor configuration
 */
export interface AuditorConfig {
  /** Target URL to audit */
  target: string;

  /** OAuth check configuration */
  oauth?: OAuthCheckConfig;

  /** NIST check configuration */
  nist?: NISTCheckConfig;

  /** OWASP check configuration */
  owasp?: OWASPCheckConfig;

  /** Reporting configuration */
  reporting?: ReportingConfig;

  /** Check filtering */
  checks?: CheckFilterConfig;

  /** HTTP request timeout (ms) */
  timeout?: number;

  /** Enable verbose logging */
  verbose?: boolean;

  /** Custom check plugins directory */
  pluginsDir?: string;

  /** User agent string for HTTP requests */
  userAgent?: string;

  /** Additional HTTP headers */
  headers?: Record<string, string>;
}
