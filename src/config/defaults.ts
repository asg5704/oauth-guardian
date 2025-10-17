/**
 * Default Configuration Values
 * Provides sensible defaults for all configuration options
 */

import {
  AuditorConfig,
  Severity,
  ReportFormat,
} from "../types/index.js";

/**
 * Default configuration for the auditor
 */
export const DEFAULT_CONFIG: Partial<AuditorConfig> = {
  // OAuth checks - all enabled by default
  oauth: {
    pkce: true,
    state: true,
    redirectUri: true,
    tokenStorage: true,
    scopes: true,
    clientAuth: true,
  },

  // NIST checks - AAL1 by default
  nist: {
    assuranceLevel: "AAL1",
    sessionManagement: true,
    authenticators: false,
  },

  // OWASP checks - high severity threshold
  owasp: {
    severityThreshold: Severity.HIGH,
    injection: true,
    logging: false,
    accessControl: true,
  },

  // Reporting - terminal by default
  reporting: {
    format: ReportFormat.TERMINAL,
    failOn: Severity.CRITICAL,
    includeRemediation: true,
    includeMetadata: true,
    includeTimestamp: true,
  },

  // HTTP client settings
  timeout: 10000, // 10 seconds
  userAgent: "OAuth-Guardian/0.1.0 (Security Audit Tool)",
  headers: {},

  // Logging
  verbose: false,
};

/**
 * Get default config merged with user overrides
 */
export function getDefaultConfig(overrides?: Partial<AuditorConfig>): AuditorConfig {
  // Validate target is present
  if (!overrides?.target) {
    throw new Error(
      "Target URL is required. Provide it via CLI argument or configuration file."
    );
  }

  // Start with defaults
  const config: AuditorConfig = {
    target: overrides.target,
    oauth: { ...DEFAULT_CONFIG.oauth, ...overrides?.oauth },
    nist: { ...DEFAULT_CONFIG.nist, ...overrides?.nist },
    owasp: { ...DEFAULT_CONFIG.owasp, ...overrides?.owasp },
    checks: overrides?.checks,
    reporting: { ...DEFAULT_CONFIG.reporting, ...overrides?.reporting },
    timeout: overrides?.timeout ?? DEFAULT_CONFIG.timeout,
    userAgent: overrides?.userAgent ?? DEFAULT_CONFIG.userAgent,
    headers: overrides?.headers ?? DEFAULT_CONFIG.headers,
    verbose: overrides?.verbose ?? DEFAULT_CONFIG.verbose,
    pluginsDir: overrides?.pluginsDir,
  };

  return config;
}

/**
 * Minimal required configuration (target only)
 */
export function getMinimalConfig(target: string): AuditorConfig {
  return getDefaultConfig({ target });
}
