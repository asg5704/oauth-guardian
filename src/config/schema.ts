/**
 * Configuration Schema with Zod Validation
 * Validates configuration files to ensure type safety
 */

import { z } from "zod";
import {
  Severity,
  ReportFormat,
  CheckCategory,
} from "../types/index.js";

/**
 * OAuth check configuration schema
 */
const OAuthCheckConfigSchema = z
  .object({
    pkce: z.union([z.boolean(), z.enum(["error", "warning"])]).optional(),
    state: z.union([z.boolean(), z.enum(["error", "warning"])]).optional(),
    redirectUri: z.union([z.boolean(), z.enum(["error", "warning"])]).optional(),
    tokenStorage: z.union([z.boolean(), z.enum(["error", "warning"])]).optional(),
    tokenLifecycle: z.union([z.boolean(), z.enum(["error", "warning"])]).optional(),
    scopes: z.union([z.boolean(), z.enum(["error", "warning"])]).optional(),
    clientAuth: z.union([z.boolean(), z.enum(["error", "warning"])]).optional(),
  })
  .optional();

/**
 * NIST check configuration schema
 */
const NISTCheckConfigSchema = z
  .object({
    assuranceLevel: z
      .enum(["AAL1", "AAL2", "AAL3"])
      .optional(),
    sessionManagement: z.boolean().optional(),
    authenticators: z.boolean().optional(),
  })
  .optional();

/**
 * OWASP check configuration schema
 */
const OWASPCheckConfigSchema = z
  .object({
    severityThreshold: z
      .enum([
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
      ])
      .optional(),
    injection: z.boolean().optional(),
    logging: z.boolean().optional(),
    accessControl: z.boolean().optional(),
  })
  .optional();

/**
 * Check filtering configuration schema
 */
const ChecksConfigSchema = z
  .object({
    include: z.array(z.string()).optional(),
    exclude: z.array(z.string()).optional(),
    categories: z
      .array(
        z.enum([
          CheckCategory.OAUTH,
          CheckCategory.NIST,
          CheckCategory.OWASP,
          CheckCategory.CUSTOM,
        ])
      )
      .optional(),
  })
  .optional();

/**
 * Reporting configuration schema
 */
const ReportingConfigSchema = z
  .object({
    format: z
      .enum([
        ReportFormat.JSON,
        ReportFormat.HTML,
        ReportFormat.MARKDOWN,
        ReportFormat.CSV,
        ReportFormat.SARIF,
        ReportFormat.TERMINAL,
      ])
      .optional(),
    output: z.string().optional(),
    failOn: z
      .enum([
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
      ])
      .optional(),
    includeRemediation: z.boolean().optional(),
    includeMetadata: z.boolean().optional(),
    includeTimestamp: z.boolean().optional(),
  })
  .optional();

/**
 * Main auditor configuration schema
 */
export const AuditorConfigSchema = z.object({
  target: z.string().url().optional(),
  oauth: OAuthCheckConfigSchema,
  nist: NISTCheckConfigSchema,
  owasp: OWASPCheckConfigSchema,
  checks: ChecksConfigSchema.nullable(),
  reporting: ReportingConfigSchema,
  timeout: z.number().int().positive().optional(),
  userAgent: z.string().optional(),
  headers: z.record(z.string(), z.string()).optional(),
  verbose: z.boolean().optional(),
  pluginsDir: z.string().optional(),
});

/**
 * Type inference from schema
 */
export type ValidatedConfig = z.infer<typeof AuditorConfigSchema>;

/**
 * Validate configuration object
 */
export function validateConfig(config: unknown): ValidatedConfig {
  return AuditorConfigSchema.parse(config);
}

/**
 * Safely validate configuration with error details
 */
export function safeValidateConfig(config: unknown): {
  success: boolean;
  data?: ValidatedConfig;
  errors?: string[];
} {
  const result = AuditorConfigSchema.safeParse(config);

  if (result.success) {
    return {
      success: true,
      data: result.data,
    };
  }

  return {
    success: false,
    errors: result.error.issues.map(
      (err) =>
        `${err.path.join(".")}: ${err.message}`
    ),
  };
}
