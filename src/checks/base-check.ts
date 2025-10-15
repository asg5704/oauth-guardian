/**
 * Base class for all security checks
 */

import {
  CheckResult,
  CheckStatus,
  CheckCategory,
  Severity,
  CheckContext,
} from "../types/index.js";

/**
 * Abstract base class that all security checks must extend
 */
export abstract class BaseCheck {
  /** Unique identifier for this check */
  abstract readonly id: string;

  /** Human-readable name */
  abstract readonly name: string;

  /** Category this check belongs to */
  abstract readonly category: CheckCategory;

  /** Default severity if check fails */
  abstract readonly defaultSeverity: Severity;

  /** Description of what this check validates */
  abstract readonly description: string;

  /** References for more information */
  protected references: string[] = [];

  /**
   * Execute the security check
   * @param context Check execution context
   * @returns Promise resolving to check result
   */
  abstract execute(context: CheckContext): Promise<CheckResult>;

  /**
   * Helper method to create a passing check result
   */
  protected pass(message?: string, metadata?: Record<string, unknown>): CheckResult {
    return {
      id: this.id,
      name: this.name,
      category: this.category,
      status: CheckStatus.PASS,
      description: this.description,
      message,
      references: this.references,
      metadata,
      timestamp: new Date(),
    };
  }

  /**
   * Helper method to create a failing check result
   */
  protected fail(
    message: string,
    severity?: Severity,
    remediation?: string,
    metadata?: Record<string, unknown>
  ): CheckResult {
    return {
      id: this.id,
      name: this.name,
      category: this.category,
      status: CheckStatus.FAIL,
      severity: severity ?? this.defaultSeverity,
      description: this.description,
      message,
      remediation,
      references: this.references,
      metadata,
      timestamp: new Date(),
    };
  }

  /**
   * Helper method to create a warning result
   */
  protected warning(
    message: string,
    remediation?: string,
    metadata?: Record<string, unknown>
  ): CheckResult {
    return {
      id: this.id,
      name: this.name,
      category: this.category,
      status: CheckStatus.WARNING,
      severity: Severity.LOW,
      description: this.description,
      message,
      remediation,
      references: this.references,
      metadata,
      timestamp: new Date(),
    };
  }

  /**
   * Helper method to create a skipped result
   */
  protected skip(reason: string): CheckResult {
    return {
      id: this.id,
      name: this.name,
      category: this.category,
      status: CheckStatus.SKIPPED,
      description: this.description,
      message: reason,
      references: this.references,
      timestamp: new Date(),
    };
  }

  /**
   * Helper method to create an error result
   */
  protected error(errorMessage: string, error?: Error): CheckResult {
    return {
      id: this.id,
      name: this.name,
      category: this.category,
      status: CheckStatus.ERROR,
      description: this.description,
      message: errorMessage,
      references: this.references,
      metadata: error
        ? {
            error: error.message,
            stack: error.stack,
          }
        : undefined,
      timestamp: new Date(),
    };
  }

  /**
   * Run the check with error handling and timing
   */
  async run(context: CheckContext): Promise<CheckResult> {
    const startTime = Date.now();

    try {
      const result = await this.execute(context);
      const executionTime = Date.now() - startTime;

      return {
        ...result,
        executionTime,
      };
    } catch (error) {
      const executionTime = Date.now() - startTime;

      return {
        ...this.error(
          "Check execution failed with an error",
          error instanceof Error ? error : undefined
        ),
        executionTime,
      };
    }
  }

  /**
   * Validate that a URL is well-formed
   */
  protected isValidUrl(urlString: string): boolean {
    try {
      const url = new URL(urlString);
      return url.protocol === "http:" || url.protocol === "https:";
    } catch {
      return false;
    }
  }

  /**
   * Log debug information if verbose mode is enabled
   */
  protected log(context: CheckContext, message: string, ...args: unknown[]): void {
    if (context.logger) {
      context.logger.debug(`[${this.id}] ${message}`, ...args);
    }
  }
}
