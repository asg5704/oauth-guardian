#!/usr/bin/env node

/**
 * OAuth Guardian CLI
 * Command-line interface for auditing OAuth 2.0 implementations
 */

import { Command } from "commander";
import chalk from "chalk";
import { readFile } from "fs/promises";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { AuditEngine } from "./auditor/engine.js";
import { PKCECheck } from "./checks/oauth/pkce.js";
import { StateParameterCheck } from "./checks/oauth/state.js";
import { RedirectURICheck } from "./checks/oauth/redirect-uri.js";
import { TokenStorageCheck } from "./checks/oauth/token-storage.js";
import { JSONReporter } from "./reporters/json-reporter.js";
import { TerminalReporter } from "./reporters/terminal-reporter.js";
import { Severity, Report } from "./types/index.js";
import { writeFile } from "fs/promises";

// Get package.json for version info
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const packageJson = JSON.parse(
  await readFile(join(__dirname, "../package.json"), "utf-8")
);

const program = new Command();

program
  .name("oauth-guardian")
  .description(
    "Audit OAuth 2.0 implementations against OWASP, NIST, and RFC specifications"
  )
  .version(packageJson.version)
  .argument("<target>", "Target URL to audit (e.g., https://auth.example.com)")
  .option("-c, --config <path>", "Path to configuration file")
  .option(
    "-f, --format <format>",
    "Report format (json, html, markdown, csv, sarif)",
    "terminal"
  )
  .option("-o, --output <path>", "Output file path (stdout if not specified)")
  .option(
    "--fail-on <severity>",
    "Fail with exit code 1 on this severity level",
    "critical"
  )
  .option("--checks <checks>", "Comma-separated list of checks to run")
  .option("--skip-checks <checks>", "Comma-separated list of checks to skip")
  .option("--nist-level <level>", "Target NIST assurance level (AAL1, AAL2, AAL3)")
  .option("-v, --verbose", "Enable verbose logging", false)
  .option("--no-color", "Disable colored output")
  .action(async (target: string, options) => {
    try {
      console.log(chalk.cyan("🛡️  OAuth Guardian"));
      console.log(chalk.gray(`Version ${packageJson.version}\n`));

      console.log(chalk.blue("Target:"), target);
      console.log(chalk.blue("Format:"), options.format);

      if (options.verbose) {
        console.log(chalk.blue("Verbose:"), "enabled");
      }

      if (options.config) {
        console.log(chalk.blue("Config:"), options.config);
      }

      console.log(); // Blank line

      // Create audit engine
      const engine = new AuditEngine({
        target,
        verbose: options.verbose,
        timeout: 10000,
      });

      // Register checks
      engine.registerChecks([
        new PKCECheck(),
        new StateParameterCheck(),
        new RedirectURICheck(),
        new TokenStorageCheck(),
      ]);

      // Run audit
      console.log(chalk.gray("Running security checks...\n"));
      const report = await engine.run();

      // Output based on format
      const format = options.format.toLowerCase();

      if (format === "json") {
        await outputJSON(report, options);
      } else {
        // Terminal format (default)
        outputTerminal(report, options);
      }

      // Check if we should fail based on severity
      const failOnSeverity = options.failOn as string;
      const severityMap: Record<string, Severity> = {
        critical: Severity.CRITICAL,
        high: Severity.HIGH,
        medium: Severity.MEDIUM,
        low: Severity.LOW,
        info: Severity.INFO,
      };

      const minSeverity = severityMap[failOnSeverity.toLowerCase()];
      if (minSeverity && engine.hasFailures(report, minSeverity)) {
        if (format !== "json") {
          console.log(
            chalk.red(
              `\n❌ Audit failed: Found issues at or above ${failOnSeverity} severity\n`
            )
          );
        }
        process.exit(1);
      } else {
        if (format !== "json") {
          console.log(chalk.green("✓ Audit completed successfully\n"));
        }
      }
    } catch (error) {
      console.error(chalk.red("\n❌ Error:"), error);
      if (error instanceof Error && error.stack) {
        console.error(chalk.gray(error.stack));
      }
      process.exit(1);
    }
  });

/**
 * Output report in JSON format
 */
async function outputJSON(report: Report, options: any): Promise<void> {
  const reporter = new JSONReporter({ pretty: true });
  const json = reporter.generate(report);

  if (options.output) {
    await writeFile(options.output, json, "utf-8");
    console.log(chalk.green(`\n✓ Report saved to ${options.output}\n`));
  } else {
    console.log(json);
  }
}

/**
 * Output report in terminal format
 */
function outputTerminal(report: Report, options: any): void {
  const reporter = new TerminalReporter({
    colors: options.color !== false, // Commander converts --no-color to color: false
    verbose: options.verbose,
    useTables: false, // Use list format by default for CLI
    showExecutionTime: true,
  });

  const output = reporter.generate(report);
  console.log(output);
}

program.parse();
