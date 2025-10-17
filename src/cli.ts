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
import { HTMLReporter } from "./reporters/html-reporter.js";
import { Severity, Report } from "./types/index.js";
import { writeFile } from "fs/promises";
import { loadConfig } from "./config/loader.js";

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
  .argument("[target]", "Target URL to audit (e.g., https://auth.example.com)")
  .option("-c, --config <path>", "Path to configuration file")
  .option(
    "-f, --format <format>",
    "Report format (json, html, markdown, csv, sarif, terminal)"
  )
  .option("-o, --output <path>", "Output file path (stdout if not specified)")
  .option(
    "--fail-on <severity>",
    "Fail with exit code 1 on this severity level"
  )
  .option("--checks <checks>", "Comma-separated list of checks to run")
  .option("--skip-checks <checks>", "Comma-separated list of checks to skip")
  .option("--nist-level <level>", "Target NIST assurance level (AAL1, AAL2, AAL3)")
  .option("-v, --verbose", "Enable verbose logging")
  .option("--no-color", "Disable colored output")
  .action(async (target: string | undefined, options) => {
    try {
      console.log(chalk.cyan("🛡️  OAuth Guardian"));
      console.log(chalk.gray(`Version ${packageJson.version}\n`));

      // Load configuration (with CLI overrides)
      const config = await loadConfig(target, options.config);

      // Override config with CLI options (only if explicitly provided)
      if (options.verbose !== undefined) {
        config.verbose = options.verbose;
      }
      if (options.checks) {
        config.checks = config.checks || {};
        config.checks.include = options.checks.split(",").map((c: string) => c.trim());
      }
      if (options.skipChecks) {
        config.checks = config.checks || {};
        config.checks.exclude = options.skipChecks.split(",").map((c: string) => c.trim());
      }

      // Override reporting config with CLI options (only if explicitly provided)
      config.reporting = config.reporting || {};

      // Only override format if explicitly provided via CLI
      if (options.format !== undefined) {
        config.reporting.format = options.format;
      }

      // Only override output if explicitly provided via CLI
      if (options.output !== undefined) {
        config.reporting.output = options.output;
      }

      // Only override failOn if explicitly provided via CLI
      if (options.failOn !== undefined) {
        config.reporting.failOn = options.failOn;
      }

      // Determine final format (defaults to terminal if not set anywhere)
      const format = (config.reporting.format || "terminal").toString().toLowerCase();

      console.log(chalk.blue("Target:"), config.target);
      console.log(chalk.blue("Format:"), format);

      if (config.verbose) {
        console.log(chalk.blue("Verbose:"), "enabled");
      }

      if (options.config) {
        console.log(chalk.blue("Config:"), options.config);
      }

      console.log(); // Blank line

      // Create audit engine with loaded config
      const engine = new AuditEngine(config);

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
      if (format === "json") {
        await outputJSON(report, config);
      } else if (format === "html") {
        await outputHTML(report, config);
      } else {
        // Terminal format (default)
        outputTerminal(report, config);
      }

      // Check if we should fail based on severity
      const failOnSeverity = (config.reporting.failOn || "critical") as string;
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
async function outputJSON(report: Report, config: any): Promise<void> {
  const reporter = new JSONReporter({ pretty: true });
  const json = reporter.generate(report);

  const outputPath = config.reporting?.output;
  if (outputPath) {
    await writeFile(outputPath, json, "utf-8");
    console.log(chalk.green(`\n✓ Report saved to ${outputPath}\n`));
  } else {
    console.log(json);
  }
}

/**
 * Output report in HTML format
 */
async function outputHTML(report: Report, config: any): Promise<void> {
  const reporter = new HTMLReporter({
    includeRemediation: config.reporting?.includeRemediation ?? true,
    includeMetadata: config.reporting?.includeMetadata ?? true,
    includeTimestamp: config.reporting?.includeTimestamp ?? true,
  });
  const html = await reporter.generate(report);

  const outputPath = config.reporting?.output;
  if (outputPath) {
    await writeFile(outputPath, html, "utf-8");
    console.log(chalk.green(`\n✓ Report saved to ${outputPath}\n`));
  } else {
    console.log(html);
  }
}

/**
 * Output report in terminal format
 */
function outputTerminal(report: Report, config: any): void {
  const reporter = new TerminalReporter({
    colors: true, // Always use colors for terminal output (can be disabled via --no-color flag)
    verbose: config.verbose ?? false,
    useTables: false, // Use list format by default for CLI
    showExecutionTime: true,
  });

  const output = reporter.generate(report);
  console.log(output);
}

program.parse();
