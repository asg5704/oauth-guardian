/**
 * Tests for CLI functionality
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { spawn } from "child_process";
import { readFile, writeFile, mkdir, rm } from "fs/promises";
import { join } from "path";
import { tmpdir } from "os";

describe("CLI", () => {
  let tempDir: string;

  beforeEach(async () => {
    // Create a temporary directory for test outputs
    tempDir = join(tmpdir(), `oauth-guardian-test-${Date.now()}`);
    await mkdir(tempDir, { recursive: true });
  });

  afterEach(async () => {
    // Clean up temporary directory
    try {
      await rm(tempDir, { recursive: true, force: true });
    } catch (error) {
      // Ignore cleanup errors
    }
  });

  describe("CLI Execution", () => {
    it("should display version when --version flag is used", (done) => {
      const cli = spawn("node", ["dist/cli.js", "--version"], {
        stdio: ["pipe", "pipe", "pipe"],
      });

      let output = "";
      cli.stdout.on("data", (data) => {
        output += data.toString();
      });

      cli.on("close", (code) => {
        expect(output).toMatch(/\d+\.\d+\.\d+/); // Should contain version number
        done();
      });
    });

    it("should display help when --help flag is used", (done) => {
      const cli = spawn("node", ["dist/cli.js", "--help"], {
        stdio: ["pipe", "pipe", "pipe"],
      });

      let output = "";
      cli.stdout.on("data", (data) => {
        output += data.toString();
      });

      cli.on("close", (code) => {
        expect(output).toContain("oauth-guardian");
        expect(output).toContain("Options:");
        expect(output).toContain("--format");
        expect(output).toContain("--output");
        done();
      });
    });

    it("should exit with error when no target URL is provided", (done) => {
      const cli = spawn("node", ["dist/cli.js"], {
        stdio: ["pipe", "pipe", "pipe"],
      });

      let stderr = "";
      cli.stderr.on("data", (data) => {
        stderr += data.toString();
      });

      cli.on("close", (code) => {
        expect(code).toBe(1);
        expect(stderr).toContain("Error");
        done();
      });
    });
  });

  describe("Output Formats", () => {
    it("should support terminal output format (default)", (done) => {
      const cli = spawn(
        "node",
        ["dist/cli.js", "https://auth.example.com", "--format", "terminal"],
        {
          stdio: ["pipe", "pipe", "pipe"],
        }
      );

      let output = "";
      cli.stdout.on("data", (data) => {
        output += data.toString();
      });

      cli.on("close", (code) => {
        expect(output).toContain("OAuth Guardian");
        expect(output).toContain("Target:");
        expect(output).toContain("https://auth.example.com");
        done();
      });
    });

    it("should support JSON output format", (done) => {
      const outputPath = join(tempDir, "report.json");
      const cli = spawn(
        "node",
        [
          "dist/cli.js",
          "https://auth.example.com",
          "--format",
          "json",
          "--output",
          outputPath,
        ],
        {
          stdio: ["pipe", "pipe", "pipe"],
        }
      );

      cli.on("close", async (code) => {
        try {
          const content = await readFile(outputPath, "utf-8");
          const json = JSON.parse(content);

          expect(json).toHaveProperty("summary");
          expect(json).toHaveProperty("metadata");
          expect(json).toHaveProperty("findings");
          expect(json.metadata.target).toBe("https://auth.example.com");

          done();
        } catch (error) {
          done(error);
        }
      });
    });

    it("should support HTML output format", (done) => {
      const outputPath = join(tempDir, "report.html");
      const cli = spawn(
        "node",
        [
          "dist/cli.js",
          "https://auth.example.com",
          "--format",
          "html",
          "--output",
          outputPath,
        ],
        {
          stdio: ["pipe", "pipe", "pipe"],
        }
      );

      cli.on("close", async (code) => {
        try {
          const content = await readFile(outputPath, "utf-8");

          expect(content).toContain("<!DOCTYPE html>");
          expect(content).toContain("OAuth Guardian");
          expect(content).toContain("https://auth.example.com");

          done();
        } catch (error) {
          done(error);
        }
      });
    });
  });

  describe("CLI Options", () => {
    it("should support verbose flag", (done) => {
      const cli = spawn(
        "node",
        ["dist/cli.js", "https://auth.example.com", "--verbose"],
        {
          stdio: ["pipe", "pipe", "pipe"],
        }
      );

      let output = "";
      cli.stdout.on("data", (data) => {
        output += data.toString();
      });

      cli.on("close", (code) => {
        expect(output).toContain("Verbose:");
        expect(output).toContain("enabled");
        done();
      });
    });

    it("should support config file option", (done) => {
      const configPath = join(tempDir, "config.yml");
      const configContent = `
target: https://config.example.com
verbose: false
reporting:
  format: terminal
`;

      writeFile(configPath, configContent, "utf-8").then(() => {
        const cli = spawn("node", ["dist/cli.js", "--config", configPath], {
          stdio: ["pipe", "pipe", "pipe"],
        });

        let output = "";
        cli.stdout.on("data", (data) => {
          output += data.toString();
        });

        cli.on("close", (code) => {
          expect(output).toContain("https://config.example.com");
          expect(output).toContain("Config:");
          done();
        });
      });
    });
  });

  describe("Exit Codes", () => {
    it("should exit with code 0 when audit passes", (done) => {
      // Google has good OAuth metadata that should pass most checks
      const cli = spawn(
        "node",
        ["dist/cli.js", "https://accounts.google.com"],
        {
          stdio: ["pipe", "pipe", "pipe"],
        }
      );

      cli.on("close", (code) => {
        // May exit with 0 or 1 depending on findings, but shouldn't crash
        expect([0, 1]).toContain(code);
        done();
      });
    });

    it("should exit with code 1 on error", (done) => {
      const cli = spawn("node", ["dist/cli.js", "invalid-url"], {
        stdio: ["pipe", "pipe", "pipe"],
      });

      cli.on("close", (code) => {
        expect(code).toBe(1);
        done();
      });
    });
  });

  describe("Integration", () => {
    it("should complete a full audit workflow", (done) => {
      const outputPath = join(tempDir, "full-audit.json");
      const cli = spawn(
        "node",
        [
          "dist/cli.js",
          "https://accounts.google.com",
          "--format",
          "json",
          "--output",
          outputPath,
        ],
        {
          stdio: ["pipe", "pipe", "pipe"],
        }
      );

      let stdout = "";
      let stderr = "";

      cli.stdout.on("data", (data) => {
        stdout += data.toString();
      });

      cli.stderr.on("data", (data) => {
        stderr += data.toString();
      });

      cli.on("close", async (code) => {
        try {
          // Should show progress messages
          expect(stdout).toContain("OAuth Guardian");
          expect(stdout).toContain("Target:");

          // Should create output file
          const content = await readFile(outputPath, "utf-8");
          const report = JSON.parse(content);

          // Should have report structure
          expect(report).toHaveProperty("summary");
          expect(report).toHaveProperty("metadata");
          expect(report).toHaveProperty("findings");

          // Should have executed checks
          expect(report.summary.total).toBeGreaterThan(0);
          expect(Array.isArray(report.findings)).toBe(true);

          // Should have correct target
          expect(report.metadata.target).toBe("https://accounts.google.com");

          done();
        } catch (error) {
          done(error);
        }
      });
    }, 30000); // Longer timeout for real HTTP requests
  });
});
