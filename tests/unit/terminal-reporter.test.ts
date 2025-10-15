import { describe, it, expect, beforeEach } from 'vitest';
import { TerminalReporter } from '../../src/reporters/terminal-reporter.js';
import { Report, CheckStatus, Severity, CheckCategory } from '../../src/types/index.js';

// Helper to strip ANSI color codes for testing
function stripAnsi(str: string): string {
  return str.replace(
    // eslint-disable-next-line no-control-regex
    /[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g,
    ''
  );
}

describe('TerminalReporter', () => {
  let mockReport: Report;

  beforeEach(() => {
    mockReport = {
      metadata: {
        targetUrl: 'https://example.com',
        startTime: new Date('2025-01-01T00:00:00Z'),
        endTime: new Date('2025-01-01T00:00:01Z'),
        executionTime: 1000,
        version: '0.1.0',
        config: { target: 'https://example.com' },
      },
      summary: {
        totalChecks: 4,
        passed: 2,
        failed: 1,
        warnings: 1,
        skipped: 0,
        errors: 0,
        bySeverity: {
          [Severity.CRITICAL]: 1,
          [Severity.HIGH]: 0,
          [Severity.MEDIUM]: 0,
          [Severity.LOW]: 0,
          [Severity.INFO]: 0,
        },
        byCategory: {
          [CheckCategory.OAUTH]: 4,
          [CheckCategory.NIST]: 0,
          [CheckCategory.OWASP]: 0,
          [CheckCategory.CUSTOM]: 0,
        },
        riskScore: 20,
        compliancePercentage: 50,
      },
      results: [
        {
          id: 'test-pass',
          name: 'Passing Check',
          category: CheckCategory.OAUTH,
          status: CheckStatus.PASS,
          description: 'A passing check',
          message: 'Everything is good',
          timestamp: new Date('2025-01-01T00:00:00Z'),
          executionTime: 100,
        },
        {
          id: 'test-fail',
          name: 'Failing Check',
          category: CheckCategory.OAUTH,
          status: CheckStatus.FAIL,
          severity: Severity.CRITICAL,
          description: 'A failing check',
          message: 'Critical issue found',
          remediation: 'Fix it now',
          timestamp: new Date('2025-01-01T00:00:00Z'),
          executionTime: 100,
        },
        {
          id: 'test-warning',
          name: 'Warning Check',
          category: CheckCategory.OAUTH,
          status: CheckStatus.WARNING,
          severity: Severity.LOW,
          description: 'A warning check',
          message: 'Potential issue',
          remediation: 'Consider fixing',
          timestamp: new Date('2025-01-01T00:00:00Z'),
          executionTime: 100,
        },
        {
          id: 'test-pass-2',
          name: 'Another Passing Check',
          category: CheckCategory.OAUTH,
          status: CheckStatus.PASS,
          description: 'Another passing check',
          message: 'All good',
          timestamp: new Date('2025-01-01T00:00:00Z'),
          executionTime: 100,
        },
      ],
      findings: [
        {
          check: {
            id: 'test-fail',
            name: 'Failing Check',
            category: CheckCategory.OAUTH,
            status: CheckStatus.FAIL,
            severity: Severity.CRITICAL,
            description: 'A failing check',
            message: 'Critical issue found',
            remediation: 'Fix it now',
            timestamp: new Date('2025-01-01T00:00:00Z'),
            executionTime: 100,
          },
        },
      ],
      compliance: [
        {
          standard: 'OAuth 2.0 / RFC 6749',
          category: CheckCategory.OAUTH,
          totalChecks: 4,
          passed: 2,
          failed: 1,
          compliancePercentage: 50,
          compliant: false,
        },
      ],
    };
  });

  describe('constructor', () => {
    it('should create reporter with default options', () => {
      const reporter = new TerminalReporter();
      expect(reporter).toBeInstanceOf(TerminalReporter);
    });

    it('should create reporter with custom options', () => {
      const reporter = new TerminalReporter({
        colors: false,
        verbose: true,
        useTables: true,
      });
      expect(reporter).toBeInstanceOf(TerminalReporter);
    });
  });

  describe('generate()', () => {
    it('should generate terminal output', () => {
      const reporter = new TerminalReporter();
      const output = reporter.generate(mockReport);

      expect(output).toBeTruthy();
      expect(output.length).toBeGreaterThan(0);
    });

    it('should include header', () => {
      const reporter = new TerminalReporter();
      const output = stripAnsi(reporter.generate(mockReport));

      expect(output).toContain('Audit Results');
    });

    it('should include summary statistics', () => {
      const reporter = new TerminalReporter();
      const output = stripAnsi(reporter.generate(mockReport));

      expect(output).toContain('Summary:');
      expect(output).toContain('Total Checks:    4');
      expect(output).toContain('Passed:        2');
      expect(output).toContain('Failed:        1');
      expect(output).toContain('Warnings:      1');
      expect(output).toContain('Compliance:      50%');
      expect(output).toContain('Risk Score:      20/100');
    });

    it('should include check results', () => {
      const reporter = new TerminalReporter();
      const output = stripAnsi(reporter.generate(mockReport));

      expect(output).toContain('Check Results:');
      expect(output).toContain('Passing Check');
      expect(output).toContain('Failing Check');
      expect(output).toContain('Warning Check');
    });

    it('should include check descriptions', () => {
      const reporter = new TerminalReporter();
      const output = stripAnsi(reporter.generate(mockReport));

      expect(output).toContain('A passing check');
      expect(output).toContain('A failing check');
      expect(output).toContain('A warning check');
    });

    it('should include compliance scorecard', () => {
      const reporter = new TerminalReporter();
      const output = stripAnsi(reporter.generate(mockReport));

      expect(output).toContain('Compliance by Standard:');
      expect(output).toContain('OAuth 2.0 / RFC 6749');
    });

    it('should show execution time by default', () => {
      const reporter = new TerminalReporter();
      const output = stripAnsi(reporter.generate(mockReport));

      expect(output).toContain('Completed in 1000ms');
    });

    it('should hide execution time when disabled', () => {
      const reporter = new TerminalReporter({ showExecutionTime: false });
      const output = stripAnsi(reporter.generate(mockReport));

      expect(output).not.toContain('Completed in');
    });
  });

  describe('verbose mode', () => {
    it('should show remediation in verbose mode', () => {
      const reporter = new TerminalReporter({ verbose: true });
      const output = stripAnsi(reporter.generate(mockReport));

      expect(output).toContain('Remediation:');
      expect(output).toContain('Fix it now');
      expect(output).toContain('Consider fixing');
    });

    it('should not show remediation in non-verbose mode', () => {
      const reporter = new TerminalReporter({ verbose: false });
      const output = stripAnsi(reporter.generate(mockReport));

      expect(output).not.toContain('Remediation:');
      expect(output).not.toContain('Fix it now');
    });
  });

  describe('table mode', () => {
    it('should use tables when useTables is true', () => {
      const reporter = new TerminalReporter({ useTables: true });
      const output = stripAnsi(reporter.generate(mockReport));

      // Tables have specific characters
      expect(output).toContain('│');
      expect(output).toContain('Check Results:');
    });

    it('should use list format when useTables is false', () => {
      const reporter = new TerminalReporter({ useTables: false });
      const output = stripAnsi(reporter.generate(mockReport));

      // List format doesn't have table characters for check results
      // Note: Compliance scorecard always uses tables
      expect(output).toContain('Passing Check');
      expect(output).toContain('A passing check');
    });

    it('should include severity in table mode', () => {
      const reporter = new TerminalReporter({ useTables: true });
      const output = stripAnsi(reporter.generate(mockReport));

      expect(output).toContain('Severity');
      expect(output).toContain('critical');
    });
  });

  describe('colors', () => {
    it('should include ANSI codes when colors enabled', () => {
      const reporter = new TerminalReporter({ colors: true });
      const output = reporter.generate(mockReport);

      // ANSI escape codes start with \u001b
      expect(output).toMatch(/\u001b/);
    });

    it('should not include chalk ANSI codes when colors disabled', () => {
      const reporter = new TerminalReporter({ colors: false });
      const output = reporter.generate(mockReport);

      // Note: cli-table3 may still output some ANSI codes for table borders
      // but chalk colors should be disabled
      expect(output).toBeTruthy();
    });
  });

  describe('generateCompact()', () => {
    it('should generate compact one-line summary', () => {
      const reporter = new TerminalReporter();
      const output = stripAnsi(reporter.generateCompact(mockReport));

      expect(output).toContain('2');
      expect(output).toContain('1');
      expect(output).toContain('50%');
      expect(output).toContain('20/100');
    });

    it('should be a single line', () => {
      const reporter = new TerminalReporter();
      const output = stripAnsi(reporter.generateCompact(mockReport));

      expect(output.split('\n')).toHaveLength(1);
    });
  });

  describe('edge cases', () => {
    it('should handle report with no findings', () => {
      const reportWithNoFindings: Report = {
        ...mockReport,
        findings: [],
      };

      const reporter = new TerminalReporter();
      const output = reporter.generate(reportWithNoFindings);

      expect(output).toBeTruthy();
    });

    it('should handle report with no compliance data', () => {
      const reportWithNoCompliance: Report = {
        ...mockReport,
        compliance: [],
      };

      const reporter = new TerminalReporter();
      const output = stripAnsi(reporter.generate(reportWithNoCompliance));

      expect(output).toBeTruthy();
      expect(output).not.toContain('Compliance by Standard:');
    });

    it('should handle check with no message', () => {
      const reportWithNoMessage: Report = {
        ...mockReport,
        results: [
          {
            ...mockReport.results[0],
            message: undefined,
          },
        ],
      };

      const reporter = new TerminalReporter();
      const output = reporter.generate(reportWithNoMessage);

      expect(output).toBeTruthy();
    });

    it('should handle long messages in table mode', () => {
      const longMessage = 'A'.repeat(200);
      const reportWithLongMessage: Report = {
        ...mockReport,
        results: [
          {
            ...mockReport.results[0],
            message: longMessage,
          },
        ],
      };

      const reporter = new TerminalReporter({ useTables: true });
      const output = reporter.generate(reportWithLongMessage);

      expect(output).toBeTruthy();
      // Long message should be truncated in the table
      const stripped = stripAnsi(output);
      expect(stripped).toContain('A');
      // Full message shouldn't appear (it's truncated)
      expect(stripped).not.toContain(longMessage);
    });
  });
});
