import { describe, it, expect, beforeEach } from 'vitest';
import { AuditEngine } from '../../../src/auditor/engine.js';
import { BaseCheck } from '../../../src/checks/base-check.js';
import {
  AuditorConfig,
  CheckResult,
  CheckContext,
  CheckCategory,
  Severity,
  CheckStatus,
} from '../../../src/types/index.js';

// Test check implementations
class PassingCheck extends BaseCheck {
  readonly id = 'test-pass';
  readonly name = 'Passing Check';
  readonly category = CheckCategory.OAUTH;
  readonly defaultSeverity = Severity.LOW;
  readonly description = 'A check that passes';

  async execute(_context: CheckContext): Promise<CheckResult> {
    return this.pass('Everything is good');
  }
}

class FailingCheck extends BaseCheck {
  readonly id = 'test-fail';
  readonly name = 'Failing Check';
  readonly category = CheckCategory.OAUTH;
  readonly defaultSeverity = Severity.CRITICAL;
  readonly description = 'A check that fails';

  async execute(_context: CheckContext): Promise<CheckResult> {
    return this.fail('Critical issue found', Severity.CRITICAL, 'Fix it now');
  }
}

class WarningCheck extends BaseCheck {
  readonly id = 'test-warning';
  readonly name = 'Warning Check';
  readonly category = CheckCategory.NIST;
  readonly defaultSeverity = Severity.MEDIUM;
  readonly description = 'A check that warns';

  async execute(_context: CheckContext): Promise<CheckResult> {
    return this.warning('Potential issue detected', 'Consider fixing this');
  }
}

class SkippedCheck extends BaseCheck {
  readonly id = 'test-skipped';
  readonly name = 'Skipped Check';
  readonly category = CheckCategory.OWASP;
  readonly defaultSeverity = Severity.LOW;
  readonly description = 'A check that skips';

  async execute(_context: CheckContext): Promise<CheckResult> {
    return this.skip('Not applicable');
  }
}

class ErrorThrowingCheck extends BaseCheck {
  readonly id = 'test-error';
  readonly name = 'Error Check';
  readonly category = CheckCategory.CUSTOM;
  readonly defaultSeverity = Severity.HIGH;
  readonly description = 'A check that throws';

  async execute(_context: CheckContext): Promise<CheckResult> {
    throw new Error('Unexpected error');
  }
}

class HighSeverityCheck extends BaseCheck {
  readonly id = 'test-high';
  readonly name = 'High Severity Check';
  readonly category = CheckCategory.OAUTH;
  readonly defaultSeverity = Severity.HIGH;
  readonly description = 'A high severity check';

  async execute(_context: CheckContext): Promise<CheckResult> {
    return this.fail('High severity issue', Severity.HIGH, 'Fix this');
  }
}

class MediumSeverityCheck extends BaseCheck {
  readonly id = 'test-medium';
  readonly name = 'Medium Severity Check';
  readonly category = CheckCategory.OAUTH;
  readonly defaultSeverity = Severity.MEDIUM;
  readonly description = 'A medium severity check';

  async execute(_context: CheckContext): Promise<CheckResult> {
    return this.fail('Medium severity issue', Severity.MEDIUM, 'Fix this');
  }
}

describe('AuditEngine', () => {
  let config: AuditorConfig;

  beforeEach(() => {
    config = {
      target: 'https://example.com',
      timeout: 5000,
      verbose: false,
    };
  });

  describe('constructor', () => {
    it('should create engine with valid config', () => {
      const engine = new AuditEngine(config);
      expect(engine).toBeInstanceOf(AuditEngine);
    });

    it('should create engine with custom user agent', () => {
      const customConfig = {
        ...config,
        userAgent: 'Custom-Agent/1.0',
      };
      const engine = new AuditEngine(customConfig);
      expect(engine).toBeInstanceOf(AuditEngine);
    });
  });

  describe('registerCheck()', () => {
    it('should register a single check', async () => {
      const engine = new AuditEngine(config);
      engine.registerCheck(new PassingCheck());

      const report = await engine.run();

      expect(report.results).toHaveLength(1);
      expect(report.results[0].id).toBe('test-pass');
    });

    it('should register multiple checks individually', async () => {
      const engine = new AuditEngine(config);
      engine.registerCheck(new PassingCheck());
      engine.registerCheck(new FailingCheck());

      const report = await engine.run();

      expect(report.results).toHaveLength(2);
    });
  });

  describe('registerChecks()', () => {
    it('should register multiple checks at once', async () => {
      const engine = new AuditEngine(config);
      engine.registerChecks([new PassingCheck(), new FailingCheck(), new WarningCheck()]);

      const report = await engine.run();

      expect(report.results).toHaveLength(3);
    });
  });

  describe('run()', () => {
    it('should execute all registered checks', async () => {
      const engine = new AuditEngine(config);
      engine.registerChecks([
        new PassingCheck(),
        new FailingCheck(),
        new WarningCheck(),
        new SkippedCheck(),
      ]);

      const report = await engine.run();

      expect(report.results).toHaveLength(4);
      expect(report.summary.totalChecks).toBe(4);
      expect(report.summary.passed).toBe(1);
      expect(report.summary.failed).toBe(1);
      expect(report.summary.warnings).toBe(1);
      expect(report.summary.skipped).toBe(1);
    });

    it('should handle errors gracefully', async () => {
      const engine = new AuditEngine(config);
      engine.registerChecks([new PassingCheck(), new ErrorThrowingCheck()]);

      const report = await engine.run();

      expect(report.results).toHaveLength(2);
      expect(report.summary.passed).toBe(1);
      expect(report.summary.errors).toBe(1);

      const errorResult = report.results.find((r) => r.id === 'test-error');
      expect(errorResult).toBeDefined();
      expect(errorResult?.status).toBe(CheckStatus.ERROR);
      expect(errorResult?.message).toContain('Check execution failed');
    });

    it('should measure execution time', async () => {
      const engine = new AuditEngine(config);
      engine.registerCheck(new PassingCheck());

      const report = await engine.run();

      expect(report.metadata.executionTime).toBeGreaterThanOrEqual(0);
      expect(typeof report.metadata.executionTime).toBe('number');
    });

    it('should set start and end times', async () => {
      const engine = new AuditEngine(config);
      engine.registerCheck(new PassingCheck());

      const before = new Date();
      const report = await engine.run();
      const after = new Date();

      expect(report.metadata.startTime.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(report.metadata.endTime.getTime()).toBeLessThanOrEqual(after.getTime());
      expect(report.metadata.endTime.getTime()).toBeGreaterThanOrEqual(
        report.metadata.startTime.getTime()
      );
    });
  });

  describe('check filtering', () => {
    it('should filter by included checks', async () => {
      const configWithInclude = {
        ...config,
        checks: {
          include: ['test-pass', 'test-fail'],
        },
      };

      const engine = new AuditEngine(configWithInclude);
      engine.registerChecks([
        new PassingCheck(),
        new FailingCheck(),
        new WarningCheck(),
        new SkippedCheck(),
      ]);

      const report = await engine.run();

      expect(report.results).toHaveLength(2);
      expect(report.results.map((r) => r.id)).toEqual(['test-pass', 'test-fail']);
    });

    it('should filter by excluded checks', async () => {
      const configWithExclude = {
        ...config,
        checks: {
          exclude: ['test-warning', 'test-skipped'],
        },
      };

      const engine = new AuditEngine(configWithExclude);
      engine.registerChecks([
        new PassingCheck(),
        new FailingCheck(),
        new WarningCheck(),
        new SkippedCheck(),
      ]);

      const report = await engine.run();

      expect(report.results).toHaveLength(2);
      expect(report.results.map((r) => r.id)).toEqual(['test-pass', 'test-fail']);
    });

    it('should filter by categories', async () => {
      const configWithCategories = {
        ...config,
        checks: {
          categories: [CheckCategory.OAUTH, CheckCategory.NIST],
        },
      };

      const engine = new AuditEngine(configWithCategories);
      engine.registerChecks([
        new PassingCheck(), // OAUTH
        new FailingCheck(), // OAUTH
        new WarningCheck(), // NIST
        new SkippedCheck(), // OWASP
      ]);

      const report = await engine.run();

      expect(report.results).toHaveLength(3);
      expect(report.results.every((r) =>
        r.category === CheckCategory.OAUTH || r.category === CheckCategory.NIST
      )).toBe(true);
    });

    it('should apply both include and exclude filters', async () => {
      const configWithBoth = {
        ...config,
        checks: {
          include: ['test-pass', 'test-fail', 'test-warning'],
          exclude: ['test-warning'],
        },
      };

      const engine = new AuditEngine(configWithBoth);
      engine.registerChecks([
        new PassingCheck(),
        new FailingCheck(),
        new WarningCheck(),
        new SkippedCheck(),
      ]);

      const report = await engine.run();

      expect(report.results).toHaveLength(2);
      expect(report.results.map((r) => r.id)).toEqual(['test-pass', 'test-fail']);
    });
  });

  describe('summary generation', () => {
    it('should calculate compliance percentage correctly', async () => {
      const engine = new AuditEngine(config);
      engine.registerChecks([
        new PassingCheck(),
        new PassingCheck(),
        new FailingCheck(),
      ]);

      const report = await engine.run();

      // 2 passed out of 3 total = 67% (rounded)
      expect(report.summary.compliancePercentage).toBe(67);
    });

    it('should exclude skipped and errors from compliance calculation', async () => {
      const engine = new AuditEngine(config);
      engine.registerChecks([
        new PassingCheck(),
        new FailingCheck(),
        new SkippedCheck(),
        new ErrorThrowingCheck(),
      ]);

      const report = await engine.run();

      // 1 passed out of 2 relevant (excluding skipped and error) = 50%
      expect(report.summary.compliancePercentage).toBe(50);
    });

    it('should calculate risk score based on severity weights', async () => {
      const engine = new AuditEngine(config);
      engine.registerChecks([
        new FailingCheck(), // CRITICAL (weight: 10)
        new HighSeverityCheck(), // HIGH (weight: 5)
        new MediumSeverityCheck(), // MEDIUM (weight: 3)
      ]);

      const report = await engine.run();

      // (1*10 + 1*5 + 1*3) * 2 = 36
      expect(report.summary.riskScore).toBe(36);
    });

    it('should cap risk score at 100', async () => {
      const engine = new AuditEngine(config);
      // Register many critical failures to exceed 100
      const criticalChecks = Array(20).fill(null).map(() => new FailingCheck());
      engine.registerChecks(criticalChecks);

      const report = await engine.run();

      expect(report.summary.riskScore).toBe(100);
    });

    it('should count checks by severity', async () => {
      const engine = new AuditEngine(config);
      engine.registerChecks([
        new FailingCheck(), // CRITICAL
        new HighSeverityCheck(), // HIGH
        new MediumSeverityCheck(), // MEDIUM
      ]);

      const report = await engine.run();

      expect(report.summary.bySeverity[Severity.CRITICAL]).toBe(1);
      expect(report.summary.bySeverity[Severity.HIGH]).toBe(1);
      expect(report.summary.bySeverity[Severity.MEDIUM]).toBe(1);
      expect(report.summary.bySeverity[Severity.LOW]).toBe(0);
      expect(report.summary.bySeverity[Severity.INFO]).toBe(0);
    });

    it('should count checks by category', async () => {
      const engine = new AuditEngine(config);
      engine.registerChecks([
        new PassingCheck(), // OAUTH
        new FailingCheck(), // OAUTH
        new WarningCheck(), // NIST
        new SkippedCheck(), // OWASP
        new ErrorThrowingCheck(), // CUSTOM
      ]);

      const report = await engine.run();

      expect(report.summary.byCategory[CheckCategory.OAUTH]).toBe(2);
      expect(report.summary.byCategory[CheckCategory.NIST]).toBe(1);
      expect(report.summary.byCategory[CheckCategory.OWASP]).toBe(1);
      expect(report.summary.byCategory[CheckCategory.CUSTOM]).toBe(1);
    });
  });

  describe('findings generation', () => {
    it('should include only failed and warning checks', async () => {
      const engine = new AuditEngine(config);
      engine.registerChecks([
        new PassingCheck(),
        new FailingCheck(),
        new WarningCheck(),
        new SkippedCheck(),
      ]);

      const report = await engine.run();

      expect(report.findings).toHaveLength(2);
      expect(report.findings[0].check.id).toBe('test-fail');
      expect(report.findings[1].check.id).toBe('test-warning');
    });

    it('should return empty findings for all passing checks', async () => {
      const engine = new AuditEngine(config);
      engine.registerChecks([new PassingCheck(), new PassingCheck()]);

      const report = await engine.run();

      expect(report.findings).toHaveLength(0);
    });
  });

  describe('compliance scorecard', () => {
    it('should generate scorecard by category', async () => {
      const engine = new AuditEngine(config);
      engine.registerChecks([
        new PassingCheck(), // OAUTH - pass
        new FailingCheck(), // OAUTH - fail
        new WarningCheck(), // NIST - warning
      ]);

      const report = await engine.run();

      expect(report.compliance).toHaveLength(2); // OAUTH and NIST

      const oauthScorecard = report.compliance.find((s) => s.category === CheckCategory.OAUTH);
      expect(oauthScorecard).toBeDefined();
      expect(oauthScorecard?.totalChecks).toBe(2);
      expect(oauthScorecard?.passed).toBe(1);
      expect(oauthScorecard?.failed).toBe(1);
      expect(oauthScorecard?.compliancePercentage).toBe(50);
      expect(oauthScorecard?.compliant).toBe(false);

      const nistScorecard = report.compliance.find((s) => s.category === CheckCategory.NIST);
      expect(nistScorecard).toBeDefined();
      expect(nistScorecard?.totalChecks).toBe(1);
      expect(nistScorecard?.passed).toBe(0); // warnings don't count as passed
      expect(nistScorecard?.failed).toBe(0);
    });

    it('should mark scorecard as compliant when no failures', async () => {
      const engine = new AuditEngine(config);
      engine.registerChecks([new PassingCheck(), new PassingCheck()]);

      const report = await engine.run();

      expect(report.compliance).toHaveLength(1);
      expect(report.compliance[0].compliant).toBe(true);
      expect(report.compliance[0].failed).toBe(0);
      expect(report.compliance[0].compliancePercentage).toBe(100);
    });
  });

  describe('hasFailures()', () => {
    it('should detect critical failures', async () => {
      const engine = new AuditEngine(config);
      engine.registerChecks([new PassingCheck(), new FailingCheck()]); // FailingCheck is CRITICAL

      const report = await engine.run();
      const hasCritical = engine.hasFailures(report, Severity.CRITICAL);

      expect(hasCritical).toBe(true);
    });

    it('should not detect failures below threshold', async () => {
      const engine = new AuditEngine(config);
      engine.registerChecks([new PassingCheck(), new MediumSeverityCheck()]);

      const report = await engine.run();
      const hasCritical = engine.hasFailures(report, Severity.CRITICAL);

      expect(hasCritical).toBe(false);
    });

    it('should detect high severity when threshold is high', async () => {
      const engine = new AuditEngine(config);
      engine.registerChecks([new PassingCheck(), new HighSeverityCheck()]);

      const report = await engine.run();
      const hasHigh = engine.hasFailures(report, Severity.HIGH);

      expect(hasHigh).toBe(true);
    });

    it('should detect high severity when threshold is medium', async () => {
      const engine = new AuditEngine(config);
      engine.registerChecks([new PassingCheck(), new HighSeverityCheck()]);

      const report = await engine.run();
      const hasMediumOrAbove = engine.hasFailures(report, Severity.MEDIUM);

      expect(hasMediumOrAbove).toBe(true);
    });

    it('should return false when no failures exist', async () => {
      const engine = new AuditEngine(config);
      engine.registerChecks([new PassingCheck(), new PassingCheck()]);

      const report = await engine.run();
      const hasFailures = engine.hasFailures(report, Severity.LOW);

      expect(hasFailures).toBe(false);
    });
  });

  describe('report metadata', () => {
    it('should include target URL', async () => {
      const engine = new AuditEngine(config);
      engine.registerCheck(new PassingCheck());

      const report = await engine.run();

      expect(report.metadata.targetUrl).toBe('https://example.com');
    });

    it('should include version', async () => {
      const engine = new AuditEngine(config);
      engine.registerCheck(new PassingCheck());

      const report = await engine.run();

      expect(report.metadata.version).toBe('0.1.0');
    });

    it('should include config', async () => {
      const engine = new AuditEngine(config);
      engine.registerCheck(new PassingCheck());

      const report = await engine.run();

      expect(report.metadata.config).toBeDefined();
      expect(report.metadata.config.target).toBe('https://example.com');
    });
  });
});
