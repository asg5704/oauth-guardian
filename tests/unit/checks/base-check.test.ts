import { describe, it, expect } from 'vitest';
import { BaseCheck } from '../../../src/checks/base-check.js';
import {
  CheckResult,
  CheckCategory,
  Severity,
  CheckContext,
  CheckStatus,
} from '../../../src/types/index.js';

// Create a concrete implementation for testing
class TestCheck extends BaseCheck {
  readonly id = 'test-check';
  readonly name = 'Test Check';
  readonly category = CheckCategory.OAUTH;
  readonly defaultSeverity = Severity.HIGH;
  readonly description = 'A test check for unit testing';

  async execute(context: CheckContext): Promise<CheckResult> {
    return this.pass('Test passed');
  }
}

class FailingCheck extends BaseCheck {
  readonly id = 'failing-check';
  readonly name = 'Failing Check';
  readonly category = CheckCategory.OAUTH;
  readonly defaultSeverity = Severity.CRITICAL;
  readonly description = 'A check that always fails';

  async execute(_context: CheckContext): Promise<CheckResult> {
    return this.fail('Test failed', Severity.CRITICAL, 'Fix the issue');
  }
}

class ErrorThrowingCheck extends BaseCheck {
  readonly id = 'error-check';
  readonly name = 'Error Check';
  readonly category = CheckCategory.OAUTH;
  readonly defaultSeverity = Severity.HIGH;
  readonly description = 'A check that throws an error';

  async execute(_context: CheckContext): Promise<CheckResult> {
    throw new Error('Something went wrong');
  }
}

describe('BaseCheck', () => {
  const mockContext: CheckContext = {
    targetUrl: 'https://example.com',
    config: {},
  };

  describe('pass()', () => {
    it('should create a passing check result', async () => {
      const check = new TestCheck();
      const result = await check.run(mockContext);

      expect(result.id).toBe('test-check');
      expect(result.name).toBe('Test Check');
      expect(result.category).toBe(CheckCategory.OAUTH);
      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.message).toBe('Test passed');
      expect(result.severity).toBeUndefined();
      expect(result.timestamp).toBeInstanceOf(Date);
      expect(result.executionTime).toBeGreaterThanOrEqual(0);
    });

    it('should include metadata when provided', async () => {
      class MetadataCheck extends BaseCheck {
        readonly id = 'metadata-check';
        readonly name = 'Metadata Check';
        readonly category = CheckCategory.OAUTH;
        readonly defaultSeverity = Severity.LOW;
        readonly description = 'Check with metadata';

        async execute(_context: CheckContext): Promise<CheckResult> {
          return this.pass('Passed with metadata', { foo: 'bar' });
        }
      }

      const check = new MetadataCheck();
      const result = await check.run(mockContext);

      expect(result.metadata).toEqual({ foo: 'bar' });
    });
  });

  describe('fail()', () => {
    it('should create a failing check result with default severity', async () => {
      const check = new FailingCheck();
      const result = await check.run(mockContext);

      expect(result.status).toBe(CheckStatus.FAIL);
      expect(result.severity).toBe(Severity.CRITICAL);
      expect(result.message).toBe('Test failed');
      expect(result.remediation).toBe('Fix the issue');
    });

    it('should use custom severity when provided', async () => {
      class CustomSeverityCheck extends BaseCheck {
        readonly id = 'custom-severity';
        readonly name = 'Custom Severity';
        readonly category = CheckCategory.OAUTH;
        readonly defaultSeverity = Severity.HIGH;
        readonly description = 'Check with custom severity';

        async execute(_context: CheckContext): Promise<CheckResult> {
          return this.fail('Failed', Severity.MEDIUM);
        }
      }

      const check = new CustomSeverityCheck();
      const result = await check.run(mockContext);

      expect(result.severity).toBe(Severity.MEDIUM);
    });
  });

  describe('warning()', () => {
    it('should create a warning check result', async () => {
      class WarningCheck extends BaseCheck {
        readonly id = 'warning-check';
        readonly name = 'Warning Check';
        readonly category = CheckCategory.OAUTH;
        readonly defaultSeverity = Severity.MEDIUM;
        readonly description = 'Check that warns';

        async execute(_context: CheckContext): Promise<CheckResult> {
          return this.warning('This is a warning', 'Consider fixing this');
        }
      }

      const check = new WarningCheck();
      const result = await check.run(mockContext);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.severity).toBe(Severity.LOW);
      expect(result.message).toBe('This is a warning');
      expect(result.remediation).toBe('Consider fixing this');
    });
  });

  describe('skip()', () => {
    it('should create a skipped check result', async () => {
      class SkippedCheck extends BaseCheck {
        readonly id = 'skipped-check';
        readonly name = 'Skipped Check';
        readonly category = CheckCategory.OAUTH;
        readonly defaultSeverity = Severity.LOW;
        readonly description = 'Check that skips';

        async execute(_context: CheckContext): Promise<CheckResult> {
          return this.skip('Not applicable');
        }
      }

      const check = new SkippedCheck();
      const result = await check.run(mockContext);

      expect(result.status).toBe(CheckStatus.SKIPPED);
      expect(result.message).toBe('Not applicable');
      expect(result.severity).toBeUndefined();
    });
  });

  describe('error()', () => {
    it('should create an error check result', async () => {
      class ErrorCheck extends BaseCheck {
        readonly id = 'error-check-manual';
        readonly name = 'Error Check Manual';
        readonly category = CheckCategory.OAUTH;
        readonly defaultSeverity = Severity.HIGH;
        readonly description = 'Check that returns error';

        async execute(_context: CheckContext): Promise<CheckResult> {
          return this.error('Manual error');
        }
      }

      const check = new ErrorCheck();
      const result = await check.run(mockContext);

      expect(result.status).toBe(CheckStatus.ERROR);
      expect(result.message).toBe('Manual error');
    });

    it('should handle thrown errors gracefully', async () => {
      const check = new ErrorThrowingCheck();
      const result = await check.run(mockContext);

      expect(result.status).toBe(CheckStatus.ERROR);
      expect(result.message).toBe('Check execution failed with an error');
      expect(result.metadata).toHaveProperty('error');
      expect(result.metadata?.error).toBe('Something went wrong');
    });
  });

  describe('run()', () => {
    it('should measure execution time', async () => {
      const check = new TestCheck();
      const result = await check.run(mockContext);

      expect(result.executionTime).toBeGreaterThanOrEqual(0);
      expect(typeof result.executionTime).toBe('number');
    });

    it('should set timestamp', async () => {
      const check = new TestCheck();
      const before = new Date();
      const result = await check.run(mockContext);
      const after = new Date();

      expect(result.timestamp.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(result.timestamp.getTime()).toBeLessThanOrEqual(after.getTime());
    });
  });

  describe('isValidUrl()', () => {
    class UrlValidationCheck extends BaseCheck {
      readonly id = 'url-check';
      readonly name = 'URL Check';
      readonly category = CheckCategory.OAUTH;
      readonly defaultSeverity = Severity.LOW;
      readonly description = 'URL validation check';

      async execute(_context: CheckContext): Promise<CheckResult> {
        return this.pass('OK');
      }

      testUrl(url: string): boolean {
        return this.isValidUrl(url);
      }
    }

    it('should validate HTTP URLs', () => {
      const check = new UrlValidationCheck();
      expect(check.testUrl('http://example.com')).toBe(true);
    });

    it('should validate HTTPS URLs', () => {
      const check = new UrlValidationCheck();
      expect(check.testUrl('https://example.com')).toBe(true);
    });

    it('should reject invalid URLs', () => {
      const check = new UrlValidationCheck();
      expect(check.testUrl('not-a-url')).toBe(false);
      expect(check.testUrl('ftp://example.com')).toBe(false);
      expect(check.testUrl('')).toBe(false);
    });
  });

  describe('log()', () => {
    it('should call logger debug when available', async () => {
      const logs: string[] = [];
      const contextWithLogger: CheckContext = {
        targetUrl: 'https://example.com',
        config: {},
        logger: {
          debug: (msg: string) => logs.push(msg),
          info: () => {},
          warn: () => {},
          error: () => {},
        },
      };

      class LoggingCheck extends BaseCheck {
        readonly id = 'logging-check';
        readonly name = 'Logging Check';
        readonly category = CheckCategory.OAUTH;
        readonly defaultSeverity = Severity.LOW;
        readonly description = 'Check that logs';

        async execute(context: CheckContext): Promise<CheckResult> {
          this.log(context, 'Test log message');
          return this.pass('OK');
        }
      }

      const check = new LoggingCheck();
      await check.run(contextWithLogger);

      expect(logs).toContain('[logging-check] Test log message');
    });
  });
});
