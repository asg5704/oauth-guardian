import { describe, it, expect, beforeEach } from 'vitest';
import { StateParameterCheck } from '../../src/checks/oauth/state.js';
import { HttpClient, type OAuthMetadata } from '../../src/auditor/http-client.js';
import { CheckContext, CheckStatus, Severity } from '../../src/types/index.js';
import MockAdapter from 'axios-mock-adapter';
import axios from 'axios';

describe('StateParameterCheck', () => {
  let mock: MockAdapter;
  let httpClient: HttpClient;
  let check: StateParameterCheck;
  let context: CheckContext;

  beforeEach(() => {
    mock = new MockAdapter(axios);
    httpClient = new HttpClient({ timeout: 5000, userAgent: 'Test-Agent' });
    check = new StateParameterCheck();
    context = {
      targetUrl: 'https://example.com',
      config: {},
      httpClient,
    };
  });

  describe('check properties', () => {
    it('should have correct check metadata', () => {
      expect(check.id).toBe('oauth-state-parameter');
      expect(check.name).toBe('State Parameter Implementation Check');
      expect(check.category).toBe('oauth');
      expect(check.defaultSeverity).toBe(Severity.HIGH);
      expect(check.description).toContain('state parameter');
    });
  });

  describe('execute() - PASS scenarios', () => {
    it('should pass when OAuth metadata is discovered', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.message).toContain('OAuth metadata discovered');
      expect(result.message).toContain('State parameter');
      expect(result.message).toContain('CSRF protection');
      expect(result.metadata).toHaveProperty('issuer', 'https://example.com');
      expect(result.metadata).toHaveProperty('authorization_endpoint');
      expect(result.metadata).toHaveProperty('note');
      expect(result.metadata).toHaveProperty('recommendation');
    });

    it('should pass with guidance note about client-side responsibility', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/authorize',
        token_endpoint: 'https://auth.example.com/token',
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.metadata?.note).toContain('client-side responsibility');
      expect(result.metadata?.recommendation).toContain('state parameter');
    });

    it('should discover metadata from OIDC endpoint if OAuth fails', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(404);

      mock
        .onGet('https://example.com/.well-known/openid-configuration')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.message).toContain('OAuth metadata discovered');
    });
  });

  describe('execute() - WARNING scenarios', () => {
    it('should warn when metadata endpoints are not found', async () => {
      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(404);

      mock
        .onGet('https://example.com/.well-known/openid-configuration')
        .reply(404);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).toContain('Unable to discover OAuth metadata');
      expect(result.message).toContain('Could not verify state parameter support');
      expect(result.message).toContain('Attempted endpoints:');
      expect(result.message).toContain('/.well-known/oauth-authorization-server');
      expect(result.message).toContain('/.well-known/openid-configuration');
      expect(result.message).toContain('404 Not Found');
      expect(result.remediation).toContain('state parameter');
      expect(result.remediation).toContain('CSRF');
      expect(result.remediation).toContain('crypto.randomBytes');
      expect(result.metadata).toHaveProperty('attempts');
      expect(result.metadata?.attempts).toHaveLength(2);
    });

    it('should provide detailed remediation for state parameter implementation', async () => {
      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(404);

      mock
        .onGet('https://example.com/.well-known/openid-configuration')
        .reply(404);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.remediation).toContain('cryptographically random');
      expect(result.remediation).toContain('session');
      expect(result.remediation).toContain('Validate');
      expect(result.remediation).toContain('RFC 6749');
    });

    it('should warn with different HTTP status codes', async () => {
      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(403);

      mock
        .onGet('https://example.com/.well-known/openid-configuration')
        .reply(500);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).toContain('403 Forbidden');
      expect(result.message).toContain('500 Internal Server Error');
    });
  });

  describe('execute() - ERROR scenarios', () => {
    it('should error when HTTP client is not available', async () => {
      const contextWithoutClient: CheckContext = {
        targetUrl: 'https://example.com',
        config: {},
        // No httpClient
      };

      const result = await check.run(contextWithoutClient);

      expect(result.status).toBe(CheckStatus.ERROR);
      expect(result.message).toBe('HTTP client not available in context');
    });

    it('should warn when network error occurs', async () => {
      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .networkError();

      const result = await check.run(context);

      // Network errors are handled gracefully and return a warning
      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).toContain('Unable to discover OAuth metadata');
    });
  });

  describe('execution timing', () => {
    it('should measure execution time', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.executionTime).toBeGreaterThanOrEqual(0);
      expect(typeof result.executionTime).toBe('number');
    });

    it('should set timestamp', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const before = new Date();
      const result = await check.run(context);
      const after = new Date();

      expect(result.timestamp.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(result.timestamp.getTime()).toBeLessThanOrEqual(after.getTime());
    });
  });

  describe('logging', () => {
    it('should call logger when available', async () => {
      const logs: string[] = [];
      const contextWithLogger: CheckContext = {
        targetUrl: 'https://example.com',
        config: {},
        httpClient,
        logger: {
          debug: (msg: string) => logs.push(msg),
          info: () => {},
          warn: () => {},
          error: () => {},
        },
      };

      const mockMetadata: OAuthMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      await check.run(contextWithLogger);

      expect(logs.some((log) => log.includes('Discovering OAuth metadata'))).toBe(true);
      expect(logs.some((log) => log.includes('state parameter'))).toBe(true);
    });
  });
});
