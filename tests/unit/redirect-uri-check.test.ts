import { describe, it, expect, beforeEach } from 'vitest';
import { RedirectURICheck } from '../../src/checks/oauth/redirect-uri.js';
import { HttpClient, type OAuthMetadata } from '../../src/auditor/http-client.js';
import { CheckContext, CheckStatus, Severity } from '../../src/types/index.js';
import MockAdapter from 'axios-mock-adapter';
import axios from 'axios';

describe('RedirectURICheck', () => {
  let mock: MockAdapter;
  let httpClient: HttpClient;
  let check: RedirectURICheck;
  let context: CheckContext;

  beforeEach(() => {
    mock = new MockAdapter(axios);
    httpClient = new HttpClient({ timeout: 5000, userAgent: 'Test-Agent' });
    check = new RedirectURICheck();
    context = {
      targetUrl: 'https://example.com',
      config: {},
      httpClient,
    };
  });

  describe('check properties', () => {
    it('should have correct check metadata', () => {
      expect(check.id).toBe('oauth-redirect-uri');
      expect(check.name).toBe('Redirect URI Validation Check');
      expect(check.category).toBe('oauth');
      expect(check.defaultSeverity).toBe(Severity.CRITICAL);
      expect(check.description).toContain('redirect URI');
    });
  });

  describe('execute() - PASS scenarios', () => {
    it('should pass when authorization endpoint is found', async () => {
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
      expect(result.message).toContain('Redirect URI validation');
      expect(result.metadata).toHaveProperty('issuer', 'https://example.com');
      expect(result.metadata).toHaveProperty('authorization_endpoint');
      expect(result.metadata).toHaveProperty('has_registration_endpoint', false);
      expect(result.metadata).toHaveProperty('recommendations');
    });

    it('should pass with registration endpoint support', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
        registration_endpoint: 'https://example.com/oauth/register',
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.message).toContain('dynamic client registration');
      expect(result.metadata).toHaveProperty('has_registration_endpoint', true);
      expect(result.metadata).toHaveProperty('registration_endpoint');
    });

    it('should include security recommendations in metadata', async () => {
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
      const recommendations = result.metadata?.recommendations as string[];
      expect(recommendations).toBeDefined();
      expect(recommendations.length).toBeGreaterThan(0);
      expect(recommendations.some((r: string) => r.includes('exact match'))).toBe(true);
      expect(recommendations.some((r: string) => r.includes('HTTPS'))).toBe(true);
      expect(recommendations.some((r: string) => r.includes('open redirect'))).toBe(true);
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
      expect(result.message).toContain('Could not verify redirect URI validation');
      expect(result.message).toContain('Attempted endpoints:');
      expect(result.message).toContain('404 Not Found');
      expect(result.remediation).toContain('Redirect URI');
      expect(result.remediation).toContain('exact');
      expect(result.remediation).toContain('HTTPS');
      expect(result.metadata).toHaveProperty('attempts');
    });

    it('should provide comprehensive remediation guidance', async () => {
      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(404);

      mock
        .onGet('https://example.com/.well-known/openid-configuration')
        .reply(404);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.remediation).toContain('Registration Phase');
      expect(result.remediation).toContain('Authorization Request');
      expect(result.remediation).toContain('Security Rules');
      expect(result.remediation).toContain('validateRedirectURI');
      expect(result.remediation).toContain('Open redirect');
      expect(result.remediation).toContain('RFC 6749');
    });
  });

  describe('execute() - FAIL scenarios', () => {
    it('should fail when no authorization endpoint is found', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'https://example.com',
        // Missing authorization_endpoint
        token_endpoint: 'https://example.com/oauth/token',
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.FAIL);
      expect(result.severity).toBe(Severity.HIGH);
      expect(result.message).toContain('No authorization endpoint');
      expect(result.message).toContain('Cannot validate redirect URI');
      expect(result.remediation).toContain('authorization_endpoint');
      expect(result.metadata).toHaveProperty('issuer');
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
      expect(logs.some((log) => log.includes('redirect URI'))).toBe(true);
    });
  });
});
