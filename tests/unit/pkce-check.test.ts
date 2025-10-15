import { describe, it, expect, beforeEach } from 'vitest';
import { PKCECheck } from '../../src/checks/oauth/pkce.js';
import { HttpClient, type OAuthMetadata } from '../../src/auditor/http-client.js';
import { CheckContext, CheckStatus, Severity } from '../../src/types/index.js';
import MockAdapter from 'axios-mock-adapter';
import axios from 'axios';

describe('PKCECheck', () => {
  let mock: MockAdapter;
  let httpClient: HttpClient;
  let check: PKCECheck;
  let context: CheckContext;

  beforeEach(() => {
    mock = new MockAdapter(axios);
    httpClient = new HttpClient({ timeout: 5000, userAgent: 'Test-Agent' });
    check = new PKCECheck();
    context = {
      targetUrl: 'https://example.com',
      config: {},
      httpClient,
    };
  });

  describe('check properties', () => {
    it('should have correct check metadata', () => {
      expect(check.id).toBe('oauth-pkce');
      expect(check.name).toBe('PKCE Implementation Check');
      expect(check.category).toBe('oauth');
      expect(check.defaultSeverity).toBe(Severity.HIGH);
      expect(check.description).toContain('PKCE');
    });
  });

  describe('execute() - PASS scenarios', () => {
    it('should pass when PKCE is supported with S256 method', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
        code_challenge_methods_supported: ['S256', 'plain'],
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.message).toContain('PKCE is properly supported with S256 method');
      expect(result.message).toContain('S256');
      expect(result.message).toContain('plain');
      expect(result.metadata).toHaveProperty('issuer', 'https://example.com');
      expect(result.metadata).toHaveProperty('supported_methods');
      expect(result.metadata?.supported_methods).toEqual(['S256', 'plain']);
    });

    it('should pass when only S256 is supported', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
        code_challenge_methods_supported: ['S256'],
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.metadata?.supported_methods).toEqual(['S256']);
    });

    it('should discover metadata from OIDC endpoint if OAuth fails', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
        code_challenge_methods_supported: ['S256'],
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(404);

      mock
        .onGet('https://example.com/.well-known/openid-configuration')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.message).toContain('PKCE is properly supported');
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
      expect(result.message).toContain('Could not verify PKCE support');
      expect(result.message).toContain('Attempted endpoints:');
      expect(result.message).toContain('/.well-known/oauth-authorization-server');
      expect(result.message).toContain('/.well-known/openid-configuration');
      expect(result.message).toContain('404 Not Found');
      expect(result.remediation).toContain('RFC 8414');
      expect(result.remediation).toContain('OpenID Connect Discovery');
      expect(result.metadata).toHaveProperty('attempts');
      expect(result.metadata?.attempts).toHaveLength(2);
    });

    it('should warn when PKCE is supported but S256 is not available', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
        code_challenge_methods_supported: ['plain'],
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).toContain('PKCE is supported');
      expect(result.message).toContain('S256 method is not available');
      expect(result.message).toContain('Supported methods: plain');
      expect(result.remediation).toContain('Add S256 (SHA-256) support');
      expect(result.remediation).toContain("'plain' method is less secure");
      expect(result.metadata).toHaveProperty('issuer');
      expect(result.metadata).toHaveProperty('supported_methods');
      expect(result.metadata?.supported_methods).toEqual(['plain']);
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

  describe('execute() - FAIL scenarios', () => {
    it('should fail when PKCE is not supported at all', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
        // No code_challenge_methods_supported field
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.FAIL);
      expect(result.severity).toBe(Severity.HIGH);
      expect(result.message).toContain('PKCE is not supported');
      expect(result.message).toContain('does not advertise code_challenge_methods_supported');
      expect(result.remediation).toContain('To implement PKCE');
      expect(result.remediation).toContain('code_challenge');
      expect(result.remediation).toContain('code_verifier');
      expect(result.remediation).toContain('RFC 7636');
      expect(result.metadata).toHaveProperty('issuer');
      expect(result.metadata).toHaveProperty('authorization_endpoint');
      expect(result.metadata).toHaveProperty('token_endpoint');
    });

    it('should fail when code_challenge_methods_supported is empty array', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
        code_challenge_methods_supported: [],
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.FAIL);
      expect(result.severity).toBe(Severity.HIGH);
    });

    it('should fail when code_challenge_methods_supported is not an array', async () => {
      const mockMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
        code_challenge_methods_supported: 'S256', // Invalid: should be array
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.FAIL);
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
        code_challenge_methods_supported: ['S256'],
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
        code_challenge_methods_supported: ['S256'],
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
        code_challenge_methods_supported: ['S256'],
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      await check.run(contextWithLogger);

      expect(logs.some((log) => log.includes('Discovering OAuth metadata'))).toBe(true);
      expect(logs.some((log) => log.includes('PKCE check passed'))).toBe(true);
    });
  });
});
