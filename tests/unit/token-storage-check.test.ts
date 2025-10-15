import { describe, it, expect, beforeEach } from 'vitest';
import { TokenStorageCheck } from '../../src/checks/oauth/token-storage.js';
import { HttpClient, type OAuthMetadata } from '../../src/auditor/http-client.js';
import { CheckContext, CheckStatus, Severity } from '../../src/types/index.js';
import MockAdapter from 'axios-mock-adapter';
import axios from 'axios';

describe('TokenStorageCheck', () => {
  let mock: MockAdapter;
  let httpClient: HttpClient;
  let check: TokenStorageCheck;
  let context: CheckContext;

  beforeEach(() => {
    mock = new MockAdapter(axios);
    httpClient = new HttpClient({ timeout: 5000, userAgent: 'Test-Agent' });
    check = new TokenStorageCheck();
    context = {
      targetUrl: 'https://example.com',
      config: {},
      httpClient,
    };
  });

  describe('check properties', () => {
    it('should have correct check metadata', () => {
      expect(check.id).toBe('oauth-token-storage');
      expect(check.name).toBe('Token Storage Security Check');
      expect(check.category).toBe('oauth');
      expect(check.defaultSeverity).toBe(Severity.HIGH);
      expect(check.description).toContain('token');
      expect(check.description).toContain('storage');
    });
  });

  describe('execute() - PASS scenarios', () => {
    it('should pass when token endpoint uses HTTPS', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.message).toContain('Token endpoint properly configured');
      expect(result.message).toContain('HTTPS');
      expect(result.metadata).toHaveProperty('issuer');
      expect(result.metadata).toHaveProperty('token_endpoint');
      expect(result.metadata).toHaveProperty('uses_https', true);
      expect(result.metadata).toHaveProperty('auth_methods');
      expect(result.metadata).toHaveProperty('client_storage_recommendations');
    });

    it('should pass with secure authentication methods', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
        token_endpoint_auth_methods_supported: ['private_key_jwt', 'client_secret_jwt'],
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.message).toContain('private_key_jwt');
      expect(result.message).toContain('client_secret_jwt');
    });

    it('should pass when no auth methods specified', async () => {
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
      expect(result.message).toContain('Ensure proper client authentication');
    });

    it('should allow HTTP for localhost', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'http://localhost:8080',
        authorization_endpoint: 'http://localhost:8080/oauth/authorize',
        token_endpoint: 'http://localhost:8080/oauth/token',
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.PASS);
      expect(result.metadata?.uses_https).toBe(false);
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
      expect(result.message).toContain('Could not verify token endpoint security');
      expect(result.remediation).toContain('Token Storage');
      expect(result.remediation).toContain('HTTPS');
      expect(result.remediation).toContain('localStorage');
      expect(result.metadata).toHaveProperty('attempts');
    });

    it('should warn when "none" authentication is supported', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
        token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).toContain("'none' authentication method");
      expect(result.message).toContain('public clients');
      expect(result.metadata).toHaveProperty('warnings');
      const warnings = result.metadata?.warnings as string[];
      expect(warnings).toBeDefined();
      expect(warnings.some((w: string) => w.includes("'none'"))).toBe(true);
    });

    it('should warn about insecure authentication methods', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
        token_endpoint_auth_methods_supported: ['client_secret_post'],
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.message).toContain('more secure methods');
      expect(result.message).toContain('private_key_jwt');
    });

    it('should provide client-side storage recommendations in warnings', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
        token_endpoint_auth_methods_supported: ['none'],
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.WARNING);
      expect(result.remediation).toContain('localStorage');
      expect(result.remediation).toContain('httpOnly');
      expect(result.remediation).toContain('SameSite');
    });
  });

  describe('execute() - FAIL scenarios', () => {
    it('should fail when no token endpoint is found', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        // Missing token_endpoint
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.FAIL);
      expect(result.severity).toBe(Severity.CRITICAL);
      expect(result.message).toContain('No token endpoint');
      expect(result.message).toContain('required');
      expect(result.remediation).toContain('token_endpoint');
    });

    it('should fail when token endpoint uses HTTP (not localhost)', async () => {
      const mockMetadata: OAuthMetadata = {
        issuer: 'http://example.com',
        authorization_endpoint: 'http://example.com/oauth/authorize',
        token_endpoint: 'http://example.com/oauth/token',
      };

      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await check.run(context);

      expect(result.status).toBe(CheckStatus.FAIL);
      expect(result.severity).toBe(Severity.CRITICAL);
      expect(result.message).toContain('insecure HTTP protocol');
      expect(result.message).toContain('MUST be transmitted over HTTPS');
      expect(result.remediation).toContain('HTTPS');
      expect(result.metadata).toHaveProperty('protocol', 'http:');
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
      expect(logs.some((log) => log.includes('token endpoint'))).toBe(true);
    });
  });
});
