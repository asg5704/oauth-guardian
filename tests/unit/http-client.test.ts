import { describe, it, expect, beforeEach } from 'vitest';
import MockAdapter from 'axios-mock-adapter';
import axios from 'axios';
import { HttpClient, type OAuthMetadata } from '../../src/auditor/http-client.js';

describe('HttpClient', () => {
  let mock: MockAdapter;
  let client: HttpClient;

  beforeEach(() => {
    mock = new MockAdapter(axios);
    client = new HttpClient({
      timeout: 5000,
      userAgent: 'Test-Agent',
    });
  });

  describe('constructor', () => {
    it('should create client with default config', () => {
      const defaultClient = new HttpClient();
      expect(defaultClient).toBeInstanceOf(HttpClient);
    });

    it('should create client with custom config', () => {
      const customClient = new HttpClient({
        timeout: 10000,
        userAgent: 'Custom-Agent',
        headers: { 'X-Custom': 'value' },
      });
      expect(customClient).toBeInstanceOf(HttpClient);
    });
  });

  describe('discoverMetadata', () => {
    const mockMetadata: OAuthMetadata = {
      issuer: 'https://example.com',
      authorization_endpoint: 'https://example.com/oauth/authorize',
      token_endpoint: 'https://example.com/oauth/token',
      code_challenge_methods_supported: ['S256', 'plain'],
    };

    it('should discover OAuth metadata from RFC 8414 endpoint', async () => {
      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(200, mockMetadata);

      const result = await client.discoverMetadata('https://example.com');

      expect(result.metadata).toEqual(mockMetadata);
      expect(result.attempts).toHaveLength(1);
      expect(result.attempts[0]).toEqual({
        url: 'https://example.com/.well-known/oauth-authorization-server',
        status: 200,
        success: true,
      });
    });

    it('should discover OpenID Connect metadata when OAuth fails', async () => {
      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(404);

      mock
        .onGet('https://example.com/.well-known/openid-configuration')
        .reply(200, mockMetadata);

      const result = await client.discoverMetadata('https://example.com');

      expect(result.metadata).toEqual(mockMetadata);
      expect(result.attempts).toHaveLength(2);
      expect(result.attempts[0].success).toBe(false);
      expect(result.attempts[1].success).toBe(true);
    });

    it('should return null metadata when both endpoints fail', async () => {
      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .reply(404);

      mock
        .onGet('https://example.com/.well-known/openid-configuration')
        .reply(404);

      const result = await client.discoverMetadata('https://example.com');

      expect(result.metadata).toBeNull();
      expect(result.attempts).toHaveLength(2);
      expect(result.attempts[0].status).toBe(404);
      expect(result.attempts[1].status).toBe(404);
    });

    it('should handle network errors gracefully', async () => {
      mock
        .onGet('https://example.com/.well-known/oauth-authorization-server')
        .networkError();

      const result = await client.discoverMetadata('https://example.com');

      expect(result.metadata).toBeNull();
      expect(result.attempts).toHaveLength(0); // Error thrown before attempts recorded
    });
  });

  describe('get', () => {
    it('should make GET request', async () => {
      mock.onGet('https://example.com/api').reply(200, { data: 'test' });

      const response = await client.get('https://example.com/api');

      expect(response.status).toBe(200);
      expect(response.data).toEqual({ data: 'test' });
    });

    it('should return non-2xx status codes', async () => {
      mock.onGet('https://example.com/api').reply(404);

      const response = await client.get('https://example.com/api');

      expect(response.status).toBe(404);
    });
  });

  describe('post', () => {
    it('should make POST request with data', async () => {
      mock.onPost('https://example.com/api', { key: 'value' }).reply(201, { success: true });

      const response = await client.post('https://example.com/api', { key: 'value' });

      expect(response.status).toBe(201);
      expect(response.data).toEqual({ success: true });
    });
  });

  describe('head', () => {
    it('should make HEAD request', async () => {
      mock.onHead('https://example.com/api').reply(200);

      const response = await client.head('https://example.com/api');

      expect(response.status).toBe(200);
    });
  });

  describe('isAccessible', () => {
    it('should return true for accessible URLs', async () => {
      mock.onHead('https://example.com/api').reply(200);

      const accessible = await client.isAccessible('https://example.com/api');

      expect(accessible).toBe(true);
    });

    it('should return true for 3xx status codes', async () => {
      mock.onHead('https://example.com/api').reply(301);

      const accessible = await client.isAccessible('https://example.com/api');

      expect(accessible).toBe(true);
    });

    it('should return false for 4xx status codes', async () => {
      mock.onHead('https://example.com/api').reply(404);

      const accessible = await client.isAccessible('https://example.com/api');

      expect(accessible).toBe(false);
    });

    it('should return false for network errors', async () => {
      mock.onHead('https://example.com/api').networkError();

      const accessible = await client.isAccessible('https://example.com/api');

      expect(accessible).toBe(false);
    });
  });

  describe('parseJson', () => {
    it('should parse valid JSON', () => {
      const result = client.parseJson('{"key": "value"}');
      expect(result).toEqual({ key: 'value' });
    });

    it('should return null for invalid JSON', () => {
      const result = client.parseJson('not json');
      expect(result).toBeNull();
    });

    it('should handle empty strings', () => {
      const result = client.parseJson('');
      expect(result).toBeNull();
    });

    it('should handle nested objects', () => {
      const json = JSON.stringify({ nested: { key: 'value' } });
      const result = client.parseJson(json);
      expect(result).toEqual({ nested: { key: 'value' } });
    });
  });
});
