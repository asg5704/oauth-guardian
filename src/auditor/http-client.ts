/**
 * HTTP Client wrapper for OAuth Guardian
 * Handles all HTTP requests with timeout and error handling
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from "axios";

export interface HttpClientConfig {
  /** Base URL for requests */
  baseURL?: string;

  /** Request timeout in milliseconds */
  timeout?: number;

  /** User agent string */
  userAgent?: string;

  /** Additional headers */
  headers?: Record<string, string>;

  /** Enable verbose logging */
  verbose?: boolean;
}

export interface OAuthMetadata {
  issuer?: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  revocation_endpoint?: string;
  introspection_endpoint?: string;
  userinfo_endpoint?: string;
  jwks_uri?: string;
  registration_endpoint?: string;
  scopes_supported?: string[];
  response_types_supported?: string[];
  grant_types_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
  code_challenge_methods_supported?: string[];
  [key: string]: unknown;
}

export interface MetadataDiscoveryAttempt {
  url: string;
  status: number;
  success: boolean;
}

export interface MetadataDiscoveryResult {
  metadata: OAuthMetadata | null;
  attempts: MetadataDiscoveryAttempt[];
}

/**
 * HTTP Client for making requests during security audits
 */
export class HttpClient {
  private client: AxiosInstance;
  private verbose: boolean;

  constructor(config: HttpClientConfig = {}) {
    this.verbose = config.verbose ?? false;

    this.client = axios.create({
      baseURL: config.baseURL,
      timeout: config.timeout ?? 10000,
      headers: {
        "User-Agent":
          config.userAgent ??
          `OAuth-Guardian/1.0 (Security Audit Tool)`,
        ...config.headers,
      },
      // Don't reject on non-2xx status codes - we want to analyze all responses
      validateStatus: () => true,
    });

    if (this.verbose) {
      this.setupRequestLogging();
    }
  }

  /**
   * Setup request/response logging for debugging
   */
  private setupRequestLogging(): void {
    this.client.interceptors.request.use((config) => {
      console.log(`→ ${config.method?.toUpperCase()} ${config.url}`);
      return config;
    });

    this.client.interceptors.response.use((response) => {
      console.log(
        `← ${response.status} ${response.config.method?.toUpperCase()} ${response.config.url}`
      );
      return response;
    });
  }

  /**
   * Discover OAuth 2.0 metadata from well-known endpoint
   * Returns both metadata and discovery attempt details
   */
  async discoverMetadata(
    issuerUrl: string
  ): Promise<MetadataDiscoveryResult> {
    const attempts: MetadataDiscoveryAttempt[] = [];

    try {
      // Try OAuth 2.0 Authorization Server Metadata (RFC 8414)
      const oauthUrl = `${issuerUrl}/.well-known/oauth-authorization-server`;
      const oauthResponse = await this.get<OAuthMetadata>(oauthUrl);

      attempts.push({
        url: oauthUrl,
        status: oauthResponse.status,
        success: oauthResponse.status === 200,
      });

      if (oauthResponse.status === 200 && oauthResponse.data) {
        return {
          metadata: oauthResponse.data,
          attempts,
        };
      }

      // Try OpenID Connect Discovery (if OAuth metadata not found)
      const oidcUrl = `${issuerUrl}/.well-known/openid-configuration`;
      const oidcResponse = await this.get<OAuthMetadata>(oidcUrl);

      attempts.push({
        url: oidcUrl,
        status: oidcResponse.status,
        success: oidcResponse.status === 200,
      });

      if (oidcResponse.status === 200 && oidcResponse.data) {
        return {
          metadata: oidcResponse.data,
          attempts,
        };
      }

      return {
        metadata: null,
        attempts,
      };
    } catch (error) {
      if (this.verbose) {
        console.error("Failed to discover OAuth metadata:", error);
      }
      return {
        metadata: null,
        attempts,
      };
    }
  }

  /**
   * Make a GET request
   */
  async get<T = unknown>(
    url: string,
    config?: AxiosRequestConfig
  ): Promise<AxiosResponse<T>> {
    return this.client.get<T>(url, config);
  }

  /**
   * Make a POST request
   */
  async post<T = unknown>(
    url: string,
    data?: unknown,
    config?: AxiosRequestConfig
  ): Promise<AxiosResponse<T>> {
    return this.client.post<T>(url, data, config);
  }

  /**
   * Make a HEAD request (useful for checking endpoints without fetching body)
   */
  async head(
    url: string,
    config?: AxiosRequestConfig
  ): Promise<AxiosResponse> {
    return this.client.head(url, config);
  }

  /**
   * Make a custom request
   */
  async request<T = unknown>(
    config: AxiosRequestConfig
  ): Promise<AxiosResponse<T>> {
    return this.client.request<T>(config);
  }

  /**
   * Check if a URL is accessible
   */
  async isAccessible(url: string): Promise<boolean> {
    try {
      const response = await this.head(url);
      return response.status >= 200 && response.status < 400;
    } catch {
      return false;
    }
  }

  /**
   * Parse JSON safely
   */
  parseJson<T = unknown>(data: string): T | null {
    try {
      return JSON.parse(data) as T;
    } catch {
      return null;
    }
  }
}
