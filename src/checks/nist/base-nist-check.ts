/**
 * Base class for NIST 800-63B compliance checks
 *
 * Provides shared functionality for Authentication Assurance Level (AAL) validation,
 * Authentication Context Class Reference (ACR) parsing, and Authentication Method
 * Reference (AMR) analysis.
 *
 * References:
 * - NIST SP 800-63B: https://pages.nist.gov/800-63-3/sp800-63b.html
 * - RFC 8176 (AMR Values): https://www.rfc-editor.org/rfc/rfc8176.html
 * - OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html
 */

import { BaseCheck } from "../base-check.js";
import { CheckResult, CheckContext } from "../../types/index.js";
import { HttpClient } from "../../auditor/http-client.js";

/**
 * NIST Authentication Assurance Levels
 */
export enum AALLevel {
  AAL1 = "AAL1", // Single-factor or multi-factor authentication
  AAL2 = "AAL2", // Multi-factor authentication with crypto
  AAL3 = "AAL3", // Hardware-based cryptographic authenticator
}

/**
 * ACR (Authentication Context Class Reference) detection result
 */
export interface ACRAnalysis {
  /** Raw ACR values found in metadata */
  acrValues: string[];

  /** Detected AAL levels based on ACR analysis */
  detectedAALs: AALLevel[];

  /** Whether the provider explicitly advertises ACR support */
  hasACRSupport: boolean;

  /** Confidence level of detection (high, medium, low) */
  confidence: "high" | "medium" | "low";

  /** Custom or non-standard ACR values that couldn't be mapped */
  unmappedValues: string[];
}

/**
 * AMR (Authentication Method Reference) analysis result
 */
export interface AMRAnalysis {
  /** Raw AMR values found in claims_supported */
  amrValues: string[];

  /** Whether multi-factor authentication is supported */
  supportsMFA: boolean;

  /** Whether hardware-based authentication is supported */
  supportsHardwareAuth: boolean;

  /** Whether phishing-resistant authentication is supported */
  supportsPhishingResistant: boolean;

  /** Detected authentication methods by category */
  methods: {
    passwords: string[]; // pwd, pin
    otp: string[]; // otp, sms, tel
    hardware: string[]; // hwk, sc
    biometric: string[]; // fpt, face, iris, retina, vbm
    cryptographic: string[]; // hwk, swk
  };
}

/**
 * OAuth/OIDC metadata structure (partial)
 */
export interface OAuthMetadata {
  issuer?: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  acr_values_supported?: string[];
  claims_supported?: string[];
  response_types_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
  code_challenge_methods_supported?: string[];
  [key: string]: unknown;
}

/**
 * Abstract base class for NIST 800-63B compliance checks
 */
export abstract class BaseNISTCheck extends BaseCheck {
  /**
   * Discover OAuth/OIDC metadata with proper error handling
   */
  protected async discoverMetadata(
    context: CheckContext
  ): Promise<{ success: boolean; metadata?: OAuthMetadata; error?: string }> {
    const httpClient = context.httpClient as HttpClient;

    if (!httpClient) {
      return {
        success: false,
        error: "HTTP client not available in context",
      };
    }

    this.log(context, "Discovering OAuth/OIDC metadata...");

    const discoveryResult = await httpClient.discoverMetadata(context.targetUrl);

    if (!discoveryResult.metadata) {
      const attemptDetails = discoveryResult.attempts
        .map((attempt) => `  - ${attempt.url} (${attempt.status})`)
        .join("\n");

      return {
        success: false,
        error: `Unable to discover OAuth metadata.\n\nAttempted endpoints:\n${attemptDetails}`,
      };
    }

    this.log(context, "OAuth metadata discovered", discoveryResult.metadata);

    return {
      success: true,
      metadata: discoveryResult.metadata as OAuthMetadata,
    };
  }

  /**
   * Analyze ACR (Authentication Context Class Reference) values
   *
   * Detects NIST AAL levels and standard ACR patterns from metadata.
   * Handles provider-specific formats (Okta, Microsoft, etc.).
   */
  protected analyzeACRValues(metadata: OAuthMetadata): ACRAnalysis {
    const acrValues = metadata.acr_values_supported || [];
    const detectedAALs: Set<AALLevel> = new Set();
    const unmappedValues: string[] = [];

    if (acrValues.length === 0) {
      return {
        acrValues: [],
        detectedAALs: [],
        hasACRSupport: false,
        confidence: "low",
        unmappedValues: [],
      };
    }

    // Analyze each ACR value
    for (const acr of acrValues) {
      const normalized = acr.toLowerCase();

      // AAL3 patterns (highest assurance)
      if (
        normalized.includes("aal:3") ||
        normalized.includes("aal3") ||
        normalized === "phrh" || // Okta: phishing-resistant hardware
        normalized.includes("veryhigh") ||
        normalized.includes("very-high")
      ) {
        detectedAALs.add(AALLevel.AAL3);
        continue;
      }

      // AAL2 patterns (multi-factor)
      // Use word boundaries for generic terms to avoid false matches
      if (
        normalized.includes("aal:2") ||
        normalized.includes("aal2") ||
        normalized.includes("2fa") ||
        normalized.includes("mfa") ||
        normalized.includes("multi") ||
        normalized === "phr" || // Okta: phishing-resistant (exact match)
        normalized === "high" || // Exact match only
        normalized === "strong" // Exact match only
      ) {
        detectedAALs.add(AALLevel.AAL2);
        continue;
      }

      // AAL1 patterns (single-factor or basic)
      // Use exact matches or specific patterns for generic terms
      if (
        normalized.includes("aal:1") ||
        normalized.includes("aal1") ||
        normalized.includes("1fa") ||
        normalized.includes("single") ||
        normalized === "basic" || // Exact match only
        normalized === "low" || // Exact match only
        normalized === "0" // Standard "insufficient" value
      ) {
        detectedAALs.add(AALLevel.AAL1);
        continue;
      }

      // Couldn't map this ACR value
      unmappedValues.push(acr);
    }

    // Determine confidence level
    let confidence: "high" | "medium" | "low" = "low";
    if (detectedAALs.size > 0 && unmappedValues.length === 0) {
      confidence = "high";
    } else if (detectedAALs.size > 0) {
      confidence = "medium";
    }

    return {
      acrValues,
      detectedAALs: Array.from(detectedAALs).sort(),
      hasACRSupport: true,
      confidence,
      unmappedValues,
    };
  }

  /**
   * Analyze AMR (Authentication Method Reference) values
   *
   * Detects supported authentication methods and their security characteristics
   * based on RFC 8176 standard AMR values.
   */
  protected analyzeAMRValues(metadata: OAuthMetadata): AMRAnalysis {
    const claimsSupported = metadata.claims_supported || [];
    const hasAMRClaim = claimsSupported.includes("amr");

    if (!hasAMRClaim) {
      return {
        amrValues: [],
        supportsMFA: false,
        supportsHardwareAuth: false,
        supportsPhishingResistant: false,
        methods: {
          passwords: [],
          otp: [],
          hardware: [],
          biometric: [],
          cryptographic: [],
        },
      };
    }

    // Note: Most providers don't expose actual AMR values in metadata,
    // only that the AMR claim is supported. We can't determine specific
    // methods without actual authentication flow or documentation.
    // This is a limitation of metadata-based detection.

    return {
      amrValues: ["amr"], // Just indicates AMR claim is supported
      supportsMFA: false, // Can't determine from metadata alone
      supportsHardwareAuth: false, // Can't determine from metadata alone
      supportsPhishingResistant: false, // Can't determine from metadata alone
      methods: {
        passwords: [],
        otp: [],
        hardware: [],
        biometric: [],
        cryptographic: [],
      },
    };
  }

  /**
   * Detect AAL support level from metadata
   *
   * Combines ACR and AMR analysis to determine the highest AAL level supported.
   * Returns undefined if AAL level cannot be determined.
   */
  protected detectAALSupport(metadata: OAuthMetadata): {
    highestAAL?: AALLevel;
    supportedAALs: AALLevel[];
    acrAnalysis: ACRAnalysis;
    amrAnalysis: AMRAnalysis;
    canDetermine: boolean;
  } {
    const acrAnalysis = this.analyzeACRValues(metadata);
    const amrAnalysis = this.analyzeAMRValues(metadata);

    const supportedAALs = acrAnalysis.detectedAALs;
    const canDetermine = supportedAALs.length > 0;

    let highestAAL: AALLevel | undefined;
    if (supportedAALs.includes(AALLevel.AAL3)) {
      highestAAL = AALLevel.AAL3;
    } else if (supportedAALs.includes(AALLevel.AAL2)) {
      highestAAL = AALLevel.AAL2;
    } else if (supportedAALs.includes(AALLevel.AAL1)) {
      highestAAL = AALLevel.AAL1;
    }

    return {
      highestAAL,
      supportedAALs,
      acrAnalysis,
      amrAnalysis,
      canDetermine,
    };
  }

  /**
   * Check if metadata indicates OIDC support
   */
  protected isOIDCProvider(metadata: OAuthMetadata): boolean {
    // OIDC providers typically support id_token response type
    const responseTypes = metadata.response_types_supported || [];
    return responseTypes.some((type) => type.includes("id_token"));
  }

  /**
   * Generate remediation guidance for missing ACR support
   */
  protected getACRRemediationGuidance(targetAAL: AALLevel): string {
    const aalRequirements: Record<AALLevel, string> = {
      [AALLevel.AAL1]: "Single-factor (password) or multi-factor authentication",
      [AALLevel.AAL2]: "Multi-factor authentication with cryptographic methods",
      [AALLevel.AAL3]:
        "Hardware-based cryptographic authenticator (phishing-resistant)",
    };

    return `
To implement ${targetAAL} compliance with ACR support:

1. Implement OpenID Connect Discovery if not already available:
   - Endpoint: /.well-known/openid-configuration

2. Add ACR values to your metadata response:
{
  "acr_values_supported": [
    "urn:nist:800-63-3:aal:1",
    "urn:nist:800-63-3:aal:2",
    "urn:nist:800-63-3:aal:3"
  ],
  "claims_supported": [
    "sub", "iss", "aud", "exp", "iat",
    "acr", "amr", "auth_time"
  ]
}

3. Support the acr_values parameter in authorization requests

4. Include acr and amr claims in ID tokens

5. Implement ${targetAAL} requirements:
   - ${aalRequirements[targetAAL]}

References:
- NIST SP 800-63B: https://pages.nist.gov/800-63-3/sp800-63b.html
- OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html
- RFC 8176 (AMR Values): https://www.rfc-editor.org/rfc/rfc8176.html
`.trim();
  }

  /**
   * Generate warning for providers without ACR metadata
   */
  protected createMetadataWarning(error: string): CheckResult {
    return this.warning(
      `${error}

Impact: Cannot automatically verify NIST AAL compliance without metadata.`,
      `Implement OAuth 2.0 Authorization Server Metadata (RFC 8414) or OpenID Connect Discovery.

Add one of these endpoints to your server:
  - /.well-known/oauth-authorization-server (RFC 8414)
  - /.well-known/openid-configuration (OpenID Connect Discovery)

Include NIST-relevant fields in your metadata:
{
  "issuer": "https://your-server.com",
  "authorization_endpoint": "https://your-server.com/oauth/authorize",
  "token_endpoint": "https://your-server.com/oauth/token",
  "acr_values_supported": ["urn:nist:800-63-3:aal:1", "urn:nist:800-63-3:aal:2"],
  "claims_supported": ["acr", "amr", "auth_time"]
}

References:
- RFC 8414: https://datatracker.ietf.org/doc/html/rfc8414
- OpenID Connect Discovery: https://openid.net/specs/openid-connect-discovery-1_0.html
- NIST SP 800-63B: https://pages.nist.gov/800-63-3/sp800-63b.html`
    );
  }

  /**
   * Check if HTTPS is enforced for endpoints
   */
  protected isHTTPSEnforced(metadata: OAuthMetadata): {
    enforced: boolean;
    insecureEndpoints: string[];
  } {
    const insecureEndpoints: string[] = [];

    // Check critical OAuth endpoints
    const endpointsToCheck = [
      metadata.authorization_endpoint,
      metadata.token_endpoint,
    ];

    for (const endpoint of endpointsToCheck) {
      if (endpoint && !endpoint.startsWith("https://")) {
        insecureEndpoints.push(endpoint);
      }
    }

    return {
      enforced: insecureEndpoints.length === 0,
      insecureEndpoints,
    };
  }

  /**
   * Get AAL session timeout requirements (in hours)
   */
  protected getAALSessionTimeoutRequirement(aal: AALLevel): number {
    switch (aal) {
      case AALLevel.AAL1:
        return 720; // 30 days = 720 hours
      case AALLevel.AAL2:
      case AALLevel.AAL3:
        return 12; // 12 hours
    }
  }

  /**
   * Get AAL idle timeout requirements (in minutes)
   */
  protected getAALIdleTimeoutRequirement(aal: AALLevel): number | undefined {
    switch (aal) {
      case AALLevel.AAL1:
        return undefined; // No specific requirement
      case AALLevel.AAL2:
        return 60; // 1 hour = 60 minutes (30 min preferred)
      case AALLevel.AAL3:
        return 15; // 15 minutes
    }
  }

  /**
   * Format AAL level for display
   */
  protected formatAAL(aal: AALLevel): string {
    const descriptions: Record<AALLevel, string> = {
      [AALLevel.AAL1]: "AAL1 (Basic Assurance - Single or Multi-Factor)",
      [AALLevel.AAL2]: "AAL2 (High Assurance - Multi-Factor with Crypto)",
      [AALLevel.AAL3]:
        "AAL3 (Very High Assurance - Hardware Cryptographic Authenticator)",
    };

    return descriptions[aal];
  }
}
