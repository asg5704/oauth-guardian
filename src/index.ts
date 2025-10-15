/**
 * OAuth Guardian
 * Programmatic API for auditing OAuth 2.0 implementations
 */

// Export types
export * from "./types/index.js";

// Export HTTP client
export { HttpClient } from "./auditor/http-client.js";

// Export audit engine
export { AuditEngine } from "./auditor/engine.js";

// Export reporters
export { JSONReporter } from "./reporters/json-reporter.js";
export { TerminalReporter } from "./reporters/terminal-reporter.js";
export { HTMLReporter } from "./reporters/html-reporter.js";

// Export base check class for custom checks
export { BaseCheck } from "./checks/base-check.js";

// Export built-in checks
export { PKCECheck } from "./checks/oauth/pkce.js";
export { StateParameterCheck } from "./checks/oauth/state.js";
export { RedirectURICheck } from "./checks/oauth/redirect-uri.js";
export { TokenStorageCheck } from "./checks/oauth/token-storage.js";

// Export configuration system
export { loadConfig, loadConfigFromFile, discoverAndLoadConfig, parseConfig } from "./config/loader.js";
export { getDefaultConfig, getMinimalConfig, DEFAULT_CONFIG } from "./config/defaults.js";
export { validateConfig, safeValidateConfig } from "./config/schema.js";
