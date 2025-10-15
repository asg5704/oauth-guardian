/**
 * Configuration Loader
 * Loads and validates configuration from YAML files
 */

import { readFile } from "fs/promises";
import { resolve } from "path";
import * as yaml from "js-yaml";
import { AuditorConfig } from "../types/index.js";
import { validateConfig, safeValidateConfig } from "./schema.js";
import { getDefaultConfig } from "./defaults.js";

/**
 * Configuration file names to search for (in order)
 */
const CONFIG_FILE_NAMES = [
  "oauth-guardian.config.yml",
  "oauth-guardian.config.yaml",
  ".oauth-guardian.yml",
  ".oauth-guardian.yaml",
];

/**
 * Load configuration from a YAML file
 */
export async function loadConfigFromFile(
  filePath: string
): Promise<AuditorConfig> {
  try {
    // Read file
    const fileContent = await readFile(filePath, "utf-8");

    // Parse YAML
    const parsed = yaml.load(fileContent);

    if (!parsed || typeof parsed !== "object") {
      throw new Error("Configuration file is empty or invalid");
    }

    // Validate with schema
    const validated = validateConfig(parsed);

    // Merge with defaults
    return getDefaultConfig(validated as Partial<AuditorConfig>);
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to load configuration from ${filePath}: ${error.message}`);
    }
    throw error;
  }
}

/**
 * Safely load configuration with error details
 */
export async function safeLoadConfigFromFile(filePath: string): Promise<{
  success: boolean;
  config?: AuditorConfig;
  errors?: string[];
}> {
  try {
    // Read file
    const fileContent = await readFile(filePath, "utf-8");

    // Parse YAML
    const parsed = yaml.load(fileContent);

    if (!parsed || typeof parsed !== "object") {
      return {
        success: false,
        errors: ["Configuration file is empty or invalid"],
      };
    }

    // Validate with schema
    const validation = safeValidateConfig(parsed);

    if (!validation.success) {
      return {
        success: false,
        errors: validation.errors,
      };
    }

    // Merge with defaults
    const config = getDefaultConfig(validation.data as Partial<AuditorConfig>);

    return {
      success: true,
      config,
    };
  } catch (error) {
    if (error instanceof Error) {
      return {
        success: false,
        errors: [error.message],
      };
    }

    return {
      success: false,
      errors: ["Unknown error loading configuration"],
    };
  }
}

/**
 * Auto-discover and load configuration file from current directory
 */
export async function discoverAndLoadConfig(): Promise<AuditorConfig | null> {
  for (const fileName of CONFIG_FILE_NAMES) {
    try {
      const filePath = resolve(process.cwd(), fileName);
      const config = await loadConfigFromFile(filePath);
      return config;
    } catch {
      // Continue to next file name
      continue;
    }
  }

  // No config file found
  return null;
}

/**
 * Load configuration with fallbacks
 * 1. Try explicit file path if provided
 * 2. Try auto-discovery in current directory
 * 3. Fall back to defaults with target
 */
export async function loadConfig(
  target: string,
  configPath?: string
): Promise<AuditorConfig> {
  // If explicit config path provided, load it
  if (configPath) {
    const result = await safeLoadConfigFromFile(configPath);
    if (!result.success) {
      throw new Error(
        `Configuration errors:\n${result.errors?.join("\n")}`
      );
    }
    // Override target if provided
    if (result.config) {
      result.config.target = target;
      return result.config;
    }
  }

  // Try auto-discovery
  const discovered = await discoverAndLoadConfig();
  if (discovered) {
    discovered.target = target;
    return discovered;
  }

  // Fall back to defaults
  return getDefaultConfig({ target });
}

/**
 * Parse configuration from object (useful for testing)
 */
export function parseConfig(obj: unknown): AuditorConfig {
  const validated = validateConfig(obj);
  return getDefaultConfig(validated as Partial<AuditorConfig>);
}
