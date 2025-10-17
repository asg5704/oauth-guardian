import { defineConfig } from "vitest/config";
import path from 'path';

export default defineConfig({
  resolve: {
    alias: {
      "@checks": path.resolve(__dirname, "./src/checks/*"),
      "@auditor": path.resolve(__dirname, "./src/auditor/*"),
      "@config": path.resolve(__dirname, "./src/config/*"),
      "@reporters": path.resolve(__dirname, "./src/reporters/*"),
      "@rules": path.resolve(__dirname, "./src/rules/*"),
      "@": path.resolve(__dirname, "./src/*"),
    }
  },
  test: {
    globals: true,
    environment: "node",
    coverage: {
      enabled: true,
      provider: "v8",
      reporter: ["text", "json", "html"],
      exclude: [
        "node_modules/",
        "dist/",
        "tests/",
        "**/*.d.ts",
        "**/*.config.*",
        "**/mockData",
        "src/cli.ts", // CLI is tested via integration tests in separate process
      ],
    },
    include: ["tests/**/*.test.ts"],
    exclude: ["node_modules", "dist"],
  },
});
