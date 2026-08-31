import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testMatch: "*.spec.js",
  projects: [{ name: "firefox", use: { ...devices["Desktop Firefox"] } }],
  use: { baseURL: "http://localhost:3000", trace: "retain-on-failure" },
  webServer: [
    {
      command:
        "cargo run --quiet --manifest-path ../Cargo.toml -- dev-idp.toml",
      url: "http://localhost:8383/.well-known/openid-configuration",
      reuseExistingServer: !process.env.CI,
      timeout: 300_000,
    },
    {
      command: "node serve.mjs",
      url: "http://localhost:3000",
      reuseExistingServer: !process.env.CI,
    },
  ],
});
