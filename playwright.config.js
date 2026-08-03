import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./browser-tests",
  workers: 1,
  retries: 0,
  timeout: 120_000,
  use: {
    headless: true,
    screenshot: "only-on-failure",
    trace: "retain-on-failure"
  }
});
