import { expect, test } from "@playwright/test";
import { startFixture } from "./fixture.js";

let fixture;

test.beforeAll(async () => {
  fixture = await startFixture();
});

test.afterAll(async () => {
  await fixture?.stop();
});

test("connect Cloudflare, bind, confirm replacement, and unbind", async ({ page }) => {
  // First-run setup.
  await page.goto(fixture.setupUrl);
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByLabel("ACME contact email").fill("browser-test@example.com");
  await page.getByRole("button", { name: "Finish setup" }).click();
  await expect(page.getByRole("heading", { name: "Domain bindings" })).toBeVisible();

  // Configure the private OAuth client. The first binding submission should
  // open authorization automatically; the fake consent endpoint approves it
  // immediately and redirects back to the callback.
  await page.getByRole("link", { name: "Cloudflare" }).click();
  await page.getByLabel("Client ID").fill("private-client-id");
  await page.getByLabel("Client secret").fill("private-client-secret");
  await page.getByRole("button", { name: "Save OAuth client" }).click();

  // Submit a clean hostname to the live loopback upstream, follow the OAuth
  // round trip, then let reconciliation finish the pending binding.
  await page.goto(`${fixture.baseUrl}/bindings/new`);
  await page.getByLabel("Hostname").fill("app.example.com");
  await page.getByLabel("Local port").fill(String(fixture.upstreamPort));
  await page.getByRole("button", { name: "Bind domain" }).click();
  await expect(page.getByText("Connected", { exact: true })).toBeVisible();
  await page.goto(fixture.baseUrl);
  const appRow = page
    .locator("tr[data-binding-id]")
    .filter({ hasText: "app.example.com" });
  await expect(async () => {
    await page.goto(fixture.baseUrl);
    await expect(appRow.locator(".pill.active")).toBeVisible();
  }).toPass({ timeout: 15_000 });

  // A hostname with pre-existing records goes through the confirmation
  // interstitial before anything is replaced.
  await page.goto(`${fixture.baseUrl}/bindings/new`);
  await page.getByLabel("Hostname").fill("conflict.example.com");
  await page.getByLabel("Local port").fill(String(fixture.upstreamPort));
  await page.getByRole("button", { name: "Bind domain" }).click();
  await expect(
    page.getByRole("heading", { name: "Replace existing records?" })
  ).toBeVisible();
  await page.getByRole("button", { name: "Replace existing records" }).click();
  await expect(
    page
      .locator("tr[data-binding-id]")
      .filter({ hasText: "conflict.example.com" })
  ).toBeVisible();

  // Unbind drains and then disappears from the dashboard.
  await appRow.getByRole("button", { name: "Unbind" }).click();
  await expect(async () => {
    await page.goto(fixture.baseUrl);
    await expect(
      page.locator("tr[data-binding-id]").filter({ hasText: "app.example.com" })
    ).toHaveCount(0);
  }).toPass({ timeout: 15_000 });
  await expect(
    page
      .locator("tr[data-binding-id]")
      .filter({ hasText: "conflict.example.com" })
  ).toBeVisible();
});
