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
  const createOAuthClient = page.getByRole("link", {
    name: "Create OAuth client in Cloudflare ↗",
  });
  await expect(createOAuthClient).toBeVisible();
  await expect(createOAuthClient).toHaveAttribute(
    "href",
    "https://dash.cloudflare.com/?to=%2F%3Aaccount%2Foauth-clients"
  );
  await expect(createOAuthClient).toHaveAttribute("target", "_blank");
  await expect(page.getByText("Code", { exact: true })).toBeVisible();
  await expect(
    page.getByText("Authorization Code + Refresh Token", { exact: true })
  ).toBeVisible();
  await expect(
    page.getByText("Client Secret Basic", { exact: true })
  ).toBeVisible();
  await expect(page.getByText("DNS · Edit", { exact: true })).toBeVisible();
  await expect(page.getByText(/Client URL required/)).toBeVisible();
  await expect(page.locator('input[name="scopes"]')).toHaveValue(
    "zone.read dns.write offline_access"
  );
  await page.getByLabel("Client ID").fill("private-client-id");
  await page.getByLabel("Client secret").fill("private-client-secret");
  await page.getByRole("button", { name: "Save OAuth client" }).click();
  await expect(
    page.getByRole("heading", { name: "Authorize Cloudflare" })
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Use these OAuth settings" })
  ).toHaveCount(0);
  await expect(
    page.getByRole("heading", { name: "Paste the generated credentials" })
  ).toHaveCount(0);
  await expect(page.getByLabel("Client ID")).not.toBeVisible();
  await expect(page.getByText("Change OAuth client credentials")).toBeVisible();

  // Submit a clean hostname to the live loopback upstream, follow the OAuth
  // round trip, then let reconciliation finish the pending binding.
  await page.goto(`${fixture.baseUrl}/bindings/new`);
  await expect(page.getByText("Public HTTPS included")).toBeVisible();
  await expect(page.getByLabel("Local service protocol")).toHaveValue("http");
  await expect(
    page.getByText("Allow an untrusted HTTPS upstream certificate")
  ).toHaveCount(0);
  await page.getByLabel("Hostname").fill("app.example.com");
  await page.getByLabel("Local port").fill(String(fixture.upstreamPort));
  await page.getByRole("button", { name: "Bind domain" }).click();
  await expect(page.getByText("Connected", { exact: true })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Authorize Cloudflare" })
  ).toHaveCount(0);
  await expect(page.getByText("Change OAuth client credentials")).toHaveCount(0);
  await page.goto(fixture.baseUrl);
  const appRow = page
    .locator("tr[data-binding-id]")
    .filter({ hasText: "app.example.com" });
  await expect(async () => {
    await page.goto(fixture.baseUrl);
    await expect(appRow.locator(".pill.active")).toBeVisible();
  }).toPass({ timeout: 15_000 });
  const rowActions = appRow.locator(".row-actions");
  await expect(rowActions).toHaveCSS("display", "flex");
  await expect(rowActions).toHaveCSS("flex-wrap", "nowrap");

  // At the reported 1024px viewport, six table columns are too cramped. Use
  // the labeled card layout before status and certificate copy starts wrapping.
  await page.setViewportSize({ width: 1024, height: 900 });
  await expect(appRow).toHaveCSS("display", "grid");
  await expect(appRow.locator("td").last()).toHaveCSS(
    "border-bottom-width",
    "0px"
  );

  // An upstream address is one unit and must not split mid-IP.
  await page.setViewportSize({ width: 810, height: 900 });
  const upstreamLines = await appRow.locator("code").evaluate(element => {
    const range = document.createRange();
    range.selectNodeContents(element);
    return range.getClientRects().length;
  });
  expect(upstreamLines).toBe(1);

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

  // Add, edit, and remove a generic secondary path route.
  await page.goto(fixture.baseUrl);
  const appBindingId = await appRow.getAttribute("data-binding-id");
  await appRow.getByRole("link", { name: "Edit" }).click();
  const addRoute = page.locator(`form[action="/bindings/${appBindingId}/routes"]`);
  await addRoute.getByLabel("Path prefix").fill("/assets/");
  await addRoute.getByLabel("Local port").fill(String(fixture.upstreamPort));
  await addRoute.getByRole("button", { name: "Add path route" }).click();
  let pathRow = page.locator("tr[data-route-id]").filter({ hasText: "/assets" });
  await expect(pathRow).toBeVisible();
  await expect(pathRow).toContainText(`http://127.0.0.1:${fixture.upstreamPort}`);
  await pathRow.getByRole("link", { name: "Edit" }).click();
  await page.getByLabel("Path prefix").fill("/static/");
  await page.getByRole("button", { name: "Save path route" }).click();
  pathRow = page.locator("tr[data-route-id]").filter({ hasText: "/static" });
  await expect(pathRow).toBeVisible();
  await pathRow.getByRole("button", { name: "Remove" }).click();
  await expect(page.locator("tr[data-route-id]")).toHaveCount(0);

  // Unbind becomes a read-only draining state, then disappears.
  await page.goto(fixture.baseUrl);
  await appRow.getByRole("button", { name: "Unbind" }).click();
  await expect(appRow.locator(".pill.draining")).toBeVisible();
  await expect(appRow.getByRole("link", { name: "Edit" })).toHaveCount(0);
  await expect(appRow.getByRole("button", { name: "Unbind" })).toHaveCount(0);
  await expect(appRow.getByText("Removal in progress")).toBeVisible();
  await expect(appRow).toHaveCount(0, { timeout: 15_000 });
  await expect(
    page
      .locator("tr[data-binding-id]")
      .filter({ hasText: "conflict.example.com" })
  ).toBeVisible();
});
