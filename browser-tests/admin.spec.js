import { expect, test } from "@playwright/test";
import { startFixture } from "./fixture.js";

let fixture;

test.beforeAll(async () => {
  fixture = await startFixture();
});

test.afterAll(async () => {
  await fixture?.stop();
});

test("first-run setup, logout, and login", async ({ page }) => {
  await page.goto(fixture.setupUrl);
  await expect(page.getByRole("heading", { name: "Create administrator" })).toBeVisible();
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByLabel("ACME contact email").fill("browser-test@example.com");
  await page.getByRole("button", { name: "Finish setup" }).click();
  await expect(page.getByRole("heading", { name: "Domain bindings" })).toBeVisible();
  await expect(page.getByRole("link", { name: "New binding" })).toBeVisible();

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Domain bindings" })).toBeVisible();
});
