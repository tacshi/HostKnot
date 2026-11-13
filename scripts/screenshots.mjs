// Regenerates the README screenshots in assets/screenshots/ by driving the
// browser fixture (fake Cloudflare, local certificates) through a realistic
// setup. Run with `npm run screenshots`.
import { mkdir } from "node:fs/promises";
import { createServer } from "node:http";
import https from "node:https";
import { chromium } from "@playwright/test";
import { startFixture } from "../browser-tests/fixture.js";

const outDir = new URL("../assets/screenshots/", import.meta.url).pathname;
// What a real install shows; the fixture itself listens on loopback.
const PUBLIC_CALLBACK = "https://203.0.113.10:9443/oauth/cloudflare/callback";

// Local services on familiar ports, so upstreams read like a real VPS.
const servers = [];
const services = {};
for (const [name, port] of [
  ["web", 3000],
  ["api", 8000],
  ["grafana", 3100],
  ["docs", 4000],
  ["assets", 8080]
]) {
  services[name] = await listen(port);
}

await mkdir(outDir, { recursive: true });
const fixture = await startFixture();
const browser = await chromium.launch();
try {
  const context = await browser.newContext({
    viewport: { width: 1280, height: 820 },
    deviceScaleFactor: 1.5,
    colorScheme: "light"
  });
  const page = await context.newPage();

  await page.goto(fixture.setupUrl);
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByLabel("ACME contact email").fill("ops@example.com");
  await page.getByRole("button", { name: "Finish setup" }).click();
  await page.getByRole("heading", { name: "Domain bindings" }).waitFor();

  // The provider walkthrough is most useful before it is configured.
  await page.goto(`${fixture.baseUrl}/providers/cloudflare`);
  await page
    .locator(".oauth-settings code")
    .evaluate((code, url) => (code.textContent = url), PUBLIC_CALLBACK);
  await shot(page, "cloudflare", { fullPage: true });
  await page.getByLabel("Client ID").fill("hostknot-private-client");
  await page.getByLabel("Client secret").fill("fixture-secret");
  await page.getByRole("button", { name: "Save OAuth client" }).click();
  await page.goto(`${fixture.baseUrl}/providers/cloudflare/connect`);
  await page.getByText("Connected", { exact: true }).waitFor();

  const bindings = [
    { host: "app.example.com", port: services.web, proxied: true },
    { host: "api.example.com", port: services.api, proxied: true },
    { host: "grafana.example.com", port: services.grafana, proxied: false },
    { host: "docs.example.com", port: services.docs, proxied: true }
  ];
  for (const binding of bindings) {
    await page.goto(`${fixture.baseUrl}/bindings/new`);
    await page.getByLabel("Hostname").fill(binding.host);
    await page.getByLabel("Local port").fill(String(binding.port));
    await page.getByLabel("Enable Cloudflare proxy").setChecked(binding.proxied);
    await page.getByRole("button", { name: "Bind domain" }).click();
    await page.getByRole("heading", { name: "Domain bindings" }).waitFor();
  }
  await waitFor(async () => {
    await page.goto(fixture.baseUrl);
    return (await page.locator(".pill.active").count()) === bindings.length;
  });

  const app = page.locator("tr[data-binding-id]").filter({ hasText: "app.example.com" });
  await app.getByRole("link", { name: "Edit" }).click();
  for (const [prefix, port] of [
    ["/assets", services.assets],
    ["/api", services.api]
  ]) {
    const form = page.locator('form[action$="/routes"]');
    await form.getByLabel("Path prefix").fill(prefix);
    await form.getByLabel("Local port").fill(String(port));
    await form.getByRole("button", { name: "Add path route" }).click();
    await page.locator("tr[data-route-id]").filter({ hasText: prefix }).waitFor();
  }
  const editUrl = page.url();

  // Real traffic through the proxy turns every health check green.
  for (const { host } of bindings) {
    await proxyGet(host, "/");
  }
  await proxyGet("app.example.com", "/assets/app.css");
  await proxyGet("app.example.com", "/api/health");

  await page.goto(fixture.baseUrl);
  await shot(page, "dashboard-light");
  // Reload after switching so color transitions don't land mid-fade.
  await page.emulateMedia({ colorScheme: "dark" });
  await page.reload();
  await shot(page, "dashboard-dark");
  await page.emulateMedia({ colorScheme: "light" });

  await page.goto(editUrl);
  await shot(page, "binding", { fullPage: true });

  await page.goto(`${fixture.baseUrl}/bindings/new`);
  await page.getByLabel("Hostname").fill("blog.example.com");
  await page.getByLabel("Local port").fill("2368");
  await page.getByLabel("Local port").blur();
  await shot(page, "new-binding", { fullPage: true });

  console.log(`Screenshots written to ${outDir}`);
} finally {
  await browser.close();
  await fixture.stop();
  for (const server of servers) {
    server.close();
  }
}

async function shot(page, name, options = {}) {
  await page.screenshot({ path: `${outDir}${name}.png`, ...options });
}

async function waitFor(check, timeout = 20_000) {
  const deadline = Date.now() + timeout;
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error("timed out waiting for bindings");
    await new Promise(resolve => setTimeout(resolve, 300));
  }
}

function proxyGet(host, path) {
  const [address, port] = [
    fixture.proxyHttps.slice(0, fixture.proxyHttps.lastIndexOf(":")),
    Number(fixture.proxyHttps.slice(fixture.proxyHttps.lastIndexOf(":") + 1))
  ];
  return new Promise((resolve, reject) => {
    const request = https.request(
      {
        host: address,
        port,
        path,
        servername: host,
        headers: { host },
        rejectUnauthorized: false
      },
      response => {
        response.resume();
        response.on("end", () =>
          response.statusCode < 500
            ? resolve()
            : reject(new Error(`${host}${path} returned ${response.statusCode}`))
        );
      }
    );
    request.on("error", reject);
    request.end();
  });
}

// Prefer the conventional port; fall back to any free one if it is taken.
async function listen(preferred) {
  const handler = (_request, response) => response.end("ok");
  for (const port of [preferred, 0]) {
    const server = createServer(handler);
    const bound = await new Promise(resolve => {
      server.once("error", () => resolve(null));
      server.listen(port, "127.0.0.1", () => resolve(server.address().port));
    });
    if (bound !== null) {
      servers.push(server);
      return bound;
    }
  }
  throw new Error("no free port");
}
