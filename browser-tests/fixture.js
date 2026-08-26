import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Spawns the prebuilt fixture binary (built by the pretest script): `cargo
// run` would recompile the whole crate inside the hook timeout and does not
// forward signals to the child on teardown.
export async function startFixture() {
  const stateDirectory = await mkdtemp(join(tmpdir(), "hostknot-playwright-"));
  const port = await availablePort();
  const fixtureBinary = new URL(
    "../target/debug/examples/browser_fixture",
    import.meta.url
  ).pathname;
  const processHandle = spawn(fixtureBinary, [], {
    cwd: new URL("..", import.meta.url),
    env: {
      ...process.env,
      HOSTKNOT_BROWSER_LISTEN: `127.0.0.1:${port}`,
      HOSTKNOT_BROWSER_STATE: stateDirectory
    },
    stdio: ["ignore", "pipe", "inherit"]
  });
  const { setupUrl, upstreamPort } = await new Promise((resolve, reject) => {
    let output = "";
    const timeout = setTimeout(
      () => reject(new Error("HostKnot fixture did not start")),
      60_000
    );
    processHandle.once("exit", code =>
      reject(new Error(`HostKnot exited with ${code}`))
    );
    processHandle.stdout.on("data", chunk => {
      output += chunk.toString();
      const setupMatch = output.match(/http:\/\/[^\s]+\/setup\?token=[^\s]+/);
      const portMatch = output.match(/upstream-port: (\d+)/);
      if (setupMatch && portMatch) {
        clearTimeout(timeout);
        resolve({ setupUrl: setupMatch[0], upstreamPort: Number(portMatch[1]) });
      }
    });
  });
  return {
    setupUrl,
    upstreamPort,
    baseUrl: setupUrl.replace(/\/setup.*$/, ""),
    async stop() {
      processHandle.kill("SIGINT");
      await rm(stateDirectory, { recursive: true, force: true });
    }
  };
}

async function availablePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => resolve(address.port));
    });
  });
}
