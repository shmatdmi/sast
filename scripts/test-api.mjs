import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import postgres from "postgres";

// Always provision our own database. Never use DATABASE_URL from the environment.
const container = `codesentry-api-test-${randomBytes(8).toString("hex")}`;
const password = randomBytes(24).toString("hex");
const docker = (args) => {
  const result = spawnSync("docker", args, { encoding: "utf8", windowsHide: true });
  if (result.error || result.status !== 0) throw new Error(result.error?.message || result.stderr || "Docker command failed");
  return result.stdout.trim();
};
let started = false;
let client;
let child;
let exitCode = 1;
const stop = () => {
  child?.kill();
  if (started) {
    spawnSync("docker", ["stop", "--time", "1", container], { stdio: "ignore", windowsHide: true });
    started = false;
  }
};
process.once("SIGINT", () => { stop(); process.exit(130); });
process.once("SIGTERM", () => { stop(); process.exit(143); });
try {
  docker(["run", "--detach", "--rm", "--name", container,
    "--publish", "127.0.0.1::5432", "--tmpfs", "/var/lib/postgresql/data",
    "--env", "POSTGRES_USER=sast_test", "--env", "POSTGRES_DB=sast_test",
    "--env", `POSTGRES_PASSWORD=${password}`, "postgres:17-alpine"]);
  started = true;
  const mapping = docker(["port", container, "5432/tcp"]);
  const port = mapping.match(/^127\.0\.0\.1:(\d+)$/)?.[1];
  if (!port) throw new Error("Test database must bind only to loopback");
  const url = `postgres://sast_test:${password}@127.0.0.1:${port}/sast_test`;
  client = postgres(url, { max: 1, connect_timeout: 1 });
  let ready = false;
  for (let attempt = 0; attempt < 60; attempt++) {
    try { await client`select 1`; ready = true; break; }
    catch { await delay(500); }
  }
  if (!ready) throw new Error("Temporary PostgreSQL did not become ready");
  await client.end();
  client = undefined;
  console.log("Running API tests against a temporary PostgreSQL container (production credentials are ignored).");
  child = spawn(process.execPath, ["--test", "--test-concurrency=1", "tests/api.integration.test.mjs"], {
    stdio: "inherit", windowsHide: true,
    env: { ...process.env, NODE_ENV: "test", DATABASE_URL: url, API_TEST_DATABASE_URL: url,
      INITIAL_ADMIN_USERNAME: "test-admin", INITIAL_ADMIN_PASSWORD: "admin-test-password", AUTH_COOKIE_SECURE: "true" },
  });
  exitCode = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", code => resolve(code ?? 1));
  });
} catch (error) {
  console.error(error.message);
} finally {
  await client?.end();
  stop();
}
process.exitCode = exitCode;
