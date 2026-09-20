import { spawnSync } from "node:child_process";
import packageMetadata from "../package.json" with { type: "json" };

const buildId = new Date().toISOString().replace(/[-:.]/g, "");
const version = `${packageMetadata.version}+build.${buildId}`;
const shouldPush = process.argv.includes("--push");

console.log(`${shouldPush ? "Building and publishing" : "Building"} shmatdmi/codesentry-sast:latest with application version ${version}`);

const result = spawnSync("docker", ["compose", "build", ...(shouldPush ? ["--push"] : [])], {
  env: { ...process.env, APP_BUILD_VERSION: version },
  stdio: "inherit",
  shell: process.platform === "win32",
});

if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}

process.exit(result.status ?? 1);
