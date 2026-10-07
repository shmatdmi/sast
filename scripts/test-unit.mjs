import { readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";

const tests = readdirSync("tests").filter(name => /\.test\.(?:ts|mjs)$/.test(name)
  && !/(?:-db|\.integration)\.test\./.test(name) && name !== "rendered-html.test.mjs")
  .sort().map(name => `tests/${name}`);
const coverage = process.argv.includes("--coverage");
const args = [
  ...(coverage ? ["--experimental-test-coverage", "--test-coverage-include=app/lib/*.ts", "--test-coverage-include=scripts/lib/*.mjs"] : []),
  "--test", "--test-concurrency=2", ...tests,
];
const result = spawnSync(process.execPath, args, { stdio: "inherit", windowsHide: true });
if (result.error) console.error(result.error.message);
process.exitCode = result.status ?? 1;
