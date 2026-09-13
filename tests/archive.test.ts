import assert from "node:assert/strict";
import test from "node:test";
import { strToU8, zipSync } from "fflate";
import { extractZip } from "../app/lib/archive.ts";

test("extracts supported source files and skips dependencies and binary content", () => {
  const archive = zipSync({
    "src/api.ts": strToU8("eval(req.query.code);"),
    "Dockerfile": strToU8("FROM node:22"),
    "node_modules/pkg/index.js": strToU8("eval('ignored')"),
    "assets/logo.png": new Uint8Array([0, 1, 2, 3]),
  });
  const result = extractZip(archive);
  assert.deepEqual(result.files.map((file) => file.name), ["Dockerfile", "src/api.ts"]);
  assert.equal(result.skippedFiles, 2);
});

test("skips generated SAST reports and temporary fixtures", () => {
  const archive = zipSync({
    "src/index.ts": strToU8("export const safe = true;"),
    "project-sast-report.json": strToU8('{"findings": [{"snippet": "eval(input)"}]}'),
    "tmp/repro.js": strToU8("eval(input)"),
  });
  const result = extractZip(archive);
  assert.deepEqual(result.files.map((file) => file.name), ["src/index.ts"]);
  assert.equal(result.skippedFiles, 2);
});

test("skips test sources and CodeSentry rule/demo fixtures during project scans", () => {
  const archive = zipSync({
    "src/index.ts": strToU8("export const safe = true;"),
    "tests/index.test.ts": strToU8("eval(userInput)"),
    "src/worker.spec.js": strToU8("eval(userInput)"),
    "app/lib/sast-engine.ts": strToU8("pattern: /eval\\s*\\(/"),
    "app/lib/demo-code.ts": strToU8("export const demo = `eval(userInput)`"),
  });
  const result = extractZip(archive);
  assert.deepEqual(result.files.map((file) => file.name), ["src/index.ts"]);
  assert.equal(result.skippedFiles, 4);
});

test("rejects traversal paths in ZIP archives", () => {
  const archive = zipSync({ "../outside.js": strToU8("eval(input)") });
  assert.throws(() => extractZip(archive), /Небезопасный путь/);
});
