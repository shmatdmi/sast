import assert from "node:assert/strict";
import test from "node:test";
import { MAX_SCAN_JSON_BYTES, parseScanJson, readScanJson, ScanInputError } from "../app/lib/scan-json.ts";
import { scanFiles } from "../app/lib/sast-engine.ts";

const payload = () => ({ projectName: "Example", release: "TEST-1", files: [{ name: "src/app.js", code: "eval(req.query.code);\n" }] });
const inputError = (status: number) => (error: unknown) => error instanceof ScanInputError && error.status === status;
const request = (body: string, contentType = "application/json") => new Request("http://localhost/api/scans/json", {
  method: "POST", headers: { "content-type": contentType }, body,
});

test("JSON sources produce real findings with filenames and line counts", async () => {
  const input = payload();
  input.files.push({ name: "src/main.py", code: "# comment\n\nprint('hello')\n" });
  const parsed = parseScanJson(await readScanJson(request(JSON.stringify(input), "Application/JSON; charset=utf-8")));
  const result = scanFiles(parsed.files);
  assert.equal(result.filesScanned, 2);
  assert.equal(result.scannedLines, 4);
  assert.equal(result.language, "multiple");
  assert.ok(result.findings.some((finding) => finding.filename === "src/app.js" && finding.line === 1));
  assert.equal(parsed.projectName, "Example");
  assert.equal(parsed.release, "TEST-1");
});

test("rejects malformed JSON, wrong content type and invalid UTF-8", async () => {
  for (const text of ["{", "", '{"files":]}']) await assert.rejects(readScanJson(request(text)), inputError(400));
  await assert.rejects(readScanJson(request("{}", "text/plain")), inputError(415));
  await assert.rejects(readScanJson(new Request("http://localhost", {
    method: "POST", headers: { "content-type": "application/json" }, body: new Uint8Array([0xff]),
  })), inputError(400));
});

test("validates project, release and file fields", () => {
  for (const value of [null, [], 1, {}, { ...payload(), projectName: " " }, { ...payload(), projectName: "a".repeat(513) },
    { ...payload(), release: "TEST-0" }, { ...payload(), release: "TOOLONG-1" },
    { ...payload(), files: [] }, { ...payload(), files: [null] },
    { ...payload(), files: [{ name: "a.js", code: 1 }] }]) {
    assert.throws(() => parseScanJson(value), inputError(400));
  }
});

test("rejects unsafe, duplicate, binary and unsupported sources", () => {
  for (const name of ["../a.js", "/a.js", "C:\\a.js", "a/../b.js", "a//b.js", "a\0.js", "a.png", ""]) {
    assert.throws(() => parseScanJson({ ...payload(), files: [{ name, code: "" }] }), inputError(400));
  }
  assert.throws(() => parseScanJson({ ...payload(), files: [
    { name: "src\\app.js", code: "" }, { name: "src/app.js", code: "" },
  ] }), /Повторяющийся путь/);
  assert.throws(() => parseScanJson({ ...payload(), files: [{ name: "a.js", code: "\0" }] }), /бинарные данные/);
});

test("normalizes paths and accepts empty files and explicitly supplied tests", () => {
  const parsed = parseScanJson({ ...payload(), projectName: " Example ", release: " TEST-1 ", files: [
    { name: "tests\\app.test.js", code: "" },
  ] });
  assert.equal(parsed.projectName, "Example");
  assert.equal(parsed.release, "TEST-1");
  assert.deepEqual(parsed.files, [{ name: "tests/app.test.js", code: "", size: 0 }]);
  assert.equal(scanFiles(parsed.files).scannedLines, 0);
});

test("enforces UTF-8 byte limits and file count", () => {
  assert.throws(() => parseScanJson({ ...payload(), files: [{ name: "a.js", code: "я".repeat(524289) }] }), inputError(413));
  assert.equal(parseScanJson({ ...payload(), files: [{ name: "a.js", code: "a".repeat(1024 * 1024) }] }).files[0].size, 1024 * 1024);
  assert.throws(() => parseScanJson({ ...payload(), files: Array.from({ length: 501 }, (_, i) => ({ name: `${i}.js`, code: "" })) }), inputError(413));
  assert.throws(() => parseScanJson({ ...payload(), files: Array.from({ length: 21 }, (_, i) => ({ name: `${i}.js`, code: "a".repeat(1024 * 1024) })) }), inputError(413));
});

test("bounds request body even with missing or understated Content-Length", async () => {
  for (const declaredSize of [undefined, "1"]) {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) { controller.enqueue(new Uint8Array(1024 * 1024)); },
      cancel() { cancelled = true; },
    });
    const headers = new Headers({ "content-type": "application/json" });
    if (declaredSize) headers.set("content-length", declaredSize);
    const streamedRequest = new Request("http://localhost", { method: "POST", headers, body, duplex: "half" } as RequestInit);
    await assert.rejects(readScanJson(streamedRequest), inputError(413));
    assert.equal(cancelled, true);
  }
  const tooLarge = request("{}");
  tooLarge.headers.set("content-length", String(MAX_SCAN_JSON_BYTES + 1));
  await assert.rejects(readScanJson(tooLarge), inputError(413));
});

test("streaming decoder preserves UTF-8 characters split across chunk boundaries", async () => {
  const input = { ...payload(), projectName: "Проект 🔐", files: [{ name: "src/app.js", code: "// Привет 🌍" }] };
  const bytes = new TextEncoder().encode(JSON.stringify(input));
  let offset = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (offset === bytes.length) return controller.close();
      controller.enqueue(bytes.subarray(offset, ++offset));
    },
  });
  const streamed = new Request("http://localhost", {
    method: "POST", headers: { "content-type": "application/json" }, body, duplex: "half",
  } as RequestInit);
  assert.deepEqual(await readScanJson(streamed), input);
  assert.equal(streamed.body?.locked, false);
});

test("empty, broken and truncated UTF-8 streams are rejected and unlocked", async () => {
  await assert.rejects(readScanJson(new Request("http://localhost", { method: "POST", headers: { "content-type": "application/json" } })), inputError(400));
  for (const body of [
    new ReadableStream<Uint8Array>({ start(controller) { controller.error(new Error("network failure")); } }),
    new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(new Uint8Array([0xe2, 0x82])); controller.close(); } }),
  ]) {
    const streamed = new Request("http://localhost", { method: "POST", headers: { "content-type": "application/json" }, body, duplex: "half" } as RequestInit);
    await assert.rejects(readScanJson(streamed), inputError(400));
    assert.equal(streamed.body?.locked, false);
  }
});

test("release boundaries and maximum file count are accepted", () => {
  for (const release of ["AB-1", "test-9999"]) assert.equal(parseScanJson({ ...payload(), release }).release, release);
  const files = Array.from({ length: 500 }, (_, i) => ({ name: `src/${i}.js`, code: "" }));
  assert.equal(parseScanJson({ ...payload(), files }).files.length, 500);
});

test("unsafe dot segments and control characters are rejected after path normalization", () => {
  for (const name of ["src/./app.js", "src/../app.js", "src\\..\\app.js", "src/\tapp.js", "src/\u007fapp.js", "//server/app.js"]) {
    assert.throws(() => parseScanJson({ ...payload(), files: [{ name, code: "" }] }), inputError(400));
  }
});
