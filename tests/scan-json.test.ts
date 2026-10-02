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
