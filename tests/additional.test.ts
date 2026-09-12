import assert from "node:assert/strict";
import test from "node:test";
import { strToU8, zipSync } from "fflate";
import {
  MAX_ARCHIVE_BYTES,
  MAX_SOURCE_FILE_BYTES,
  extractZip,
  isSupportedSourceFile,
} from "../app/lib/archive.ts";
import {
  detectLanguage,
  scanCode,
  scanFiles,
} from "../app/lib/sast-engine.ts";

function ruleIds(code: string, filename: string) {
  return scanCode(code, filename).findings.map((finding) => finding.ruleId);
}

test("recognizes supported source files case-insensitively", () => {
  for (const name of [
    "index.js", "view.TSX", "service.py", "Main.java", "main.go",
    "Program.cs", "lib.rb", "App.kt", "main.rs", "run.sh",
    "compose.yml", ".env", "Dockerfile",
  ]) {
    assert.equal(isSupportedSourceFile(name), true, name);
  }
  assert.equal(isSupportedSourceFile("archive.zip"), false);
  assert.equal(isSupportedSourceFile("image.png"), false);
});

test("detects every advertised language by extension", () => {
  const cases = {
    "app.js": "javascript",
    "app.ts": "typescript",
    "app.py": "python",
    "App.java": "java",
    "index.php": "php",
    "main.go": "go",
    "Program.cs": "csharp",
    "app.rb": "ruby",
    "App.kt": "kotlin",
    "main.rs": "rust",
    "App.swift": "swift",
    "Main.scala": "scala",
    "deploy.sh": "shell",
    "compose.yaml": "config",
  };
  for (const [filename, language] of Object.entries(cases)) {
    assert.equal(detectLanguage(filename, ""), language, filename);
  }
  assert.equal(detectLanguage("unknown.file", "plain text"), "unknown");
});

test("representative rules work across language families", () => {
  const cases = [
    ["eval(input);", "app.js", "JS001"],
    ["pickle.load(payload)", "app.py", "PY005"],
    ["new ObjectInputStream(stream);", "App.java", "JAVA002"],
    ["<?php unserialize($data);", "index.php", "PHP002"],
    ["tls.Config{InsecureSkipVerify: true}", "main.go", "GO002"],
    ["var formatter = new BinaryFormatter();", "Program.cs", "CS001"],
    ["Marshal.load(data)", "app.rb", "RB001"],
    ["ObjectInputStream(stream)", "App.kt", "JAVA002"],
    ["chmod 777 app", "deploy.sh", "CFG003"],
    ["privileged: true", "compose.yaml", "CFG001"],
  ];
  for (const [code, filename, ruleId] of cases) {
    assert.ok(ruleIds(code, filename).includes(ruleId), filename + " -> " + ruleId);
  }
});

test("normalizes line endings and returns a stable finding contract", () => {
  const result = scanCode("const safe = true;\r\neval(value);", "app.js");
  const finding = result.findings.find((item) => item.ruleId === "JS001");
  assert.ok(finding);
  assert.equal(finding.line, 2);
  assert.equal(finding.column, 1);
  assert.equal(finding.snippet, "eval(value);");
  assert.equal(finding.cwe, "CWE-95");
  assert.match(finding.references[0], /^https:\/\/cwe\.mitre\.org\//);
  assert.equal(result.scannedLines, 2);
  assert.equal(result.summary.score, 72);
});

test("honors a manually selected language and exclusions", () => {
  const forced = scanCode("eval(value)", "snippet.txt", "python");
  assert.equal(forced.language, "python");
  assert.ok(forced.findings.some((finding) => finding.ruleId === "PY001"));
  assert.ok(!forced.findings.some((finding) => finding.ruleId === "JS001"));

  const excluded = scanCode(
    "password = 'example-secret'\nyaml.load(data, Loader=yaml.SafeLoader)",
    "safe.py",
  );
  assert.ok(!excluded.findings.some((finding) => finding.ruleId === "SEC001"));
  assert.ok(!excluded.findings.some((finding) => finding.ruleId === "PY002"));
});

test("detects direct secret comparison without flagging constant-time comparison", () => {
  const unsafe = ruleIds("if (token === suppliedToken) allow();", "auth.ts");
  assert.ok(unsafe.includes("AUTH001"));

  const safe = ruleIds("timingSafeEqual(token, suppliedToken);", "auth.ts");
  assert.ok(!safe.includes("AUTH001"));
});

test("tracks user input into sensitive operations and aggregates files", () => {
  const sql = scanCode(
    "const value = req.query.value;\naudit.log('request');\ndb.query(value);",
    "api.ts",
  );
  assert.ok(sql.findings.some((finding) => finding.ruleId === "FLOW-SQL"));

  const safe = scanCode(
    "const value = req.query.value;\nvalidateInput(value);\ndb.query(value);",
    "api.ts",
  );
  assert.ok(!safe.findings.some((finding) => finding.ruleId === "FLOW-SQL"));

  const combined = scanFiles([
    { name: "api.ts", code: "eval(value);" },
    { name: "worker.py", code: "pickle.load(value)" },
  ]);
  assert.equal(combined.language, "multiple");
  assert.equal(combined.filesScanned, 2);
  assert.ok(combined.findings.every((finding) => Boolean(finding.filename)));
});

test("rejects oversized, corrupt and source-less ZIP input", () => {
  assert.throws(() => extractZip(new Uint8Array(MAX_ARCHIVE_BYTES + 1)));
  assert.throws(() => extractZip(strToU8("not a zip")));
  assert.throws(() => extractZip(zipSync({ "README.md": strToU8("docs") })));

  const archive = zipSync({
    "large.js": strToU8("a".repeat(MAX_SOURCE_FILE_BYTES + 1)),
    "src/ok.ts": strToU8("const ok = true;"),
  });
  const extracted = extractZip(archive);
  assert.deepEqual(extracted.files.map((file) => file.name), ["src/ok.ts"]);
  assert.equal(extracted.skippedFiles, 1);
});
