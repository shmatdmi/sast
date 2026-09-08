import assert from "node:assert/strict";
import test from "node:test";
import { detectLanguage, ruleCount, scanCode, scanFiles } from "../app/lib/sast-engine.ts";

test("detects supported languages by filename and content", () => {
  assert.equal(detectLanguage("service.py", "print('ok')"), "python");
  assert.equal(detectLanguage("handler.ts", "const ok = true"), "typescript");
  assert.equal(detectLanguage("snippet.txt", "<?php echo 'ok';"), "php");
});

test("finds representative critical and high-risk issues", () => {
  const code = [
    "const password = 'correct-horse-battery';",
    "const query = 'SELECT * FROM users WHERE id=' + userId;",
    "document.body.innerHTML = request.body;",
    "eval(request.query.code);",
  ].join("\n");

  const result = scanCode(code, "api.js");
  const ruleIds = result.findings.map((finding) => finding.ruleId);

  assert.equal(result.language, "javascript");
  assert.ok(ruleIds.includes("SEC001"));
  assert.ok(ruleIds.includes("SQL001"));
  assert.ok(ruleIds.includes("JS001"));
  assert.ok(ruleIds.includes("JS003"));
  assert.ok(result.summary.critical >= 3);
  assert.ok(result.summary.score < 60);
});

test("returns a clean score for safe code", () => {
  const result = scanCode("const greeting = 'hello';", "safe.ts");
  assert.equal(result.summary.total, 0);
  assert.equal(result.summary.score, 100);
});

test("ships an extended rule pack and detects infrastructure formats", () => {
  assert.ok(ruleCount >= 50);
  assert.equal(detectLanguage("Dockerfile", "FROM node:22"), "config");
  assert.equal(detectLanguage("compose.yaml", "services: {}"), "config");
  assert.equal(detectLanguage("deploy.sh", "#!/bin/bash"), "shell");
  assert.equal(detectLanguage("main.rs", "fn main() {}"), "rust");
});

test("detects provider secrets, unsafe crypto and container configuration", () => {
  const code = [
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
    "DATABASE_URL=postgres://admin:supersecret@db.internal/app",
    "privileged: true",
    "cipher: AES/ECB/PKCS5Padding",
  ].join("\n");
  const ids = scanCode(code, "compose.yaml").findings.map((finding) => finding.ruleId);
  assert.ok(ids.includes("SEC003"));
  assert.ok(ids.includes("SEC007"));
  assert.ok(ids.includes("CFG001"));
  assert.ok(ids.includes("CRYPTO002"));
});

test("tracks untrusted values across lines into sensitive sinks", () => {
  const code = [
    "const target = req.query.url;",
    "audit.log('proxy request');",
    "const response = await fetch(target);",
  ].join("\n");
  const finding = scanCode(code, "proxy.ts").findings.find((item) => item.ruleId === "FLOW-SSRF");
  assert.ok(finding);
  assert.equal(finding.line, 3);
  assert.equal(finding.cwe, "CWE-918");
  assert.match(finding.description, /строки 1/);
});

test("stops a tracked flow after an explicit validation step", () => {
  const code = [
    "const target = req.query.url;",
    "validateAllowedUrl(target);",
    "const response = await fetch(target);",
  ].join("\n");
  const ids = scanCode(code, "proxy.ts").findings.map((finding) => finding.ruleId);
  assert.ok(!ids.includes("FLOW-SSRF"));
});

test("finds security constructs spanning multiple lines", () => {
  const code = [
    "ServicePointManager.ServerCertificateValidationCallback =",
    "  (sender, certificate, chain, errors) => true;",
  ].join("\n");
  const finding = scanCode(code, "Client.cs").findings.find((item) => item.ruleId === "CS002");
  assert.ok(finding);
  assert.equal(finding.line, 1);
});

test("aggregates findings from multiple files and preserves their paths", () => {
  const result = scanFiles([
    { name: "src/api.ts", code: "eval(req.query.code);" },
    { name: "scripts/deploy.py", code: "password = 'production-secret'" },
  ]);
  assert.equal(result.filesScanned, 2);
  assert.equal(result.language, "multiple");
  assert.ok(result.findings.some((finding) => finding.filename === "src/api.ts"));
  assert.ok(result.findings.some((finding) => finding.filename === "scripts/deploy.py"));
});
