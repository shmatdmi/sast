import assert from "node:assert/strict";
import test from "node:test";
import { detectLanguage, scanCode } from "../app/lib/sast-engine.ts";

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
