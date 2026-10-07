import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";
import { zipSync, strToU8 } from "fflate";
import { createAdditionalRules } from "../app/lib/sast-rules-additional.ts";
import { createExpansionRules } from "../app/lib/sast-rules-expansion.ts";
import { createExtendedRules } from "../app/lib/sast-rules.ts";
import { ruleCount, scanCode, scanFiles, staticRuleIds } from "../app/lib/sast-engine.ts";
import { extractZip } from "../app/lib/archive.ts";

type Fixture = { id: string; family: string; unsafe: string; safe: string };
const fixtures: Fixture[] = JSON.parse(readFileSync(new URL("./fixtures/additional-rules.json", import.meta.url), "utf8"))
  .map((fixture: Fixture & { unsafeParts?: string[] }) => ({ ...fixture, unsafe: fixture.unsafeParts?.join("") ?? fixture.unsafe }));
const filenames: Record<string, string> = {
  JS: "code.ts", PY: "code.py", JAVA: "Code.java", PHP: "code.php", GO: "code.go",
  CS: "Code.cs", RB: "code.rb", RS: "code.rs", SWIFT: "Code.swift", SCALA: "Code.scala",
  SH: "deploy.sh", CFG: "settings.conf",
};
const rules = createAdditionalRules();
// Rules that existed before this pack; later packs may detect additional risks.
const previousIds = new Set(staticRuleIds.slice(0, 400));

test("300 new rules have stable unique IDs, fixtures and complete metadata", () => {
  assert.equal(rules.length, 300);
  assert.equal(ruleCount, 150036);
  assert.equal(new Set(staticRuleIds).size, ruleCount);
  assert.equal(new Set(fixtures.map(f => f.id)).size, 300);
  assert.deepEqual(fixtures.map(f => f.id).sort(), rules.map(r => r.id).sort());
  const knownSignatures = new Set([...createExtendedRules(["unknown"]), ...createExpansionRules(["unknown"])]
    .map(r => `${r.languages.join(",")}:${r.pattern}`));
  const titles = new Set<string>();
  for (const rule of rules) {
    const signature = `${rule.languages.join(",")}:${rule.pattern}`;
    assert.ok(!knownSignatures.has(signature), `duplicate signature ${rule.id}`);
    assert.ok(!titles.has(rule.title), `duplicate title ${rule.id}`);
    knownSignatures.add(signature);
    titles.add(rule.title);
    assert.ok(staticRuleIds.includes(rule.id));
    assert.ok(rule.title.length > 8 && rule.description.length > 40 && rule.recommendation.length > 30, rule.id);
    assert.match(rule.cwe, /^CWE-\d+$/);
    assert.match(rule.owasp, /^A\d{2}:2021$/);
    assert.ok(rule.languages.length && rule.category && rule.references.length, rule.id);
    assert.equal(rule.confidence, "medium");
    assert.ok(!rule.pattern.global && !rule.pattern.sticky, rule.id);
  }
});

for (const { id, family, unsafe, safe } of fixtures) {
  test(`${id}: detects risky input and accepts safe alternative`, () => {
    const filename = filenames[family];
    const matches = scanFiles([{ name: filename, code: unsafe }]).findings.filter(f => f.ruleId === id);
    assert.equal(matches.length, 1, `missing ${id}: ${unsafe}`);
    assert.equal(matches[0].snippet, unsafe.trim().slice(0, 220));
    assert.equal(matches[0].filename, filename);
    assert.ok(!scanCode(unsafe, filename).findings.some(f => previousIds.has(f.ruleId)), `fixture already covered by old rules: ${id}`);
    assert.ok(!scanCode(safe, filename).findings.some(f => f.ruleId === id), `false positive ${id}: ${safe}`);
    assert.ok(!scanCode(unsafe, "other.txt", "unknown").findings.some(f => f.ruleId === id), `wrong language ${id}`);
    if (family === "JS") assert.ok(scanCode(unsafe, "code.js").findings.some(f => f.ruleId === id));
    if (family === "JAVA") assert.ok(scanCode(unsafe, "Code.kt").findings.some(f => f.ruleId === id));
  });
}

test("new rules preserve CRLF coordinates, repeated findings and file IDs", () => {
  const result = scanFiles([
    { name: "first.ts", code: "// header\r\n  helmet({ contentSecurityPolicy: false });\r\n  helmet({ contentSecurityPolicy: false });" },
    { name: "second.ts", code: "helmet({ contentSecurityPolicy: false });" },
  ]);
  const matches = result.findings.filter(f => f.ruleId === "JS223");
  assert.equal(matches.length, 3);
  assert.deepEqual(matches.filter(f => f.filename === "first.ts").map(f => [f.line, f.column]), [[2, 12], [3, 12]]);
  assert.equal(new Set(matches.map(f => f.id)).size, 3);
});

test("ZIP scans new rules and excludes the catalog and fixtures", () => {
  const archive = extractZip(zipSync({
    "src/client.ts": strToU8("helmet({ contentSecurityPolicy: false });"),
    "infra/cloud.tf": strToU8('http_tokens = "optional"'),
    "app/lib/sast-rules-additional.ts": strToU8("helmet({ contentSecurityPolicy: false });"),
    "tests/fixtures/additional-rules.json": strToU8('{"http_tokens":"optional"}'),
  }));
  assert.equal(archive.files.length, 2);
  assert.equal(archive.skippedFiles, 2);
  const result = scanFiles(archive.files);
  for (const id of ["JS223", "CFG207"]) assert.ok(result.findings.some(f => f.ruleId === id), id);
});

test("20000 rules handle long nonmatching lines and a multi-language safe corpus", () => {
  const started = performance.now();
  const corpus = "// ordinary text\n".repeat(3000) + "x".repeat(20000);
  for (const filename of Object.values(filenames)) {
    const result = scanCode(corpus, filename);
    assert.equal(result.summary.total, 0, filename);
    assert.equal(result.scannedLines, 3001);
  }
  assert.ok(performance.now() - started < 15000, "safe corpus exceeded 15 seconds");
});
