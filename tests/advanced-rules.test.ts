import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";
import { zipSync, strToU8 } from "fflate";
import { createAdvancedRules } from "../app/lib/sast-rules-advanced.ts";
import { createAdditionalRules } from "../app/lib/sast-rules-additional.ts";
import { createExpansionRules } from "../app/lib/sast-rules-expansion.ts";
import { createExtendedRules } from "../app/lib/sast-rules.ts";
import { ruleCount, scanCode, scanFiles, staticRuleIds } from "../app/lib/sast-engine.ts";
import { extractZip } from "../app/lib/archive.ts";

type Fixture = { id: string; family: string; unsafe: string; safe: string };
// Synthetic tokens are assembled only during tests to avoid publishing token-shaped literals.
const fixtures: Fixture[] = JSON.parse(readFileSync(new URL("./fixtures/advanced-rules.json", import.meta.url), "utf8"))
  .map((fixture: Fixture & { unsafeParts?: string[] }) => ({ ...fixture, unsafe: fixture.unsafeParts?.join("") ?? fixture.unsafe }));
const filenames: Record<string, string> = {
  SEC: "keys.env", JS: "code.ts", PY: "code.py", JAVA: "Code.java", PHP: "code.php", GO: "code.go",
  CS: "Code.cs", RB: "code.rb", RS: "code.rs", SWIFT: "Code.swift", SCALA: "Code.scala",
  SH: "deploy.sh", CFG: "settings.conf",
};
const rules = createAdvancedRules();
const previousIds = new Set(staticRuleIds.slice(0, 700));

test("fourth pack adds 300 distinct rules with fixtures and complete metadata", () => {
  assert.equal(rules.length, 300);
  assert.equal(ruleCount, 150036);
  assert.equal(new Set(staticRuleIds).size, ruleCount);
  assert.equal(new Set(fixtures.map(f => f.id)).size, 300);
  assert.deepEqual(fixtures.map(f => f.id).sort(), rules.map(r => r.id).sort());
  assert.equal(rules.filter(r => r.category === "secrets").length, 40);
  const earlier = [...createExtendedRules(["unknown"]), ...createExpansionRules(["unknown"]), ...createAdditionalRules()];
  const signatures = new Set(earlier.map(r => `${r.languages.join(",")}:${r.pattern}`));
  const titles = new Set(earlier.map(r => r.title));
  for (const rule of rules) {
    const signature = `${rule.languages.join(",")}:${rule.pattern}`;
    assert.ok(!signatures.has(signature), `duplicate signature ${rule.id}`);
    assert.ok(!titles.has(rule.title), `duplicate title ${rule.id}`);
    signatures.add(signature);
    titles.add(rule.title);
    assert.ok(staticRuleIds.includes(rule.id) && !previousIds.has(rule.id));
    assert.ok(rule.title.length > 8 && rule.description.length > 40 && rule.recommendation.length > 30, rule.id);
    assert.match(rule.cwe, /^CWE-\d+$/);
    assert.match(rule.owasp, /^A\d{2}:2021$/);
    assert.ok(rule.languages.length && rule.category && rule.references.length, rule.id);
    assert.equal(rule.confidence, rule.category === "secrets" ? "high" : "medium");
    assert.ok(!rule.pattern.global && !rule.pattern.sticky, rule.id);
  }
});

for (const { id, family, unsafe, safe } of fixtures) {
  test(`${id}: risky construct, safe alternative and applicability`, () => {
    const filename = filenames[family];
    const result = scanFiles([{ name: filename, code: unsafe }]);
    const matches = result.findings.filter(f => f.ruleId === id);
    assert.equal(matches.length, 1, `missing ${id}: ${unsafe}`);
    assert.equal(matches[0].filename, filename);
    assert.equal(matches[0].snippet, unsafe.trim().slice(0, 220));
    assert.ok(!result.findings.some(f => previousIds.has(f.ruleId)), `already covered by previous 700 rules: ${id}`);
    assert.ok(!scanCode(safe, filename).findings.some(f => f.ruleId === id), `false positive ${id}: ${safe}`);
    const unrelated = scanCode(unsafe, "other.txt", "unknown").findings.some(f => f.ruleId === id);
    assert.equal(unrelated, family === "SEC", `wrong language ${id}`);
    if (family === "JS") assert.ok(scanCode(unsafe, "code.js").findings.some(f => f.ruleId === id));
    if (family === "JAVA") assert.ok(scanCode(unsafe, "Code.kt").findings.some(f => f.ruleId === id));
  });
}

test("service credential signatures reject truncated, overlong and embedded tokens in every language", () => {
  for (const fixture of fixtures.filter(f => f.family === "SEC")) {
    for (const language of rules.find(r => r.id === fixture.id)!.languages) {
      assert.ok(scanCode(fixture.unsafe, "code.txt", language).findings.some(f => f.ruleId === fixture.id), `${fixture.id} ${language}`);
    }
    for (const nearMiss of ["x" + fixture.unsafe, fixture.unsafe + "x".repeat(401), fixture.unsafe.slice(0, 6)]) {
      assert.ok(!scanCode(nearMiss, "keys.env").findings.some(f => f.ruleId === fixture.id), `${fixture.id}: ${nearMiss}`);
    }
  }
});

test("new checks preserve CRLF positions, repeated findings and filenames", () => {
  const result = scanFiles([
    { name: "first.ts", code: "// header\r\n  ajv.compile(req.body.schema);\r\n  ajv.compile(req.body.schema);" },
    { name: "second.ts", code: "ajv.compile(req.body.schema);" },
  ]);
  const matches = result.findings.filter(f => f.ruleId === "JS302");
  assert.equal(matches.length, 3);
  assert.deepEqual(matches.filter(f => f.filename === "first.ts").map(f => [f.line, f.column]), [[2, 3], [3, 3]]);
  assert.equal(new Set(matches.map(f => f.id)).size, 3);
});

test("ZIP runs advanced checks and excludes internal catalog and fixtures", () => {
  const archive = extractZip(zipSync({
    "src/client.ts": strToU8("ajv.compile(req.body.schema);"),
    "infra/cloud.tf": strToU8('viewer_protocol_policy = "allow-all"'),
    "app/lib/sast-rules-advanced.ts": strToU8("ajv.compile(req.body.schema);"),
    "tests/fixtures/advanced-rules.json": strToU8('{"example":"sensitive"}'),
  }));
  assert.equal(archive.files.length, 2);
  assert.equal(archive.skippedFiles, 2);
  const result = scanFiles(archive.files);
  for (const id of ["JS302", "CFG303"]) assert.ok(result.findings.some(f => f.ruleId === id), id);
});

test("20000 rules handle long near-matches and large safe multi-language inputs", () => {
  const started = performance.now();
  const corpus = "// ordinary text\n".repeat(3000) + "x".repeat(20000);
  for (const filename of Object.values(filenames)) assert.equal(scanCode(corpus, filename).summary.total, 0, filename);
  const malformed = "sc_" + "a".repeat(20000) + ".acc_" + "a".repeat(20000);
  assert.equal(scanCode(malformed, "keys.env").summary.total, 0);
  assert.ok(performance.now() - started < 15000, "safe and malformed inputs exceeded 15 seconds");
});
