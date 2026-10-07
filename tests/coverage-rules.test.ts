import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { strToU8, zipSync } from "fflate";
import { createCoverageRules } from "../app/lib/sast-rules-coverage.ts";
import { supportedLanguages, supportedLanguageCount, languageLabels } from "../app/lib/sast-languages.ts";
import { acceptedSourceExtensions, extractZip, isSupportedSourceFile } from "../app/lib/archive.ts";
import { detectLanguage, getStaticRules, ruleCount, scanCode, scanFiles } from "../app/lib/sast-engine.ts";
import { parseScanJson } from "../app/lib/scan-json.ts";
import { createRuleSnapshot } from "../scripts/lib/sast-rule-seed.mjs";
import { createRuleExtensionSql } from "../scripts/lib/sast-rule-extension.mjs";

type Fixture = { id: string; unsafe: string; safe: string; language?: string; name?: string };
const fixtures: Fixture[] = JSON.parse(readFileSync(new URL("./fixtures/coverage-rules.json", import.meta.url), "utf8"))
  .map((fixture: Fixture & { unsafeParts?: string[] }) => ({ ...fixture, unsafe: fixture.unsafeParts?.join("") ?? fixture.unsafe }));
const rules = createCoverageRules();
const specific = fixtures.filter((fixture) => fixture.language);
const representatives = [...new Map(specific.map((fixture) => [fixture.language!, fixture])).values()];

test("coverage has twenty real analysis groups with upload and selector support", () => {
  assert.equal(supportedLanguageCount, 20);
  assert.equal(new Set(supportedLanguages.map((language) => language.id)).size, 20);
  for (const { id, label, extensions } of supportedLanguages) {
    assert.equal(languageLabels[id], label);
    for (const extension of extensions) {
      const name = `src/file.${extension}`;
      assert.ok(acceptedSourceExtensions.includes(extension));
      assert.ok(isSupportedSourceFile(name));
      assert.equal(detectLanguage(name, ""), id);
    }
  }
});

test("appends 36 rules while preserving the 150000-rule catalog fingerprint", () => {
  assert.equal(rules.length, 36);
  assert.equal(ruleCount, 150036);
  assert.deepEqual(new Set(fixtures.map((fixture) => fixture.id)), new Set(rules.map((rule) => rule.id)));
  const catalog = getStaticRules();
  const parent = createRuleSnapshot(catalog.slice(0, 150000));
  const sql = readFileSync("drizzle/0010_expression_rule_catalog_150000.sql", "utf8");
  assert.ok(sql.startsWith(`-- Built-in catalog: ${parent.name}; 150000 static rules.`));
  assert.deepEqual(catalog.slice(150000).map((rule) => rule.id), rules.map((rule) => rule.id));
});

for (const fixture of fixtures) {
  test(`${fixture.id}: detects unsafe code and rejects the safe alternative`, () => {
    const rule = rules.find((candidate) => candidate.id === fixture.id)!;
    const targets = fixture.language ? [{ language: fixture.language, name: fixture.name! }] : representatives.map((item) => ({ language: item.language!, name: item.name! }));
    for (const { language, name } of targets) {
      const result = scanCode(`\r\n${fixture.unsafe}\r\n`, name);
      assert.equal(result.language, language);
      const finding = result.findings.find((item) => item.ruleId === fixture.id);
      assert.ok(finding, `${name}: ${fixture.unsafe}`);
      assert.equal(finding.line, 2);
      assert.equal(finding.cwe, rule.cwe);
      assert.equal(finding.recommendation, rule.recommendation);
      assert.equal(finding.confidence, "medium");
      assert.ok(!scanCode(fixture.safe, name).findings.some((item) => item.ruleId === fixture.id), fixture.safe);
      assert.ok(!scanCode(fixture.unsafe, "wrong.txt", "unknown").findings.some((item) => item.ruleId === fixture.id));
    }
  });
}

test("detects pasted snippets and disambiguates shared C/C++ headers", () => {
  for (const [code, language] of [
    ["#include <stdio.h>\nint main(void) {}", "c"],
    ["#include <iostream>\nusing namespace std;", "cpp"],
    ["import 'dart:io';\nvoid main() {}", "dart"],
    ["defmodule Example do\nend", "elixir"],
    ["local command = input\nos.execute(command)", "lua"],
    ["Invoke-Expression -Command $input", "powershell"],
  ]) assert.equal(detectLanguage("snippet.txt", code), language);
  assert.equal(detectLanguage("header.h", "namespace example { class Item {}; }"), "cpp");
  assert.equal(detectLanguage("header.h", "int lookup(void);"), "c");
  assert.equal(detectLanguage("main.C", ""), "cpp");
  assert.equal(detectLanguage("data.json", "Invoke-Expression text"), "config");
});

test("ZIP and JSON API sources retain six language findings and filenames", () => {
  const files = representatives.map(({ name, unsafe }) => ({ name: `src/${name}`, code: unsafe }));
  const zip = zipSync({ ...Object.fromEntries(files.map(({ name, code }) => [name, strToU8(code)])),
    "app/lib/sast-rules-coverage.ts": strToU8("const pattern = /gets/;"),
    "app/lib/sast-languages.ts": strToU8("export const metadata = [];"),
  });
  const extracted = extractZip(zip);
  assert.equal(extracted.files.length, 6);
  assert.equal(extracted.skippedFiles, 2);
  const parsed = parseScanJson({ projectName: "Coverage", release: "TEST-20", files });
  for (const sources of [extracted.files, parsed.files]) {
    const result = scanFiles(sources);
    assert.equal(result.filesScanned, 6);
    assert.equal(result.language, "multiple");
    for (const { id, name } of representatives) assert.ok(result.findings.some((finding) => finding.ruleId === id && finding.filename === `src/${name}`));
  }
});

test("compact migration matches current snapshot and rejects changed parent definitions", () => {
  const all = getStaticRules();
  const base = createRuleSnapshot(all.slice(0, 150000));
  const snapshot = createRuleSnapshot(all);
  const sql = createRuleExtensionSql(base, snapshot);
  assert.equal(readFileSync("drizzle/0011_coverage_20_languages.sql", "utf8"), sql);
  assert.ok(Buffer.byteLength(sql) < 70000, "the migration embeds only the appended definitions");
  const changed = structuredClone(snapshot);
  changed.entries[0].definition.title += " changed";
  assert.throws(() => createRuleExtensionSql(base, changed), /preserve/);
  assert.throws(() => createRuleExtensionSql(base, base), /preserve/);
});
