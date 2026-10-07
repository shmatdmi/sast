import assert from "node:assert/strict";
import test from "node:test";
import { getStaticRules, ruleCount, staticRuleIds } from "../app/lib/sast-engine.ts";
import { createRuleSeedSql, createRuleSnapshot } from "../scripts/lib/sast-rule-seed.mjs";

test("catalog snapshot preserves all built-in metadata, expressions and order", () => {
  const source = getStaticRules();
  const snapshot = createRuleSnapshot(source);
  assert.equal(snapshot.entries.length, ruleCount);
  assert.equal(snapshot.entries.length, ruleCount);
  assert.deepEqual(snapshot.entries.map((entry) => entry.ruleId), staticRuleIds);
  for (const [index, entry] of snapshot.entries.entries()) {
    const roundTrip = JSON.parse(JSON.stringify(entry.definition));
    const { pattern, exclude, scope, category, ...metadata } = source[index];
    const { pattern: storedPattern, patternFlags, exclude: storedExclude, excludeFlags, scope: storedScope, category: storedCategory, ...storedMetadata } = roundTrip;
    assert.deepEqual(storedMetadata, metadata, entry.ruleId);
    assert.equal(new RegExp(storedPattern, patternFlags).toString(), pattern.toString(), entry.ruleId);
    assert.equal(storedExclude === null ? undefined : new RegExp(storedExclude, excludeFlags).toString(), exclude?.toString(), entry.ruleId);
    assert.equal(storedScope, scope ?? "line");
    assert.equal(storedCategory, category ?? null);
  }
});

test("catalog fingerprints are stable and detect metadata, expression and ordering changes", () => {
  const source = getStaticRules();
  const original = createRuleSnapshot(source);
  assert.deepEqual(original, createRuleSnapshot());
  source[0].recommendation += " changed";
  const changed = createRuleSnapshot(source);
  assert.notEqual(changed.contentHash, original.contentHash);
  assert.notEqual(changed.entries[0].contentHash, original.entries[0].contentHash);
  assert.equal(changed.entries[1].contentHash, original.entries[1].contentHash);
  assert.notEqual(createRuleSnapshot([...getStaticRules()].reverse()).contentHash, original.contentHash);
  source[0].pattern = /changed-pattern/i;
  assert.notEqual(createRuleSnapshot(source).contentHash, changed.contentHash);
  assert.deepEqual(createRuleSnapshot(), original, "exported objects do not mutate the scanner");
});

test("seed rejects empty and duplicate catalogs before writing to PostgreSQL", () => {
  assert.throws(() => createRuleSnapshot([]), /empty/);
  const [rule] = getStaticRules();
  assert.throws(() => createRuleSnapshot([rule, rule]), /Duplicate/);
});

test("SQL seed escapes quotes and preserves backslashes and Unicode in definitions", () => {
  const [rule] = getStaticRules();
  rule.title = "Тест O'Reilly";
  rule.pattern = /\btest\s*\('value'\)/i;
  const seed = createRuleSeedSql(createRuleSnapshot([rule]));
  assert.ok(seed.includes("Тест O''Reilly"));
  assert.ok(seed.includes(JSON.stringify(rule.pattern.source).replaceAll("'", "''")));
  assert.ok(seed.includes("SET LOCAL standard_conforming_strings = on"));
});
