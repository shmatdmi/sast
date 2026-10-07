import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";
import { createComposedRules } from "../app/lib/sast-rules-composed.ts";
import { getStaticRules, ruleCount, scanCode } from "../app/lib/sast-engine.ts";
import { createRuleSnapshot } from "../scripts/lib/sast-rule-seed.mjs";
import { extractZip } from "../app/lib/archive.ts";
import { zipSync, strToU8 } from "fflate";

test("70000 unique rules preserve the complete historical 20000 snapshot", () => {
  const rules = getStaticRules();
  assert.equal(ruleCount, 150036);
  assert.equal(createComposedRules().length, 50000);
  assert.equal(new Set(rules.map(r => r.id)).size, ruleCount);
  assert.equal(new Set(rules.map(r => `${r.languages}:${r.pattern}`)).size, ruleCount);
  const sql = readFileSync('drizzle/0008_framework_rule_catalog_20000.sql', 'utf8');
  const old = JSON.parse(sql.split("FROM jsonb_array_elements('")[1].split("'::jsonb)")[0].replaceAll("''", "'"));
  assert.deepEqual(createRuleSnapshot(rules.slice(0, 20000)).entries, old);
});

test("all 50000 expressions match composition and reject unrelated sources and wrappers", () => {
  for (const rule of createComposedRules()) {
    const [api, details] = rule.title.split(': ');
    const channel = details.split('HTTP-ввод из ')[1];
    const source = channel.endsWith('()') ? channel.slice(0, -2) + "('value')" : channel + "['value']";
    const operator = rule.languages.includes('php') ? '.' : '+';
    let expression = `'prefix' ${operator} ${source}`;
    if (rule.id.endsWith('_SUFFIX')) expression = `${source} ${operator} 'suffix'`;
    if (rule.id.endsWith('_TEMPLATE')) expression = '`prefix${' + source + '}suffix`';
    if (rule.id.endsWith('_FSTRING')) expression = 'f"prefix{' + source + '}suffix"';
    assert.ok(rule.pattern.test(`${api}(${expression})`), rule.id);
    for (const code of [`${api}(validate(${expression}))`, `${api}('fixed', ${expression})`, `unrelated${api}(${expression})`, `${api}(${expression.replace(channel.endsWith('()') ? channel.slice(0, -2) : channel, 'trusted')})`]) {
      assert.ok(!rule.pattern.test(code), `${rule.id}: ${code}`);
    }
    assert.equal(rule.confidence, 'medium');
    assert.ok(rule.recommendation.length > 30 && rule.references.length);
  }
});

test("scanner integration, coordinates, language boundaries and ZIP exclusion", () => {
  const examples = [
    ['a.ts', "axios.get('prefix' + req.query['value'])"],
    ['a.py', 'requests.get(f"prefix{request.body}suffix")'],
    ['a.php', "file_get_contents($request->input('value') . 'suffix')"],
    ['a.rb', "File.read('prefix' + request.body)"],
  ];
  for (const [file, code] of examples) {
    const found = scanCode(`// header\r\n  ${code}`, file).findings.filter(f => f.ruleId.startsWith('CMP_'));
    assert.equal(found.length, 1, code);
    assert.deepEqual([found[0].line, found[0].column], [2, 3]);
    assert.ok(!scanCode(code, 'a.go').findings.some(f => f.ruleId.startsWith('CMP_')));
  }
  const archive = extractZip(zipSync({ 'app/lib/sast-rules-composed.ts': strToU8('code'), 'src/a.ts': strToU8('code') }));
  assert.equal(archive.files.length, 1);
});

test("large safe corpus and malformed compositions complete within ten seconds", () => {
  const start = performance.now();
  for (const file of ['a.ts', 'a.py', 'a.php', 'a.rb']) {
    const code = 'ordinary text\n'.repeat(5000) + 'axios.get(' + ' '.repeat(50000) + '"prefix" + request.bodyExtra)';
    assert.ok(!scanCode(code, file).findings.some(f => f.ruleId.startsWith('CMP_')));
  }
  assert.ok(performance.now() - start < 10000);
  // Exercise long literals specifically against the new rules; unrelated legacy
  // assignment heuristics have quadratic behavior on very long identifier runs.
  const literal = 'axios.get("' + 'x'.repeat(50000) + '" + request.bodyExtra)';
  const longStart = performance.now();
  for (const rule of createComposedRules().filter(r => r.title.startsWith('axios.get:'))) {
    assert.ok(!rule.pattern.test(literal), rule.id);
  }
  assert.ok(performance.now() - longStart < 10000);
});
