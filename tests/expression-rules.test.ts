import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { performance } from "node:perf_hooks";
import { zipSync, strToU8 } from "fflate";
import { createExpressionRules, getExpressionRuleApi } from "../app/lib/sast-rules-expressions.ts";
import { getStaticRules, ruleCount, scanCode, scanFiles } from "../app/lib/sast-engine.ts";
import { createRuleSnapshot } from "../scripts/lib/sast-rule-seed.mjs";
import { extractZip } from "../app/lib/archive.ts";

test("150000 distinct definitions preserve the entire historical 70000 snapshot", () => {
  const rules=getStaticRules();
  assert.equal(ruleCount,150036);
  assert.equal(createExpressionRules().length,80000);
  assert.equal(new Set(rules.map(r=>r.id)).size,ruleCount);
  assert.equal(new Set(rules.map(r=>`${r.languages}:${r.pattern}`)).size,ruleCount);
  const sql=readFileSync('drizzle/0009_composed_rule_catalog_70000.sql','utf8');
  const historical=JSON.parse(sql.split("FROM jsonb_array_elements('")[1].split("'::jsonb)")[0].replaceAll("''","'"));
  assert.deepEqual(createRuleSnapshot(rules.slice(0,70000)).entries,historical);
});

for(const [language,count] of [['javascript',31500],['python',31500],['php',8500],['ruby',8500]] as const) {
  test(`${language}: every new API/source/form detects risk and rejects wrappers`,()=>{
    const output=execFileSync(process.execPath,['tests/fixtures/expression-rules-check.mjs',language],{encoding:'utf8',timeout:120000});
    assert.deepEqual(JSON.parse(output),{language,count});
  });
}

test("all 400 API groups integrate with language index and CRLF positions",()=>{
  const representatives=new Map<string,ReturnType<typeof createExpressionRules>[number]>();
  for(const rule of createExpressionRules()) if(rule.id.endsWith('_GROUP')) {
    const api=getExpressionRuleApi(rule.id)!;
    representatives.set(`${rule.languages[0]}:${api}`,rule);
  }
  assert.equal(representatives.size,400);
  for(const rule of representatives.values()) {
    const api=getExpressionRuleApi(rule.id)!;
    const channel=rule.title.split('HTTP-ввод из ')[1];
    const expression=channel.endsWith('()')?channel.slice(0,-2)+'()':channel;
    const file={javascript:'a.ts',python:'a.py',php:'a.php',ruby:'a.rb'}[rule.languages[0]]!;
    const code=`// header\r\n  ${api}((${expression}))`;
    const found=scanCode(code,file).findings.filter(f=>f.ruleId===rule.id);
    assert.equal(found.length,1,rule.id);
    assert.deepEqual([found[0].line,found[0].column],[2,3]);
    assert.ok(!scanCode(code,'a.go').findings.some(f=>f.ruleId===rule.id));
  }
});

test("repeated findings, fallback boundaries and ZIP self-exclusion",()=>{
  const code="axios.get(req.query['value'] || 'default')";
  const findings=scanFiles([{name:'a.ts',code:code+'\r\n'+code},{name:'b.ts',code}]).findings.filter(f=>f.ruleId==='EXPR_HTTPJS281_FALLBACK');
  assert.equal(findings.length,3);
  assert.equal(new Set(findings.map(f=>f.id)).size,3);
  for(const source of ["req.queryExtra['value']", "obj.req.query['value']", "validate(req.query['value'])"]) assert.ok(!scanCode(`axios.get(${source} || 'default')`,'a.ts').findings.some(f=>f.ruleId.startsWith('EXPR_')));
  const archive=extractZip(zipSync({'src/a.ts':strToU8(code),'app/lib/sast-rules-expressions.ts':strToU8(code)}));
  assert.equal(archive.files.length,1);
});

test("150000-rule safe corpus and malformed expressions complete within ten seconds",()=>{
  const start=performance.now();
  for(const file of ['a.ts','a.py','a.php','a.rb']) {
    const code='ordinary text\n'.repeat(5000)+'axios.get('+' '.repeat(50000)+"(request.bodyExtra) || 'default')";
    assert.ok(!scanCode(code,file).findings.some(f=>f.ruleId.startsWith('EXPR_')));
  }
  assert.ok(performance.now()-start<10000);
});
