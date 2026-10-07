import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";
import { zipSync, strToU8 } from "fflate";
import { createFrameworkRules, getFrameworkRuleApi } from "../app/lib/sast-rules-framework.ts";
import { getStaticRules, ruleCount, scanCode, scanFiles } from "../app/lib/sast-engine.ts";
import { createRuleSnapshot } from "../scripts/lib/sast-rule-seed.mjs";
import { extractZip } from "../app/lib/archive.ts";

// Independent access expressions; property, getter and async body-reader fixtures.
const fixtures = [
  { family: "JS", file: "a.ts", other: "a.py", expressions: [
    "req.payload.value", "req.rawBody", "req.originalUrl", "req.url", "req.hostname", "req.signedCookies.value",
    "request.payload.value", "request.headers['x-value']", "request.cookies.value", "request.rawBody", "request.url", "request.hostname",
    "ctx.params.value", "ctx.headers['x-value']", "ctx.request.query.value", "ctx.request.headers['x-value']", "ctx.request.rawBody",
    "ctx.request.url", "ctx.request.hostname", "ctx.request.files.value",
    "req.get('x-value')", "req.header('x-value')", "req.param('value')", "request.get('x-value')", "request.header('x-value')",
    "request.param('value')", "ctx.get('x-value')", "ctx.cookies.get('value')", "await request.json()", "await request.text()",
    "await request.formData()", "await req.json()", "await req.text()", "await req.formData()",
    "await event.request.json()", "await event.request.text()", "await event.request.formData()",
    "request.nextUrl.searchParams.get('value')", "req.nextUrl.searchParams.get('value')", "c.req.query('value')",
  ] },
  { family: "PY", file: "a.py", other: "a.ts", expressions: [
    "self.request.arguments['value']", "self.request.body", "self.request.headers['x-value']", "self.request.query_arguments['value']",
    "self.request.body_arguments['value']", "self.request.cookies['value']", "self.request.path", "self.request.uri", "self.request.host",
    "self.path_args[0]", "self.path_kwargs['value']", "request.data", "request.body", "request.query_string", "request.META['HTTP_X_VALUE']",
    "request.url", "request.path", "request.host", "request.rel_url", "request.match_info['value']",
    "self.get_argument('value')", "self.get_arguments('value')", "self.get_query_argument('value')", "self.get_query_arguments('value')",
    "self.get_body_argument('value')", "self.get_body_arguments('value')", "self.get_cookie('value')",
    "request.get_json()", "request.get_data()", "request.get_cookie('value')", "request.get_param('value')", "request.get_param_as_list('value')",
    "request.get_param_as_int('value')", "request.get_header('x-value')", "request.get_media()",
    "await request.text()", "await request.json()", "await request.post()", "bottle.request.get_cookie('value')", "flask.request.get_json()",
  ] },
  { family: "PHP", file: "a.php", other: "a.py", expressions: [
    "$request->input('value')", "$request->query('value')", "$request->post('value')", "$request->get('value')", "$request->cookie('value')",
    "$request->header('x-value')", "$request->file('value')", "$request->getContent()", "$request->getPayload()->get('value')", "$request->toArray()['value']",
    "$request->getQueryParams()['value']", "$request->getParsedBody()['value']", "$request->getCookieParams()['value']", "$request->getUploadedFiles()['value']",
    "$request->getHeader('x-value')", "$request->getHeaderLine('x-value')", "$request->getBody()", "$request->getUri()",
    "$request->getServerParams()['HTTP_X_VALUE']", "$request->getAttribute('value')",
    "request()->input('value')", "request()->query('value')", "request()->post('value')", "request()->cookie('value')", "request()->header('x-value')",
    "$this->request->getGet('value')", "$this->request->getPost('value')", "$this->request->getCookie('value')",
    "$this->request->getHeaderLine('x-value')", "$this->request->getBody()",
  ] },
  { family: "RB", file: "a.rb", other: "a.py", expressions: [
    "request.body", "request.raw_post", "request.query_string", "request.fullpath", "request.original_url",
    "request.url", "request.path", "request.host", "request.headers['x-value']", "request.referer", "request.user_agent",
    "request.media_type", "request.authorization", "request.remote_ip", "request.ip", "request.content_type", "request.path_info", "request.script_name",
    "env['HTTP_X_VALUE']", "controller.params[:value]", "controller.request.params['value']", "controller.request.cookies['value']",
    "controller.request.headers['x-value']", "controller.request.body", "controller.request.query_parameters['value']",
    "controller.request.request_parameters['value']", "controller.request.path_parameters['value']",
    "controller.request.env['HTTP_X_VALUE']", "controller.cookies[:value]", "rack_request.params['value']",
  ] },
];

test("20000 distinct definitions, full metadata and unchanged historical 5000 snapshot", () => {
  const rules = getStaticRules();
  assert.equal(ruleCount, 150036);
  assert.equal(createFrameworkRules().length, 15000);
  assert.equal(new Set(rules.map(r => r.id)).size, ruleCount);
  assert.equal(new Set(rules.map(r => `${r.languages}:${r.pattern}`)).size, ruleCount);
  const sql = readFileSync(new URL('../drizzle/0007_http_rule_catalog_5000.sql', import.meta.url), 'utf8');
  const historical = JSON.parse(sql.split("FROM jsonb_array_elements('")[1].split("'::jsonb)")[0].replaceAll("''", "'"));
  assert.deepEqual(createRuleSnapshot(rules.slice(0, 5000)).entries, historical);
  for (const rule of createFrameworkRules()) {
    const api = getFrameworkRuleApi(rule.id);
    assert.ok(api && rule.title.startsWith(api), rule.id);
    assert.ok(rule.languages.length && rule.recommendation.length > 30 && rule.references.length);
    assert.equal(rule.confidence, 'medium');
    assert.ok(!rule.pattern.global && !rule.pattern.sticky);
  }
});

for (const { family, file, other, expressions } of fixtures) {
  test(`FW${family}: all API/access pairs, sanitizer wrappers and language boundaries`, () => {
    const prefix = `FW${family}`;
    const rules = createFrameworkRules().filter(r => r.id.startsWith(prefix));
    assert.equal(expressions.length, family === 'JS' || family === 'PY' ? 40 : 30);
    const apiCount = family === 'JS' || family === 'PY' ? 150 : 50;
    assert.equal(rules.length, apiCount * expressions.length);
    for (let apiIndex = 0; apiIndex < apiCount; apiIndex++) {
      const api = getFrameworkRuleApi(rules[apiIndex * expressions.length].id)!;
      const unsafe = expressions.map(expression => `${api}(${expression})`).join('\n');
      const matches = scanCode(unsafe, file).findings.filter(f => f.ruleId.startsWith(prefix));
      assert.equal(matches.length, expressions.length, `${api}: missing/overlapping channels`);
      for (const [sourceIndex, match] of matches.sort((a, b) => a.line - b.line).entries()) {
        assert.equal(match.ruleId, `${prefix}${String(apiIndex * expressions.length + sourceIndex + 1).padStart(5, '0')}`);
        assert.equal(match.line, sourceIndex + 1);
      }
      const safe = expressions.flatMap(expression => [
        `${api}(validate(${expression}))`, `${api}('fixed', ${expression})`, `${api}(trusted_value)`,
        `unrelated${api}(${expression})`,
      ]).join('\n');
      assert.ok(!scanCode(safe, file).findings.some(f => f.ruleId.startsWith(prefix)), api);
      assert.ok(!scanCode(unsafe, other).findings.some(f => f.ruleId.startsWith(prefix)), `${api}: wrong language`);
    }
  });
}

test("framework boundaries, repeated CRLF findings and archive self-exclusion", () => {
  const code = "// header\r\n  axios.get(await request.text());\r\n  axios.get(await request.text());";
  const findings = scanFiles([{ name: 'a.ts', code }, { name: 'b.ts', code }]).findings.filter(f => f.ruleId === 'FWJS01150');
  assert.equal(findings.length, 4);
  assert.deepEqual(findings.slice(0, 2).map(f => [f.line, f.column]), [[2, 3], [3, 3]]);
  assert.equal(new Set(findings.map(f => f.id)).size, 4);
  for (const expression of ['req.payloadExtra.value', 'request.textExtra()', 'obj.request.text()']) {
    assert.ok(!scanCode(`axios.get(${expression})`, 'a.ts').findings.some(f => f.ruleId.startsWith('FW')));
  }
  const archive = extractZip(zipSync({
    'src/a.ts': strToU8(code), 'app/lib/sast-rules-framework.ts': strToU8(code),
  }));
  assert.equal(archive.files.length, 1);
  assert.equal(archive.skippedFiles, 1);
  assert.ok(scanFiles(archive.files).findings.some(f => f.ruleId === 'FWJS01150'));
});

test("20000-rule safe corpus and long near-matches stay within 10 seconds", () => {
  const started = performance.now();
  for (const file of ['a.ts', 'a.py', 'a.php', 'a.rb']) {
    const code = 'ordinary text\n'.repeat(5000) + 'axios.get(' + ' '.repeat(50000) + 'request.textExtra())';
    assert.ok(!scanCode(code, file).findings.some(f => f.ruleId.startsWith('FW')));
  }
  assert.ok(performance.now() - started < 10000);
});
