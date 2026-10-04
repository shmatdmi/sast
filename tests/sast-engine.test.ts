import assert from "node:assert/strict";
import test from "node:test";
import { countSourceLines, detectLanguage, ruleCount, scanCode, scanFiles } from "../app/lib/sast-engine.ts";

test("counts physical source lines consistently across line endings and EOF", () => {
  for (const [source, expected] of [["", 0], ["x", 1], ["x\n", 1], ["\n", 1], ["x\n\n", 2], ["// comment\n\nx", 3], ["x\r\ny\r\n", 2], ["x\ry\r", 2]] as const) {
    assert.equal(countSourceLines(source), expected);
    assert.equal(scanCode(source).scannedLines, expected);
  }
  const result = scanFiles([{ name: "a.js", code: "x\n" }, { name: "b.py", code: "# comment\r\n\r\ny" }, { name: "empty.ts", code: "" }]);
  assert.equal(result.scannedLines, 4);
  assert.equal(result.filesScanned, 3);
  assert.equal(scanFiles([]).scannedLines, 0);
});

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

const securityConfigurationCases = [
  { id: "JS021", file: "process.ts", cwe: "CWE-78", category: "injection", unsafe: [
    'spawn(command, args, { shell: true });',
    'execFileSync(command, args, {\n  shell: true\n});',
  ], safe: ['spawn(command, args, { shell: false });', 'spawn(command, args);', 'spawn(command, args);\nconst options = { shell: true };'] },
  { id: "PY021", file: "client.py", cwe: "CWE-295", category: "transport", unsafe: [
    'context = ssl._create_unverified_context()', 'context.verify_mode =\n  ssl.CERT_NONE',
  ], safe: ['context = ssl.create_default_context()', 'context.verify_mode = ssl.CERT_REQUIRED'] },
  { id: "PY022", file: "views.py", cwe: "CWE-79", category: "xss", unsafe: [
    'env = jinja2.Environment(autoescape=False)', 'env = Environment(\n  loader=loader,\n  autoescape=False\n)',
    'env = Environment(loader=FileSystemLoader("templates"), autoescape=False)',
  ], safe: ['env = Environment(autoescape=True)', 'env = Environment(autoescape=select_autoescape(["html"]))', 'env = Environment(autoescape=True)\nautoescape=False'] },
  { id: "JAVA021", file: "Decoder.java", cwe: "CWE-502", category: "deserialization", unsafe: [
    'new XMLDecoder(stream);', 'new java.beans.XMLDecoder(stream);',
  ], safe: ['new XMLEncoder(stream);', 'new XMLDecoderFactory();'] },
  { id: "CS004", file: "Json.cs", cwe: "CWE-502", category: "deserialization", unsafe: [
    'TypeNameHandling = TypeNameHandling.All', 'TypeNameHandling =\n  Newtonsoft.Json.TypeNameHandling.Auto',
    'TypeNameHandling = TypeNameHandling.Objects', 'TypeNameHandling = TypeNameHandling.Arrays',
  ], safe: ['TypeNameHandling = TypeNameHandling.None'] },
  { id: "CS005", file: "Xml.cs", cwe: "CWE-611", category: "xxe", unsafe: [
    'DtdProcessing = DtdProcessing.Parse', 'DtdProcessing =\n  System.Xml.DtdProcessing.Parse',
  ], safe: ['DtdProcessing = DtdProcessing.Prohibit', 'DtdProcessing = DtdProcessing.Ignore'] },
  { id: "PHP008", file: "client.php", cwe: "CWE-295", category: "transport", unsafe: [
    'curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);', 'CURLOPT_SSL_VERIFYHOST => 0',
    'curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,\n false);',
  ], safe: ['curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);', 'CURLOPT_SSL_VERIFYHOST => 2', 'CURLOPT_SSL_VERIFYHOST => 0x02'] },
  { id: "CFG009", file: "compose.yaml", cwe: "CWE-250", category: "configuration", unsafe: [
    'volumes:\n  - /var/run/docker.sock:/var/run/docker.sock:ro',
    'volumes:\n  - type: bind\n    source: /run/docker.sock\n    target: /run/docker.sock',
    'volumes:\n  - "/var/run/docker.sock:/var/run/docker.sock"',
    'hostPath:\n  path: /var/run/docker.sock',
  ], safe: ['volumes:\n  - /srv/data:/data', '# - /var/run/docker.sock:/var/run/docker.sock', 'source: /var/run/docker.sock.backup'] },
  { id: "CFG010", file: "pod.yaml", cwe: "CWE-250", category: "configuration", unsafe: [
    'cap_add: [SYS_ADMIN]', 'capabilities:\n  add:\n    - NET_BIND_SERVICE\n    - SYS_ADMIN', 'cap_add:\n  - "ALL"',
  ], safe: ['cap_add: [NET_BIND_SERVICE]', 'capabilities:\n  drop: [ALL]', 'cap_add: [SYS_ADMINISTRATOR]', 'cap_add:\n  - NET_BIND_SERVICE\nother:\n  - SYS_ADMIN'] },
  { id: "CFG011", file: "pod.yaml", cwe: "CWE-693", category: "configuration", unsafe: [
    'security_opt:\n  - seccomp=unconfined', 'seccompProfile:\n  type: Unconfined', 'seccompProfile: { type: "Unconfined" }',
  ], safe: ['seccompProfile:\n  type: RuntimeDefault', 'seccompProfile:\n  type: Localhost', 'other:\n  type: Unconfined'] },
];

test("detects dangerous runtime settings with useful finding metadata", () => {
  for (const rule of securityConfigurationCases) {
    for (const code of rule.unsafe) {
      const result = scanCode(code, rule.file);
      const finding = result.findings.find((item) => item.ruleId === rule.id);
      assert.ok(finding, `${rule.id}: ${code}`);
      assert.equal(finding.cwe, rule.cwe);
      assert.equal(finding.category, rule.category);
      assert.ok(finding.recommendation.length > 20);
      assert.equal(finding.references[0], `https://cwe.mitre.org/data/definitions/${rule.cwe.slice(4)}.html`);
      assert.ok(finding.line >= 1 && finding.line <= result.scannedLines);
    }
  }
});

test("runtime rules preserve safe alternatives and respect language boundaries", () => {
  for (const rule of securityConfigurationCases) {
    for (const code of rule.safe) {
      assert.ok(!scanCode(code, rule.file).findings.some((item) => item.ruleId === rule.id), `${rule.id}: ${code}`);
    }
    assert.ok(!scanCode(rule.unsafe[0], "other.rb").findings.some((item) => item.ruleId === rule.id), rule.id);
  }
});

test("new multiline rules retain positions across CRLF and work in Kotlin", () => {
  const finding = scanCode('const ok = true;\r\n  spawn(cmd, args, {\r\n    shell: true\r\n  });', "process.ts").findings.find((item) => item.ruleId === "JS021");
  assert.ok(finding);
  assert.equal(finding.line, 2);
  assert.equal(finding.column, 3);
  assert.equal(finding.owasp, "A03:2021");
  assert.ok(scanCode('val decoder = XMLDecoder(stream)', "Decoder.kt").findings.some((item) => item.ruleId === "JAVA021"));
  assert.equal(scanCode('seccompProfile:\n  type: Unconfined', "pod.yaml").findings.find((item) => item.ruleId === "CFG011")?.owasp, "A05:2021");
});
