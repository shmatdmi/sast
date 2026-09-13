import assert from "node:assert/strict";
import test from "node:test";
import { strToU8, zipSync } from "fflate";
import {
  MAX_ARCHIVE_BYTES,
  MAX_SOURCE_FILE_BYTES,
  extractZip,
  isSupportedSourceFile,
} from "../app/lib/archive.ts";
import {
  detectLanguage,
  scanCode,
  scanFiles,
} from "../app/lib/sast-engine.ts";

function ruleIds(code: string, filename: string) {
  return scanCode(code, filename).findings.map((finding) => finding.ruleId);
}

test("recognizes supported source files case-insensitively", () => {
  for (const name of [
    "index.js", "view.TSX", "service.py", "Main.java", "main.go",
    "Program.cs", "lib.rb", "App.kt", "main.rs", "run.sh",
    "compose.yml", ".env", "Dockerfile",
  ]) {
    assert.equal(isSupportedSourceFile(name), true, name);
  }
  assert.equal(isSupportedSourceFile("archive.zip"), false);
  assert.equal(isSupportedSourceFile("image.png"), false);
});

test("detects every advertised language by extension", () => {
  const cases = {
    "app.js": "javascript",
    "app.ts": "typescript",
    "app.py": "python",
    "App.java": "java",
    "index.php": "php",
    "main.go": "go",
    "Program.cs": "csharp",
    "app.rb": "ruby",
    "App.kt": "kotlin",
    "main.rs": "rust",
    "App.swift": "swift",
    "Main.scala": "scala",
    "deploy.sh": "shell",
    "compose.yaml": "config",
  };
  for (const [filename, language] of Object.entries(cases)) {
    assert.equal(detectLanguage(filename, ""), language, filename);
  }
  assert.equal(detectLanguage("unknown.file", "plain text"), "unknown");
});

test("representative rules work across language families", () => {
  const cases = [
    ["eval(input);", "app.js", "JS001"],
    ["pickle.load(payload)", "app.py", "PY005"],
    ["new ObjectInputStream(stream);", "App.java", "JAVA002"],
    ["<?php unserialize($data);", "index.php", "PHP002"],
    ["tls.Config{InsecureSkipVerify: true}", "main.go", "GO002"],
    ["var formatter = new BinaryFormatter();", "Program.cs", "CS001"],
    ["Marshal.load(data)", "app.rb", "RB001"],
    ["ObjectInputStream(stream)", "App.kt", "JAVA002"],
    ["chmod 777 app", "deploy.sh", "CFG003"],
    ["privileged: true", "compose.yaml", "CFG001"],
  ];
  for (const [code, filename, ruleId] of cases) {
    assert.ok(ruleIds(code, filename).includes(ruleId), filename + " -> " + ruleId);
  }
});

test("detects expanded Java, Go and Python security rules", () => {
  const cases = [
    ["tempfile.mktemp()", "app.py", "PY011"],
    ["tarfile.open(name).extractall(target)", "app.py", "PY012"],
    ["mark_safe(user_html)", "app.py", "PY013"],
    ["jwt.decode(token, options={\"verify_signature\": False})", "app.py", "PY014"],
    ["hashlib.md5(payload).hexdigest()", "app.py", "PY015"],
    ["logger.info(\"token=%s\", token)", "app.py", "PY016"],
    ["engine.eval(userCode);", "App.java", "JAVA005"],
    ["new Random();", "App.java", "JAVA006"],
    ["void checkServerTrusted(X509Certificate[] chain, String authType) {}", "App.java", "JAVA007"],
    ["statement.executeQuery(\"SELECT * FROM users WHERE id=\" + id);", "App.java", "JAVA008"],
    ["new File(base, request.getParameter(\"name\"));", "App.java", "JAVA009"],
    ["MessageDigest.getInstance(\"SHA-1\");", "App.java", "JAVA010"],
    ["md5.Sum(payload)", "main.go", "GO004"],
    ["http.ListenAndServe(\":8080\", handler)", "main.go", "GO005"],
    ["os.WriteFile(name, data, 0777)", "main.go", "GO006"],
    ["parser.ParseUnverified(token, claims)", "main.go", "GO007"],
    ["filepath.Join(base, r.URL.Query().Get(\"file\"))", "main.go", "GO008"],
    ["db.Query(fmt.Sprintf(\"SELECT * FROM users WHERE id=%s\", id))", "main.go", "GO009"],
  ];
  for (const [code, filename, ruleId] of cases) {
    assert.ok(ruleIds(code, filename).includes(ruleId), filename + " -> " + ruleId);
  }
});

test("expanded language rules preserve common safe alternatives", () => {
  const safeCases = [
    ["tempfile.NamedTemporaryFile()", "safe.py", "PY011"],
    ["hashlib.sha256(payload).hexdigest()", "safe.py", "PY015"],
    ["new SecureRandom();", "Safe.java", "JAVA006"],
    ["MessageDigest.getInstance(\"SHA-256\");", "Safe.java", "JAVA010"],
    ["sha256.Sum256(payload)", "safe.go", "GO004"],
    ["http.ListenAndServeTLS(\":443\", \"cert.pem\", \"key.pem\", handler)", "safe.go", "GO005"],
  ];
  for (const [code, filename, ruleId] of safeCases) {
    assert.ok(!ruleIds(code, filename).includes(ruleId), filename + " unexpectedly matched " + ruleId);
  }
});

test("normalizes line endings and returns a stable finding contract", () => {
  const result = scanCode("const safe = true;\r\neval(value);", "app.js");
  const finding = result.findings.find((item) => item.ruleId === "JS001");
  assert.ok(finding);
  assert.equal(finding.line, 2);
  assert.equal(finding.column, 1);
  assert.equal(finding.snippet, "eval(value);");
  assert.equal(finding.cwe, "CWE-95");
  assert.match(finding.references[0], /^https:\/\/cwe\.mitre\.org\//);
  assert.equal(result.scannedLines, 2);
  assert.equal(result.summary.score, 72);
});

test("honors a manually selected language and exclusions", () => {
  const forced = scanCode("eval(value)", "snippet.txt", "python");
  assert.equal(forced.language, "python");
  assert.ok(forced.findings.some((finding) => finding.ruleId === "PY001"));
  assert.ok(!forced.findings.some((finding) => finding.ruleId === "JS001"));

  const excluded = scanCode(
    "password = 'example-secret'\nyaml.load(data, Loader=yaml.SafeLoader)",
    "safe.py",
  );
  assert.ok(!excluded.findings.some((finding) => finding.ruleId === "SEC001"));
  assert.ok(!excluded.findings.some((finding) => finding.ruleId === "PY002"));
});

test("detects direct secret comparison without flagging constant-time comparison", () => {
  // Assemble the fixture at runtime so a scan of this repository does not
  // mistake the intentionally vulnerable example for application code.
  const unsafeSnippet = ["if (token ", "=== suppliedToken) allow();"].join("");
  const unsafe = ruleIds(unsafeSnippet, "auth.ts");
  assert.ok(unsafe.includes("AUTH001"));

  const safe = ruleIds("timingSafeEqual(token, suppliedToken);", "auth.ts");
  assert.ok(!safe.includes("AUTH001"));
});

test("does not confuse PostgreSQL driver setup with a request-controlled path", () => {
  const findings = ruleIds('db, err := sql.Open("postgres", databaseURL)', "main.go");
  assert.ok(!findings.includes("PATH001"));
});

test("tracks user input into sensitive operations and aggregates files", () => {
  const sql = scanCode(
    "const value = req.query.value;\naudit.log('request');\ndb.query(value);",
    "api.ts",
  );
  assert.ok(sql.findings.some((finding) => finding.ruleId === "FLOW-SQL"));

  const safe = scanCode(
    "const value = req.query.value;\nvalidateInput(value);\ndb.query(value);",
    "api.ts",
  );
  assert.ok(!safe.findings.some((finding) => finding.ruleId === "FLOW-SQL"));

  const combined = scanFiles([
    { name: "api.ts", code: "eval(value);" },
    { name: "worker.py", code: "pickle.load(value)" },
  ]);
  assert.equal(combined.language, "multiple");
  assert.equal(combined.filesScanned, 2);
  assert.ok(combined.findings.every((finding) => Boolean(finding.filename)));
});

test("rejects oversized, corrupt and source-less ZIP input", () => {
  assert.throws(() => extractZip(new Uint8Array(MAX_ARCHIVE_BYTES + 1)));
  assert.throws(() => extractZip(strToU8("not a zip")));
  assert.throws(() => extractZip(zipSync({ "README.md": strToU8("docs") })));

  const archive = zipSync({
    "large.js": strToU8("a".repeat(MAX_SOURCE_FILE_BYTES + 1)),
    "src/ok.ts": strToU8("const ok = true;"),
  });
  const extracted = extractZip(archive);
  assert.deepEqual(extracted.files.map((file) => file.name), ["src/ok.ts"]);
  assert.equal(extracted.skippedFiles, 1);
});
