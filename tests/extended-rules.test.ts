import assert from "node:assert/strict";
import test from "node:test";
import { performance } from "node:perf_hooks";
import { createExtendedRules } from "../app/lib/sast-rules.ts";
import { ruleCount, scanCode, scanFiles, staticRuleIds } from "../app/lib/sast-engine.ts";

// Independent fixtures cover each advertised rule, rather than deriving inputs
// from regexes. Provider credentials are synthetic and constructed at runtime.
const cases: Array<[string, string, string, string]> = [
  ["SEC010", "keys.env", "sk_live_" + "a".repeat(32), "pk_live_" + "a".repeat(32)],
  ["SEC011", "keys.env", "AIza" + "A".repeat(35), "AIza" + "A".repeat(34)],
  ["SEC012", "keys.env", "glpat-" + "A".repeat(20), "glpat-${GITLAB_TOKEN}"],
  ["SEC013", "keys.env", "npm_" + "A".repeat(36), "npm_${NPM_TOKEN}"],
  ["SEC014", "keys.env", "SG." + "A".repeat(22) + "." + "B".repeat(43), "SG.public.identifier"],
  ["SEC015", "keys.env", "AccountKey=" + "A".repeat(86) + "==", "AccountKey=${AZURE_KEY}"],

  ["JS030", "page.js", "document.write(userHtml);", 'document.write("hello");'],
  ["JS031", "timer.ts", 'setTimeout("run(userInput)", 10);', "setTimeout(() => run(userInput), 10);"],
  ["JS032", "bridge.js", 'window.postMessage(payload, "*");', 'window.postMessage(payload, "https://trusted.example");'],
  ["JS033", "electron.ts", "webPreferences: { nodeIntegration: true }", "webPreferences: { nodeIntegration: false }"],
  ["JS034", "electron.js", "webPreferences: { contextIsolation: false }", "webPreferences: { contextIsolation: true }"],
  ["JS035", "electron.ts", "webPreferences: { webSecurity: false }", "webPreferences: { webSecurity: true }"],
  ["JS036", "search.ts", "new RegExp(req.query.pattern);", 'new RegExp("^[a-z]+$");'],
  ["JS037", "api.js", "res.send(req.query.html);", "res.json({ text: req.query.html });"],
  ["JS038", "electron.ts", "webPreferences: { sandbox: false }", "webPreferences: { sandbox: true }"],
  ["JS039", "auth.ts", 'localStorage.setItem("access_token", token);', 'localStorage.setItem("theme", theme);'],

  ["PY030", "ssh.py", "client.set_missing_host_key_policy(paramiko.AutoAddPolicy())", "client.set_missing_host_key_policy(paramiko.RejectPolicy())"],
  ["PY031", "views.py", "@csrf_exempt\ndef update(request): pass", "@csrf_protect\ndef update(request): pass"],
  ["PY032", "xml.py", "etree.XMLParser(resolve_entities=True)", "etree.XMLParser(resolve_entities=False, no_network=True)"],
  ["PY033", "db.py", 'User.objects.raw(f"SELECT * FROM users WHERE id={user_id}")', 'User.objects.raw("SELECT * FROM users WHERE id=%s", [user_id])'],
  ["PY034", "files.py", 'send_file(request.args["file"])', 'send_from_directory("public", "readme.txt")'],
  ["PY035", "settings.py", "SESSION_COOKIE_HTTPONLY = False", "SESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True"],
  ["PY036", "model.py", "torch.load(path, weights_only=False)", "torch.load(path, weights_only=True)"],
  ["PY037", "data.py", "pd.read_pickle(path)", "pd.read_csv(path)"],
  ["PY038", "settings.py", 'ALLOWED_HOSTS = ["*"]', 'ALLOWED_HOSTS = ["app.example"]'],
  ["PY039", "settings.py", 'PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]', 'PASSWORD_HASHERS = ["django.contrib.auth.hashers.Argon2PasswordHasher"]'],

  ["JAVA030", "Crypto.java", 'Cipher.getInstance("DES/CBC/PKCS5Padding");', 'Cipher.getInstance("AES/GCM/NoPadding");'],
  ["JAVA031", "Security.kt", "http.csrf().disable();", "http.csrf();"],
  ["JAVA032", "Security.java", "rules.anyRequest().permitAll();", "rules.anyRequest().authenticated();"],
  ["JAVA033", "Directory.java", 'ctx.search(base, "(uid=" + name + ")", controls);', 'ctx.search(base, "(uid={0})", new Object[]{name}, controls);'],
  ["JAVA034", "View.kt", "settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW)", "settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW)"],
  ["JAVA035", "View.java", 'webView.addJavascriptInterface(bridge, "api");', 'webView.removeJavascriptInterface("api");'],
  ["JAVA036", "View.kt", "settings.setAllowUniversalAccessFromFileURLs(true)", "settings.setAllowUniversalAccessFromFileURLs(false)"],
  ["JAVA037", "Key.java", "new RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4);", "new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4);"],

  ["PHP030", "xml.php", "simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);", "simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET);"],
  ["PHP031", "legacy.php", 'preg_replace("/pattern/e", $replacement, $input);', 'preg_replace_callback("/pattern/", $callback, $input);'],
  ["PHP032", "token.php", "$token = mt_rand();", "$token = bin2hex(random_bytes(32));"],
  ["PHP033", "redirect.php", "header('Location: ' . $_GET['url']);", "header('Location: /home');"],
  ["PHP034", "session.php", "ini_set('session.cookie_secure', '0');", "ini_set('session.cookie_secure', '1');"],
  ["PHP035", "ldap.php", "ldap_search($conn, $base, '(uid=' . $_GET['name'] . ')');", "ldap_search($conn, $base, '(uid=' . ldap_escape($name, '', LDAP_ESCAPE_FILTER) . ')');"],

  ["GO030", "tls.go", "tls.Config{MinVersion: tls.VersionTLS10}", "tls.Config{MinVersion: tls.VersionTLS13}"],
  ["GO031", "cipher.go", "rc4.NewCipher(key)", "aes.NewCipher(key)"],
  ["GO032", "key.go", "rsa.GenerateKey(rand.Reader, 1024)", "rsa.GenerateKey(rand.Reader, 3072)"],
  ["GO033", "ssh.go", "HostKeyCallback: ssh.InsecureIgnoreHostKey()", "HostKeyCallback: knownhosts.New(path)"],
  ["GO034", "files.go", 'http.FileServer(http.Dir("/"))', 'http.FileServer(http.Dir("public"))'],
  ["GO035", "page.go", 'import "text/template"\nfunc page(w http.ResponseWriter) {}', 'import "html/template"\nfunc page(w http.ResponseWriter) {}'],

  ["CS030", "Client.cs", "handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;", "var handler = new HttpClientHandler();"],
  ["CS031", "Repo.cs", 'db.Users.FromSqlRaw($"SELECT * FROM users WHERE id={id}");', 'db.Users.FromSqlInterpolated($"SELECT * FROM users WHERE id={id}");'],
  ["CS032", "Directory.cs", 'searcher.Filter = "(uid=" + name + ")";', 'searcher.Filter = "(uid=service-account)";'],
  ["CS033", "Cipher.cs", "TripleDES.Create();", "new AesGcm(key, 16);"],
  ["CS034", "View.cs", "Html.Raw(userHtml)", "Html.Encode(userHtml)"],
  ["CS035", "Controller.cs", "[IgnoreAntiforgeryToken]\npublic void Update() {}", "[ValidateAntiForgeryToken]\npublic void Update() {}"],

  ["RB030", "view.rb", "params[:html].html_safe", "sanitize(params[:html])"],
  ["RB031", "user.rb", "params.require(:user).permit!", "params.require(:user).permit(:name)"],
  ["RB032", "controller.rb", "skip_before_action :verify_authenticity_token", "skip_before_action :load_metrics"],
  ["RB033", "client.rb", "client.verify_mode = OpenSSL::SSL::VERIFY_NONE", "client.verify_mode = OpenSSL::SSL::VERIFY_PEER"],

  ["RS030", "client.rs", "builder.set_verify(SslVerifyMode::NONE);", "builder.set_verify(SslVerifyMode::PEER);"],
  ["RS031", "hash.rs", "let digest = sha1::Sha1::digest(bytes);", "let digest = sha2::Sha256::digest(bytes);"],
  ["RS032", "db.rs", 'conn.prepare(&format!("SELECT * FROM users WHERE id={}", id));', 'conn.prepare("SELECT * FROM users WHERE id=?1");'],
  ["RS033", "file.rs", "options.mode(0o777);", "options.mode(0o600);"],

  ["SWIFT030", "Keychain.swift", "attrs[kSecAttrAccessible] = kSecAttrAccessibleAlways", "attrs[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlocked"],
  ["SWIFT031", "Cipher.swift", "let options = CCOptions(kCCOptionECBMode)", "let options = CCOptions(kCCOptionPKCS7Padding)"],
  ["SWIFT032", "DB.swift", 'sqlite3_exec(db, "SELECT * FROM users WHERE id=\\(id)", nil, nil, nil)', 'sqlite3_prepare_v2(db, "SELECT * FROM users WHERE id=?", -1, &stmt, nil)'],
  ["SWIFT033", "Archive.swift", "NSKeyedUnarchiver.unarchiveObject(with: data)", "NSKeyedUnarchiver.unarchivedObject(ofClass: Profile.self, from: data)"],

  ["SCALA030", "Token.scala", "val token = scala.util.Random.alphanumeric.take(32)", "val token = new java.security.SecureRandom().nextLong()"],
  ["SCALA031", "Client.scala", "SSLLooseConfig(disableHostnameVerification = true)", "SSLLooseConfig(disableHostnameVerification = false)"],
  ["SCALA032", "View.scala", "Html(userContent)", "HtmlFormat.escape(userContent)"],
  ["SCALA033", "Client.scala", "acceptAnyCertificate = true", "acceptAnyCertificate = false"],

  ["SH030", "deploy.sh", "ssh -o StrictHostKeyChecking=no server", "ssh -o StrictHostKeyChecking=yes server"],
  ["SH031", "deploy.sh", "scp -o UserKnownHostsFile=/dev/null file server:", "scp -o UserKnownHostsFile=known_hosts file server:"],
  ["SH032", "setup.sh", "umask 000", "umask 077"],
  ["SH033", "login.sh", "sshpass -p 'synthetic-pass' ssh server", "sshpass -f /run/secrets/password ssh server"],

  ["CFG030", "pod.yaml", "runAsNonRoot: false", "runAsNonRoot: true"],
  ["CFG031", "pod.yaml", "volumes:\n  - name: host\n    hostPath:\n      path: /etc", "volumes:\n  - name: scratch\n    emptyDir: {}"],
  ["CFG032", "pod.yaml", "capabilities:\n  add: [SYS_PTRACE]", "capabilities:\n  drop:\n    - SYS_PTRACE"],
  ["CFG033", "compose.yaml", "security_opt:\n  - apparmor=unconfined", "security_opt:\n  - apparmor=restricted"],
  ["CFG034", "compose.yaml", "pid: host", "pid: private"],
  ["CFG035", "workflow.yaml", "permissions: write-all", "permissions:\n  contents: read"],
  ["CFG036", "workflow.yaml", 'run: echo "${{ github.event.issue.title }}"', 'env:\n  TITLE: ${{ github.event.issue.title }}\nrun: echo "$TITLE"'],
  ["CFG037", "db.env", "PG_OPTIONS=sslmode=disable", "PG_OPTIONS=sslmode=verify-full"],
  ["CFG038", "AndroidManifest.xml", '<application android:usesCleartextTraffic="true"/>', '<application android:usesCleartextTraffic="false"/>'],
  ["CFG039", "headers.json", '"CSP": "script-src \'self\' \'unsafe-eval\'"', '"CSP": "script-src \'self\'"'],
  ["CFG040", "AndroidManifest.xml", '<application android:debuggable="true"/>', '<application android:debuggable="false"/>'],
  ["CFG041", "policy.json", '{"Effect": "Allow", "Action": "*", "Resource": "*"}', '{"Effect": "Deny", "Action": "*", "Resource": "*"}'],
  ["CFG042", "storage.yaml", "acl: public-read", "acl: private"],
  ["CFG043", "Dockerfile", "ADD https://example.test/app.tar.gz /app/", "ADD --checksum=sha256:abc123 https://example.test/app.tar.gz /app/"],
];

test("extended catalog contains 86 distinct, documented rules and 400 total IDs", () => {
  const pack = createExtendedRules(["unknown"]);
  assert.equal(ruleCount, 400);
  assert.equal(new Set(staticRuleIds).size, ruleCount);
  assert.equal(pack.length, 86);
  assert.deepEqual(cases.map(([id]) => id).sort(), pack.map((rule) => rule.id).sort());
  for (const rule of pack) {
    assert.ok(staticRuleIds.includes(rule.id));
    assert.match(rule.cwe, /^CWE-\d+$/);
    assert.match(rule.owasp, /^A\d{2}:2021$/);
    assert.ok(rule.description.length > 25 && rule.recommendation.length > 25, rule.id);
    assert.ok(rule.references.length && rule.category && rule.confidence, rule.id);
  }
});

for (const [id, filename, unsafe, safe] of cases) {
  test(`${id}: detects risky input and preserves the safe alternative`, () => {
    const findings = scanCode(unsafe, filename).findings;
    const finding = findings.find((item) => item.ruleId === id);
    assert.ok(finding, `${id} missing for ${unsafe}`);
    assert.equal(findings.filter((item) => item.ruleId === id).length, 1);
    assert.ok(!scanCode(safe, filename).findings.some((item) => item.ruleId === id), `false positive: ${safe}`);
    assert.equal(finding.snippet, unsafe.split("\n")[finding.line - 1].trim().slice(0, 220));
    if (!id.startsWith("SEC")) {
      assert.ok(!scanCode(unsafe, "irrelevant.txt", "unknown").findings.some((item) => item.ruleId === id));
    }
  });
}

test("expanded pack handles CRLF, repeated occurrences and multi-file aggregation", () => {
  const result = scanFiles([
    { name: "settings.py", code: "# settings\r\nSESSION_COOKIE_SECURE = False\r\nSESSION_COOKIE_HTTPONLY = False" },
    { name: "Security.kt", code: "http.anyRequest().permitAll()" },
  ]);
  const cookies = result.findings.filter((item) => item.ruleId === "PY035");
  assert.deepEqual(cookies.map((item) => [item.filename, item.line, item.column]), [["settings.py", 2, 1], ["settings.py", 3, 1]]);
  assert.ok(result.findings.some((item) => item.ruleId === "JAVA032" && item.filename === "Security.kt"));
  assert.equal(new Set(result.findings.map((item) => item.id)).size, result.findings.length);
});

test("expanded pack scans a large safe source within a practical time bound", () => {
  const code = "const greeting = 'hello';\n".repeat(12_000);
  const started = performance.now();
  const result = scanCode(code, "large.ts");
  assert.equal(result.summary.total, 0);
  assert.equal(result.scannedLines, 12_000);
  assert.ok(performance.now() - started < 10_000, "large scan exceeded 10 seconds");
});
