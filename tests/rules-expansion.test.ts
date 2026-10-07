import assert from "node:assert/strict";
import test from "node:test";
import { performance } from "node:perf_hooks";
import { createExpansionRules } from "../app/lib/sast-rules-expansion.ts";
import { ruleCount, scanCode, scanFiles, staticRuleIds, detectLanguage } from "../app/lib/sast-engine.ts";
import { extractZip, isSupportedSourceFile } from "../app/lib/archive.ts";
import { strToU8, zipSync } from "fflate";

const filenames: Record<string, string> = { SEC: "keys.env", JS: "code.ts", PY: "code.py", JAVA: "Code.java", PHP: "code.php", GO: "code.go", CS: "Code.cs", RB: "code.rb", RS: "code.rs", SWIFT: "Code.swift", SCALA: "Code.scala", SH: "deploy.sh", CFG: "settings.conf" };
// Independent inputs, in ID order 100..N within each family. Never generate a
// vulnerable example from the implementation regex. Credentials are synthetic.
const examples: Record<string, Array<[string, string]>> = {
  SEC: [
    ["pypi-AgEIcHlwaS5vcmc" + "A".repeat(60), "pypi-${PYPI_TOKEN}"],
    ["dapi" + "a1".repeat(16), "dapi${DATABRICKS_TOKEN}"],
    ["dop_v1_" + "a1".repeat(32), "dop_v1_${DO_TOKEN}"],
    ["shpat_" + "a1".repeat(16), "shopify-token-from-env"],
    ["dp.pt." + "a1".repeat(21) + "a", "dp.pt.${DOPPLER_TOKEN}"],
    ["PMAK-" + "a1".repeat(12) + "-" + "b2".repeat(17), "PMAK-${POSTMAN_TOKEN}"],
    ["pul-" + "a1".repeat(20), "pul-${PULUMI_TOKEN}"],
    ["glsa_" + "Ab12".repeat(8) + "_" + "ab12".repeat(2), "glsa_${GRAFANA_TOKEN}"],
    ["sntryu_" + "a1".repeat(32), "sntryu_${SENTRY_TOKEN}"],
    ["https://hooks.slack.com/services/T" + "A".repeat(8) + "/B" + "B".repeat(8) + "/" + "Ab12".repeat(6), "https://hooks.slack.com/services/${SLACK_WEBHOOK}"],
    ["123456789:A" + "Ab12_-".repeat(5) + "Ab12", "123456789:${BOT_TOKEN}"],
    ["AGE-SECRET-KEY-1" + "QP".repeat(29), "age1" + "QP".repeat(29)],
    ["A3-ABC123-ABC123-ABCDE-ABCDE-ABCDE-ABCDE", "A3-${ONEPASSWORD_SECRET}"],
    ["ops_eyJ" + "Ab12".repeat(70), "ops_${ONEPASSWORD_TOKEN}"],
    ["AKCp" + "Ab12".repeat(17) + "A", "AKCp${ARTIFACTORY_TOKEN}"],
    ["p8e-" + "a1".repeat(16), "p8e-${ADOBE_SECRET}"],
  ],
  JS: [
    ["element.html(req.query.html);", "element.text(req.query.html);"],
    ["sanitizer.bypassSecurityTrustHtml(html);", "sanitizer.sanitize(SecurityContext.HTML, html);"],
    ['<div v-html="userHtml"></div>', "<div>{{ userHtml }}</div>"],
    ["{@html userHtml}", "{userHtml}"],
    ["_.template(req.query.template);", "_.template('<p><%- name %></p>');"],
    ["filter = { $where: req.query.filter };", "filter = { userId: validatedId };"],
    ["serialize(data, { unsafe: true });", "serialize(data, { unsafe: false });"],
    ["Handlebars.compile(req.body.template);", "Handlebars.compile('<p>{{name}}</p>');"],
    ["ejs.render(req.query.template, model);", "ejs.render('<p><%= name %></p>', model);"],
    ["crypto.createCipher('aes-256-cbc', key);", "crypto.createCipheriv('aes-256-gcm', key, iv);"],
    ["Buffer.allocUnsafe(1024);", "Buffer.alloc(1024);"],
    ["jwt.sign(payload, 'shortkey');", "jwt.sign(payload, signingKey);"],
    ["bcrypt.hash(password, 4);", "bcrypt.hash(password, 12);"],
    ["crypto.pbkdf2(password, salt, 1000, 32, 'sha256', callback);", "crypto.pbkdf2(password, salt, 600000, 32, 'sha256', callback);"],
    ["{ minVersion: 'TLSv1.1' }", "{ minVersion: 'TLSv1.3' }"],
    ["{ checkServerIdentity: (host, cert) => undefined }", "{ checkServerIdentity: tls.checkServerIdentity }"],
    ["{ enableRemoteModule: true }", "{ enableRemoteModule: false }"],
    ["{ allowRunningInsecureContent: true }", "{ allowRunningInsecureContent: false }"],
    ["$.getScript(req.query.url);", "$.getScript('/static/app.js');"],
    ["$sceProvider.enabled(false);", "$sceProvider.enabled(true);"],
  ],
  PY: [
    ["yaml.unsafe_load(data)", "yaml.safe_load(data)"],
    ["jsonpickle.decode(data)", "json.loads(data)"],
    ["marshal.loads(data)", "json.loads(data)"],
    ["shelve.open(path)", "sqlite3.connect(path)"],
    ["etree.XMLParser(huge_tree=True)", "etree.XMLParser(huge_tree=False)"],
    ["parse(data, forbid_dtd=False)", "parse(data, forbid_dtd=True)"],
    ["context.check_hostname = False", "context.check_hostname = True"],
    ["ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)", "ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)"],
    ["DES.new(key, mode)", "AES.new(key, AES.MODE_GCM)"],
    ["RSA.generate(1024)", "RSA.generate(3072)"],
    ['User.objects.extra(where=[f"id={user_id}"])', 'User.objects.filter(id=user_id)'],
    ['cursor.execute(f"SELECT * FROM users WHERE id={uid}")', 'cursor.execute("SELECT * FROM users WHERE id=%s", [uid])'],
    ["WTF_CSRF_ENABLED = False", "WTF_CSRF_ENABLED = True"],
    ["app.jinja_env.autoescape = False", "app.jinja_env.autoescape = True"],
    ["aiohttp.TCPConnector(ssl=False)", "aiohttp.TCPConnector(ssl=context)"],
    ['client.exec_command(request.args["command"])', 'client.exec_command("uptime")'],
    ["logging.config.listen(9030)", "logging.config.listen(9030, verify=verify_signature)"],
    ['os.execvp(request.args["command"], args)', 'os.execvp("/usr/bin/tool", args)'],
    ['subprocess.run([request.args["command"], argument])', 'subprocess.run(["/usr/bin/tool", argument])'],
    ["SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'", "SESSION_SERIALIZER = 'django.contrib.sessions.serializers.JSONSerializer'"],
  ],
  JAVA: [
    ['stream.allowTypesByWildcard(new String[]{"**"});', 'stream.allowTypes(new Class[]{Profile.class});'],
    ["factory.setExpandEntityReferences(true);", "factory.setExpandEntityReferences(false);"],
    ['factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);', 'factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);'],
    ["factory.setXIncludeAware(true);", "factory.setXIncludeAware(false);"],
    ["factory.setProperty(XMLInputFactory.SUPPORT_DTD, true);", "factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);"],
    ["factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.TRUE);", "factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);"],
    ['factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "all");', 'factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");'],
    ['System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "true");', 'System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "false");'],
    ['ctx.lookup(request.getParameter("name"));', 'ctx.lookup("java:comp/env/jdbc/app");'],
    ['parser.parseExpression(request.getParameter("expression"));', 'parser.parseExpression("name");'],
    ['new Template("dynamic", request.getParameter("template"), config);', 'config.getTemplate("profile.ftl");'],
    ['Velocity.evaluate(context, writer, "http", request.getParameter("template"));', 'Velocity.mergeTemplate("profile.vm", "UTF-8", context, writer);'],
    ['SecretKeyFactory.getInstance("PBEWithMD5AndDES");', 'SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");'],
    ['Signature.getInstance("SHA1withRSA");', 'Signature.getInstance("RSASSA-PSS");'],
    ['Mac.getInstance("HmacMD5");', 'Mac.getInstance("HmacSHA256");'],
    ['SSLContext.getInstance("TLSv1.1");', 'SSLContext.getInstance("TLSv1.3");'],
    ["cookie.setHttpOnly(false);", "cookie.setHttpOnly(true);"],
    ["cookie.setSecure(false);", "cookie.setSecure(true);"],
    ["settings.setAllowFileAccess(true);", "settings.setAllowFileAccess(false);"],
    ["WebView.setWebContentsDebuggingEnabled(true);", "WebView.setWebContentsDebuggingEnabled(false);"],
  ],
  PHP: [
    ["create_function('$x', $code);", "function ($x) { return $x; };"],
    ["eval($code);", "json_decode($data, true);"],
    ["assert($_GET['code']);", "assert(is_string($code));"],
    ["call_user_func($_GET['function'], $arg);", "call_user_func($allowedHandlers[$operation], $arg);"],
    ["preg_replace_callback('/x/', $_POST['handler'], $data);", "preg_replace_callback('/x/', $knownCallback, $data);"],
    ["$phar->getMetadata();", "$phar->getMetadata(['allowed_classes' => false]);"],
    ["extract($_POST);", "$name = $_POST['name'];"],
    ["parse_str($_GET['query']);", "parse_str($query, $output);"],
    ["echo $_GET['html'];", "echo htmlspecialchars($text, ENT_QUOTES, 'UTF-8');"],
    ["file_get_contents($_GET['url']);", "file_get_contents($validatedUrl);"],
    ["curl_setopt($ch, CURLOPT_URL, $_GET['url']);", "curl_setopt($ch, CURLOPT_URL, $allowedUrl);"],
    ["readfile($_GET['path']);", "readfile($allowedPath);"],
    ["move_uploaded_file($temp, $_POST['path']);", "move_uploaded_file($temp, $serverPath);"],
    ["password_hash($password, PASSWORD_BCRYPT, ['cost' => 4]);", "password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);"],
    ["ini_set('session.use_strict_mode', '0');", "ini_set('session.use_strict_mode', '1');"],
    ["ini_set('session.use_trans_sid', '1');", "ini_set('session.use_trans_sid', '0');"],
  ],
  GO: [
    ["token := rand.Intn(10000)", "token := make([]byte, 32); cryptoRand.Read(token)"],
    ["jwt.WithoutClaimsValidation()", "jwt.WithAudience(expectedAudience)"],
    ['jwt.WithValidMethods([]string{"none"})', 'jwt.WithValidMethods([]string{"RS256"})'],
    ["key := jwt.UnsafeAllowNoneSignatureType", "key := verifiedPublicKey"],
    ["grpc.WithInsecure()", "grpc.WithTransportCredentials(tlsCredentials)"],
    ["insecure.NewCredentials()", "credentials.NewTLS(config)"],
    ["tls.Config{MaxVersion: tls.VersionTLS11}", "tls.Config{MaxVersion: tls.VersionTLS13}"],
    ["decoder.Strict = false", "decoder.Strict = true"],
    ['http.Redirect(w, r, r.FormValue("next"), 302)', 'http.Redirect(w, r, "/home", 302)'],
    ['http.ServeFile(w, r, r.FormValue("path"))', 'http.ServeFile(w, r, validatedPath)'],
    ['os.RemoveAll(r.FormValue("directory"))', "os.RemoveAll(validatedOwnedDirectory)"],
    ["tls.Config{KeyLogWriter: os.Stdout}", "tls.Config{KeyLogWriter: nil}"],
    ["bcrypt.GenerateFromPassword(password, 4)", "bcrypt.GenerateFromPassword(password, 12)"],
    ["ssh.CertChecker{IsUserAuthority: func(key ssh.PublicKey) bool { return true }}", "ssh.CertChecker{IsUserAuthority: knownUserAuthority}"],
  ],
  CS: [
    ["reader.ProhibitDtd = false;", "reader.ProhibitDtd = true;"],
    ["settings.XmlResolver = new XmlUrlResolver();", "settings.XmlResolver = null;"],
    ["transform.Load(path, XsltSettings.TrustedXslt, resolver);", "transform.Load(path, XsltSettings.Default, null);"],
    ["[ValidateInput(false)]", "[ValidateInput(true)]"],
    ["EnableViewStateMac = false;", "EnableViewStateMac = true;"],
    ["ViewStateEncryptionMode = ViewStateEncryptionMode.Never;", "ViewStateEncryptionMode = ViewStateEncryptionMode.Always;"],
    ["EnableEventValidation = false;", "EnableEventValidation = true;"],
    ["new CookieOptions { HttpOnly = false };", "new CookieOptions { HttpOnly = true };"],
    ["new CookieOptions { Secure = false };", "new CookieOptions { Secure = true };"],
    ["options.RequireHttpsMetadata = false;", "options.RequireHttpsMetadata = true;"],
    ["parameters.ValidateIssuerSigningKey = false;", "parameters.ValidateIssuerSigningKey = true;"],
    ["parameters.RequireSignedTokens = false;", "parameters.RequireSignedTokens = true;"],
    ["parameters.ValidateLifetime = false;", "parameters.ValidateLifetime = true;"],
    ["parameters.ValidateAudience = false;", "parameters.ValidateAudience = true;"],
    ["parameters.ValidateIssuer = false;", "parameters.ValidateIssuer = true;"],
    ["new RSACryptoServiceProvider(1024);", "new RSACryptoServiceProvider(3072);"],
  ],
  RB: [
    ["Psych.unsafe_load_file(path)", "Psych.safe_load_file(path)"],
    ["Oj.object_load(json)", "Oj.strict_load(json)"],
    ["JSON.parse(json, create_additions: true)", "JSON.parse(json, create_additions: false)"],
    ["Kernel.open(params[:path])", "File.open(validatedPath)"],
    ["ERB.new(params[:template])", "ERB.new(trustedTemplate)"],
    ["context.min_version = OpenSSL::SSL::TLS1_VERSION", "context.min_version = OpenSSL::SSL::TLS1_2_VERSION"],
    ["config.session_store :cookie_store, httponly: false", "config.session_store :cookie_store, httponly: true"],
    ['User.find_by_sql("SELECT * FROM users WHERE id=#{id}")', 'User.find_by_sql(["SELECT * FROM users WHERE id=?", id])'],
    ["User.order(params[:sort])", "User.order(allowedSortColumn)"],
    ["render inline: params[:template]", "render template: 'profiles/show'"],
    ["service.public_send(params[:action])", "allowedHandlers[operation].call"],
    ["send_file params[:path]", "send_file allowedPath"],
  ],
  RS: [
    ["des::Des::new_from_slice(key)", "aes_gcm::Aes256Gcm::new(key)"],
    ["connector.set_verify_hostname(false);", "connector.set_verify_hostname(true);"],
    ["Cors::permissive()", 'Cors::default().allowed_origin("https://app.example")'],
    ['Files::new("/files", "/")', 'Files::new("/files", "public")'],
    ["SecretKey::from(&[0; 64])", "SecretKey::generate()"],
    ["validation.validate_exp = false;", "validation.validate_exp = true;"],
    ["validation.insecure_disable_signature_validation();", "Validation::new(Algorithm::RS256);"],
    ["openssl::rsa::Rsa::generate(1024)", "openssl::rsa::Rsa::generate(3072)"],
    ["argon2::Params::new(1024, 2, 1, None)", "argon2::Params::new(19456, 2, 1, None)"],
    ["public_key.encrypt(&mut rng, rsa::Pkcs1v15Encrypt, bytes)", "public_key.encrypt(&mut rng, rsa::Oaep::new::<Sha256>(), bytes)"],
  ],
  SWIFT: [
    ['UserDefaults.standard.set(token, forKey: "token")', 'keychain.store(token, forKey: "token")'],
    ['NSLog("%@", password)', 'NSLog("login completed")'],
    ["webView.loadHTMLString(userHtml, baseURL: nil)", "webView.loadHTMLString(trustedHtml, baseURL: nil)"],
    ['prefs.setValue(true, forKey: "allowFileAccessFromFileURLs")', 'prefs.setValue(false, forKey: "allowFileAccessFromFileURLs")'],
    ["SecTrustSetExceptions(trust, exceptions)", "SecTrustEvaluateWithError(trust, &error)"],
    ["[kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 1024]", "[kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 3072]"],
    ["CCAlgorithm(kCCAlgorithmDES)", "CCAlgorithm(kCCAlgorithmAES)"],
    ["unarchiver.requiresSecureCoding = false", "unarchiver.requiresSecureCoding = true"],
    ['db.execute(sql: "SELECT * FROM users WHERE id=\\(id)")', 'db.execute(sql: "SELECT * FROM users WHERE id=?", arguments: [id])'],
    ["[FileAttributeKey.posixPermissions: 0o777]", "[FileAttributeKey.posixPermissions: 0o600]"],
  ],
  SCALA: [
    ["toolbox.eval(tree)", "evaluateAllowedOperation(operation)"],
    ["toolbox.parse(request.body.asText.get)", "parseValidatedData(request.body.asText.get)"],
    ["HtmlFormat.raw(userHtml)", "HtmlFormat.escape(userHtml)"],
    ['sqlu"DELETE FROM users WHERE id=#$id"', 'sqlu"DELETE FROM users WHERE id=$id"'],
    ["cors.withAllowedOrigins(HttpOriginRange.*)", 'cors.withAllowedOrigins(HttpOriginRange("https://app.example"))'],
    ['Process(Seq("sh", "-c", command))', 'Process(Seq("/usr/bin/tool", arg))'],
    ['Source.fromURL(request.getQueryString("url").get)', "Source.fromURL(validatedUrl)"],
    ['Redirect(request.getQueryString("next").get)', 'Redirect("/home")'],
    ['Ok.sendFile(new File(request.getQueryString("path").get))', "Ok.sendFile(allowedFile)"],
    ["SSLLooseConfig(allowWeakCiphers = true)", "SSLLooseConfig(allowWeakCiphers = false)"],
  ],
  SH: [
    ["set -eux", "set -eu"],
    ["curl -u 'admin:synthetic-pass' https://api.example", "curl --netrc-file /run/secrets/netrc https://api.example"],
    ["openssl enc -des-cbc -in file", "encrypt_with_aead file"],
    ["openssl dgst -md5 file", "openssl dgst -sha256 file"],
    ["openssl genrsa -out key.pem 1024", "openssl genrsa -out key.pem 3072"],
    ["chmod u+s app", "chmod 0750 app"],
    ["chmod o+w file", "chmod 0600 file"],
    ["docker run --cap-add=SYS_ADMIN app", "docker run --cap-drop=ALL app"],
    ["docker run -v /:/host app", "docker run -v /srv/app:/data:ro app"],
    ["docker run --network=host app", "docker run --network=app-network app"],
    ["curl --location-trusted https://api.example", "curl --location https://api.example"],
    ["tar -x --absolute-names -f archive.tar", "tar -x -f archive.tar -C target"],
  ],
  CFG: [
    ["windowsOptions:\n  hostProcess: true", "windowsOptions:\n  hostProcess: false"],
    ["automountServiceAccountToken: true", "automountServiceAccountToken: false"],
    ["readOnlyRootFilesystem: false", "readOnlyRootFilesystem: true"],
    ["procMount: Unmasked", "procMount: Default"],
    ["shareProcessNamespace: true", "shareProcessNamespace: false"],
    ["capabilities:\n  add: [NET_RAW]", "capabilities:\n  drop: [NET_RAW]"],
    ["args: [--enable-skip-login]", "args: [--enable-insecure-login=false]"],
    ['ports: ["2375:2375"]', 'ports: ["127.0.0.1:2376:2376"]'],
    ['{"insecure-registries": ["registry.example:5000"]}', '{"insecure-registries": []}'],
    ["BlockPublicAcls: false", "BlockPublicAcls: true"],
    ["StorageEncrypted: false", "StorageEncrypted: true"],
    ["PubliclyAccessible: true", "PubliclyAccessible: false"],
    ["EnableKeyRotation: false", "EnableKeyRotation: true"],
    ["DeletionProtection: false", "DeletionProtection: true"],
    ["require_ssl: false", "require_ssl: true"],
    ["allowBlobPublicAccess: true", "allowBlobPublicAccess: false"],
    ["xpack.security.enabled: false", "xpack.security.enabled: true"],
    ["authorization: disabled", "authorization: enabled"],
    ["protected-mode no", "protected-mode yes"],
    ["skip-grant-tables", "skip-networking"],
    ["proxy_ssl_verify off;", "proxy_ssl_verify on;"],
    ["server app backend:443 ssl verify none", "server app backend:443 ssl verify required ca-file ca.pem"],
    ["autoindex on;", "autoindex off;"],
    ["management.endpoints.web.exposure.include=*", "management.endpoints.web.exposure.include=health,info"],
  ],
};
const cases = Object.entries(examples).flatMap(([prefix, pairs]) => pairs.map(([unsafe, safe], index) => ({ id: `${prefix}${100 + index}`, filename: filenames[prefix], unsafe, safe })));

test("expansion adds 200 unique rules with independent fixtures and complete metadata", () => {
  const pack = createExpansionRules(["unknown"]);
  assert.equal(pack.length, 200);
  assert.equal(ruleCount, 150036);
  assert.equal(new Set(staticRuleIds).size, ruleCount);
  assert.deepEqual(cases.map(({ id }) => id).sort(), pack.map((rule) => rule.id).sort());
  assert.equal(new Set(pack.map((rule) => `${rule.languages.join(',')}:${rule.pattern}`)).size, 200);
  for (const rule of pack) {
    assert.ok(rule.title.length > 8 && rule.description.length > 30 && rule.recommendation.length > 25, rule.id);
    assert.match(rule.cwe, /^CWE-\d+$/);
    assert.match(rule.owasp, /^A\d{2}:2021$/);
    assert.ok(rule.languages.length && rule.category && rule.references.length, rule.id);
  }
});
for (const { id, filename, unsafe, safe } of cases) {
  test(`${id}: risky construct and safe alternative`, () => {
    const result = scanCode(unsafe, filename);
    const finding = result.findings.find((item) => item.ruleId === id);
    assert.ok(finding, `missing ${id}: ${unsafe}`);
    assert.equal(result.findings.filter((item) => item.ruleId === id).length, 1);
    assert.equal(finding.snippet, unsafe.split("\n")[finding.line - 1].trim().slice(0, 220));
    assert.ok(!scanCode(safe, filename).findings.some((item) => item.ruleId === id), `false positive ${id}: ${safe}`);
    if (!id.startsWith("SEC")) assert.ok(!scanCode(unsafe, "other.txt", "unknown").findings.some((item) => item.ruleId === id));
  });
}
test("new formats survive ZIP extraction and select the correct rule language", () => {
  const formats = { vue: "javascript", svelte: "javascript", conf: "config", ini: "config", toml: "config", tf: "config", hcl: "config", plist: "config" };
  for (const [extension, language] of Object.entries(formats)) {
    assert.ok(isSupportedSourceFile(`settings.${extension.toUpperCase()}`));
    assert.equal(detectLanguage(`settings.${extension}`, ""), language);
  }
  const archive = extractZip(zipSync({
    "src/View.vue": strToU8('<div v-html="userHtml"></div>'), "src/View.svelte": strToU8("{@html userHtml}"),
    "config/redis.conf": strToU8("protected-mode no"), "app/lib/sast-rules-expansion.ts": strToU8("pattern catalog"),
  }));
  assert.equal(archive.files.length, 3);
  assert.equal(archive.skippedFiles, 1);
  const findings = scanFiles(archive.files).findings;
  for (const id of ["JS102", "JS103", "CFG118"]) assert.ok(findings.some((item) => item.ruleId === id));
});
test("new rules preserve CRLF positions, IDs and Kotlin applicability", () => {
  const result = scanFiles([
    { name: "Security.kt", code: "// config\r\ncookie.setHttpOnly(false);\r\ncookie.setHttpOnly(false);" },
    { name: "service.conf", code: "# TLS\r\nproxy_ssl_verify off;" },
  ]);
  assert.deepEqual(result.findings.filter((item) => item.ruleId === "JAVA116").map((item) => item.line), [2, 3]);
  assert.ok(result.findings.some((item) => item.ruleId === "CFG120" && item.line === 2));
  assert.equal(new Set(result.findings.map((item) => item.id)).size, result.findings.length);
});
test("20000 rules scan large safe sources within a practical time bound", () => {
  const started = performance.now();
  for (const filename of ["large.ts", "large.py", "large.conf"]) {
    const result = scanCode("# plain text\n".repeat(20000), filename);
    assert.equal(result.summary.total, 0);
    assert.equal(result.scannedLines, 20000);
  }
  assert.ok(performance.now() - started < 15000, "safe scans exceeded 15 seconds");
});
