import assert from "node:assert/strict";
import test from "node:test";
import { performance } from "node:perf_hooks";
import { zipSync, strToU8 } from "fflate";
import { createHttpRules } from "../app/lib/sast-rules-http.ts";
import { getStaticRules, ruleCount, scanCode, scanFiles } from "../app/lib/sast-engine.ts";
import { extractZip } from "../app/lib/archive.ts";

// Independent expected API order and input syntax: never generate examples from a rule's regex.
const jsApis = `child_process.exec child_process.execSync child_process.execFile child_process.execFileSync
child_process.spawn child_process.spawnSync shell.exec execa.command execa.commandSync
vm.runInNewContext vm.runInThisContext vm.runInContext vm.Script vm.compileFunction
ejs.compile ejs.render pug.compile pug.render handlebars.compile nunjucks.renderString
sequelize.query knex.raw prisma.$queryRawUnsafe prisma.$executeRawUnsafe connection.query pool.query
db.exec db.prepare axios.get axios.post axios.put axios.delete got.get got.post undici.request
http.get https.get fs.readFile fs.readFileSync fs.createReadStream fs.writeFile fs.writeFileSync
fs.createWriteStream fs.unlink fs.unlinkSync fs.rm fs.rmSync fs.readdir fs.readdirSync res.download`.split(/\s+/);
const pyApis = `os.system os.popen subprocess.getoutput subprocess.getstatusoutput subprocess.Popen
subprocess.run subprocess.call subprocess.check_call subprocess.check_output os.execv os.execve
os.execl os.execlp os.execvp os.execvpe eval exec compile jinja2.Template mako.template.Template
django.template.Template render_template_string cursor.execute cursor.executemany cursor.executescript
connection.execute sqlalchemy.text peewee.SQL requests.get requests.post requests.put requests.delete
requests.head requests.patch httpx.get httpx.post httpx.put urllib.request.urlopen urllib.request.Request
open os.remove os.unlink os.rmdir os.listdir os.scandir shutil.rmtree shutil.copyfile shutil.move send_file pathlib.Path`.split(/\s+/);
jsApis.push(...`fs.promises.readFile fs.promises.writeFile fs.promises.appendFile fs.promises.open
fs.promises.unlink fs.promises.rm fs.promises.rmdir fs.promises.mkdir fs.promises.readdir
fs.promises.stat fs.promises.lstat fs.promises.access fs.promises.chmod fs.promises.chown
fs.promises.truncate fs.promises.utimes fs.promises.realpath fs.promises.readlink fs.promises.copyFile fs.promises.rename
fsExtra.readFile fsExtra.writeFile fsExtra.appendFile fsExtra.remove fsExtra.removeSync
fsExtra.emptyDir fsExtra.emptyDirSync fsExtra.ensureDir fsExtra.ensureDirSync fsExtra.ensureFile fsExtra.ensureFileSync
fsExtra.outputFile fsExtra.outputFileSync fsExtra.readJson fsExtra.readJsonSync fsExtra.writeJson fsExtra.writeJsonSync
fsExtra.copy fsExtra.copySync fsExtra.move
axios.patch axios.head axios.options got.put got.delete got.patch got.head got.stream
superagent.get superagent.post superagent.put superagent.delete superagent.patch superagent.head
undici.fetch fetch request.get request.post request.put request.delete
lodash.template _.template doT.template eta.compile eta.renderString liquid.parse nunjucks.compile
handlebars.precompile Handlebars.compile Handlebars.precompile ejs.renderFile ejs.compileClient
pug.compileFile pug.renderFile nunjucks.render eta.renderFile liquid.parseFile liquid.renderFile mustache.render Mustache.render
mysql.query mysql2.query sqlite.exec sqlite.prepare betterSqlite.prepare sql.query sql.execute database.query database.execute database.exec
cp.exec cp.execSync cp.execFile cp.execFileSync cp.spawn cp.spawnSync shelljs.exec execa.sync exec execSync`.split(/\s+/));
pyApis.push(...`os.open os.chmod os.chown os.stat os.lstat os.access os.makedirs os.mkdir os.rename os.replace
os.readlink os.symlink os.walk os.truncate shutil.copy shutil.copy2 shutil.copytree shutil.chown pathlib.PurePath Path
httpx.delete httpx.head httpx.options httpx.patch session.get session.post session.put session.delete session.head session.patch
client.get client.post client.put client.delete client.head client.patch wget.download urllib.request.urlretrieve
urllib.request.URLopener.open urllib.request.FancyURLopener.open
db.execute db.executemany db.executescript db.query database.execute database.fetch_all database.fetch_one database.fetch_val
engine.execute session.execute text RawSQL django.db.models.expressions.RawSQL pandas.read_sql pandas.read_sql_query
pandas.read_sql_table pd.read_sql pd.read_sql_query psycopg.sql.SQL SQL
pickle.loads dill.loads cloudpickle.loads marshal.loads jsonpickle.decode yaml.unsafe_load pickle.load dill.load yaml.unsafe_load_all
cloudpickle.load shelve.open pandas.read_csv torch.load torch.jit.load joblib.load numpy.load numpy.loadtxt numpy.genfromtxt pandas.read_pickle pd.read_pickle
importlib.import_module __import__ runpy.run_path runpy.run_module ctypes.CDLL ctypes.PyDLL ctypes.WinDLL ctypes.OleDLL builtins.eval builtins.exec
bottle.template bottle.SimpleTemplate tornado.template.Template tornado.template.Loader django.template.Engine.from_string
environment.from_string env.from_string template.Template Template jinja2.Environment.from_string`.split(/\s+/));
const phpApis = `exec shell_exec system passthru popen proc_open pcntl_exec eval assert create_function
mysqli_query mysqli_multi_query pg_query pg_send_query sqlite_query $pdo->query $pdo->exec $mysqli->query $mysqli->multi_query $db->query
file_get_contents file fopen readfile file_put_contents unlink rmdir mkdir scandir glob opendir chmod chown rename copy
move_uploaded_file parse_ini_file simplexml_load_file DOMDocument::load unserialize igbinary_unserialize yaml_parse yaml_parse_file
curl_init $client->get $client->post $client->delete $twig->createTemplate $blade->compileString header`.split(/\s+/);
const rbApis = `system exec spawn IO.popen Open3.capture2 Open3.capture2e Open3.capture3 Open3.popen2 Open3.popen2e Open3.popen3
eval instance_eval class_eval module_eval Kernel.eval ActiveRecord::Base.connection.execute ActiveRecord::Base.connection.exec_query
connection.execute connection.exec_query connection.select_all DB.fetch DB.run database.execute File.read File.binread File.write
File.binwrite File.open File.delete File.unlink File.rename FileUtils.rm FileUtils.rm_rf FileUtils.cp FileUtils.mv
Dir.entries Dir.glob Dir.mkdir Dir.rmdir Marshal.load Marshal.restore YAML.load YAML.unsafe_load YAML.load_file
URI.open Net::HTTP.get Net::HTTP.get_response RestClient.get RestClient.post ERB.new`.split(/\s+/);
const channels = [
  { prefix: "HTTPJS", apis: jsApis, filename: "handler.ts", other: "handler.py", sources: [
    "req.query.value", "req.body.value", "req.params.value", "req.headers['x-value']", "req.cookies.value",
    "request.query.value", "request.body.value", "request.params.value", "ctx.query.value", "ctx.request.body.value",
  ] },
  { prefix: "HTTPPY", apis: pyApis, filename: "handler.py", other: "handler.ts", sources: [
    "request.args['value']", "request.form['value']", "request.values['value']", "request.json['value']",
    "request.cookies['value']", "request.headers['x-value']", "request.GET['value']", "request.POST['value']",
    "request.query_params['value']", "request.path_params['value']",
  ] },
  { prefix: "HTTPPHP", apis: phpApis, filename: "handler.php", other: "handler.py", sources: [
    "$_GET['value']", "$_POST['value']", "$_REQUEST['value']", "$_COOKIE['value']", "$_SERVER['HTTP_X_VALUE']",
    "$request->query->get('value')", "$request->request->get('value')", "$request->cookies->get('value')",
    "$request->headers->get('x-value')", "$request->server->get('HTTP_X_VALUE')",
  ] },
  { prefix: "HTTPRB", apis: rbApis, filename: "handler.rb", other: "handler.py", sources: [
    "params[:value]", "request.params['value']", "request.GET['value']", "request.POST['value']",
    "request.cookies['value']", "request.env['HTTP_X_VALUE']", "request.query_parameters['value']",
    "request.request_parameters['value']", "request.path_parameters['value']", "cookies[:value]",
  ] },
];

test("20000-rule catalog includes 4000 unique HTTP API/input definitions", () => {
  const rules = createHttpRules();
  assert.equal(ruleCount, 150036);
  assert.equal(rules.length, 4000);
  assert.equal(new Set(getStaticRules().map(r => r.id)).size, ruleCount);
  const signatures = getStaticRules().map(r => `${r.languages.join(',')}:${r.pattern}`);
  assert.equal(new Set(signatures).size, signatures.length);
  for (const rule of rules) {
    assert.equal(rule.confidence, "medium");
    assert.ok(rule.description.length > 80 && rule.recommendation.length > 30);
    assert.match(rule.cwe, /^CWE-\d+$/);
    assert.match(rule.owasp, /^A\d{2}:2021$/);
    assert.ok(rule.references.length && rule.category && !rule.pattern.global);
  }
});

for (const { prefix, apis, sources, filename, other } of channels) {
  test(`${prefix}: every API and input channel detects direct flow and rejects safe alternatives`, () => {
    assert.equal(apis.length, prefix === 'HTTPJS' || prefix === 'HTTPPY' ? 150 : 50);
    for (const [apiIndex, api] of apis.entries()) {
      for (const [sourceIndex, source] of sources.entries()) {
        const id = `${prefix}${String(apiIndex * 10 + sourceIndex + 1).padStart(3, '0')}`;
        const unsafe = `${api}(${source})`;
        const matches = scanCode(unsafe, filename).findings.filter(f => f.ruleId.startsWith(prefix));
        assert.deepEqual(matches.map(f => f.ruleId), [id], unsafe);
        assert.equal(matches[0].column, 1);
        for (const safe of [`${api}(trusted_value)`, `${api}(validate(${source}))`,
          `${api}('fixed', ${source})`, `${api}(trusted_value, ${source})`]) {
          assert.ok(!scanCode(safe, filename).findings.some(f => f.ruleId === id), `${id}: ${safe}`);
        }
        assert.ok(!scanCode(unsafe, other).findings.some(f => f.ruleId === id), id);
      }
    }
  });
}

test("HTTP boundaries, whitespace, CRLF, repeated findings and file IDs", () => {
  const code = "// header\r\n  axios.get ( req.query['url'] );\r\n  axios.get(req.query.url);";
  const findings = scanFiles([{ name: "a.ts", code }, { name: "b.ts", code }]).findings.filter(f => f.ruleId === 'HTTPJS281');
  assert.equal(findings.length, 4);
  assert.deepEqual(findings.slice(0, 2).map(f => [f.line, f.column]), [[2, 3], [3, 3]]);
  assert.equal(new Set(findings.map(f => f.id)).size, 4);
  for (const code of ["myaxios.get(req.query.url)", "obj.axios.get(req.query.url)",
    "axios.get(req.queryExtra.url)", "axios.get(req.query_value)", "axios.get(ctx.req.query.url)"]) {
    assert.ok(!scanCode(code, "a.ts").findings.some(f => f.ruleId === 'HTTPJS281'), code);
  }
  assert.ok(scanCode("axios.get(req.query.url)", "a.js").findings.some(f => f.ruleId === 'HTTPJS281'));
});

test("ZIP scans new checks and excludes their own catalog", () => {
  const archive = extractZip(zipSync({
    "src/handler.py": strToU8("httpx.put(request.POST['url'])"),
    "app/lib/sast-rules-http.ts": strToU8("httpx.put(request.POST['url'])"),
  }));
  assert.equal(archive.files.length, 1);
  assert.equal(archive.skippedFiles, 1);
  assert.ok(scanFiles(archive.files).findings.some(f => f.ruleId === "HTTPPY368"));
});

test("new HTTP patterns handle long malformed calls without broad backtracking", () => {
  const started = performance.now();
  for (const filename of ["a.ts", "a.py"]) {
    const code = "ordinary text\n".repeat(5000) + "axios.get(" + " ".repeat(50000) + "req.queryExtra.url)";
    assert.ok(!scanCode(code, filename).findings.some(f => f.ruleId.startsWith('HTTP')));
  }
  assert.ok(performance.now() - started < 10000);
});
