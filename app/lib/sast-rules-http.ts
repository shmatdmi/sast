import type { Rule } from "./sast-engine.ts";

// Each stable ID identifies one API + HTTP input channel, not a new weakness class.
// Only direct first-argument flows are recognized; aliases and sanitizers need dataflow analysis.
type Sink = [api: string, cwe: number];
const jsSinks: Sink[] = [
  ["child_process.exec", 78], ["child_process.execSync", 78],
  ["child_process.execFile", 78], ["child_process.execFileSync", 78],
  ["child_process.spawn", 78], ["child_process.spawnSync", 78],
  ["shell.exec", 78], ["execa.command", 78], ["execa.commandSync", 78],
  ["vm.runInNewContext", 94], ["vm.runInThisContext", 94], ["vm.runInContext", 94],
  ["vm.Script", 94], ["vm.compileFunction", 94],
  ["ejs.compile", 1336], ["ejs.render", 1336], ["pug.compile", 1336],
  ["pug.render", 1336], ["handlebars.compile", 1336], ["nunjucks.renderString", 1336],
  ["sequelize.query", 89], ["knex.raw", 89], ["prisma.$queryRawUnsafe", 89],
  ["prisma.$executeRawUnsafe", 89], ["connection.query", 89], ["pool.query", 89],
  ["db.exec", 89], ["db.prepare", 89],
  ["axios.get", 918], ["axios.post", 918], ["axios.put", 918], ["axios.delete", 918],
  ["got.get", 918], ["got.post", 918], ["undici.request", 918],
  ["http.get", 918], ["https.get", 918],
  ["fs.readFile", 22], ["fs.readFileSync", 22], ["fs.createReadStream", 22],
  ["fs.writeFile", 22], ["fs.writeFileSync", 22], ["fs.createWriteStream", 22],
  ["fs.unlink", 22], ["fs.unlinkSync", 22], ["fs.rm", 22],
  ["fs.rmSync", 22], ["fs.readdir", 22], ["fs.readdirSync", 22], ["res.download", 22],
];
const pySinks: Sink[] = [
  ["os.system", 78], ["os.popen", 78], ["subprocess.getoutput", 78],
  ["subprocess.getstatusoutput", 78], ["subprocess.Popen", 78],
  ["subprocess.run", 78], ["subprocess.call", 78], ["subprocess.check_call", 78],
  ["subprocess.check_output", 78], ["os.execv", 78], ["os.execve", 78],
  ["os.execl", 78], ["os.execlp", 78], ["os.execvp", 78], ["os.execvpe", 78],
  ["eval", 95], ["exec", 94], ["compile", 94],
  ["jinja2.Template", 1336], ["mako.template.Template", 1336],
  ["django.template.Template", 1336], ["render_template_string", 1336],
  ["cursor.execute", 89], ["cursor.executemany", 89], ["cursor.executescript", 89],
  ["connection.execute", 89], ["sqlalchemy.text", 89], ["peewee.SQL", 89],
  ["requests.get", 918], ["requests.post", 918], ["requests.put", 918],
  ["requests.delete", 918], ["requests.head", 918], ["requests.patch", 918],
  ["httpx.get", 918], ["httpx.post", 918], ["httpx.put", 918],
  ["urllib.request.urlopen", 918], ["urllib.request.Request", 918],
  ["open", 22], ["os.remove", 22], ["os.unlink", 22], ["os.rmdir", 22],
  ["os.listdir", 22], ["os.scandir", 22], ["shutil.rmtree", 22],
  ["shutil.copyfile", 22], ["shutil.move", 22], ["send_file", 22], ["pathlib.Path", 22],
];
const jsSources = ["req.query", "req.body", "req.params", "req.headers", "req.cookies",
  "request.query", "request.body", "request.params", "ctx.query", "ctx.request.body"];
const pySources = ["request.args", "request.form", "request.values", "request.json",
  "request.cookies", "request.headers", "request.GET", "request.POST",
  "request.query_params", "request.path_params"];
// Appended API rows keep the original 2000-catalog IDs stable.
const rows = (apis: string, cwe: number): Sink[] => apis.trim().split(/\s+/).map(api => [api, cwe]);
jsSinks.push(
  ...rows(`fs.promises.readFile fs.promises.writeFile fs.promises.appendFile fs.promises.open
    fs.promises.unlink fs.promises.rm fs.promises.rmdir fs.promises.mkdir fs.promises.readdir
    fs.promises.stat fs.promises.lstat fs.promises.access fs.promises.chmod fs.promises.chown
    fs.promises.truncate fs.promises.utimes fs.promises.realpath fs.promises.readlink
    fs.promises.copyFile fs.promises.rename`, 22),
  ...rows(`fsExtra.readFile fsExtra.writeFile fsExtra.appendFile fsExtra.remove fsExtra.removeSync
    fsExtra.emptyDir fsExtra.emptyDirSync fsExtra.ensureDir fsExtra.ensureDirSync
    fsExtra.ensureFile fsExtra.ensureFileSync fsExtra.outputFile fsExtra.outputFileSync
    fsExtra.readJson fsExtra.readJsonSync fsExtra.writeJson fsExtra.writeJsonSync
    fsExtra.copy fsExtra.copySync fsExtra.move`, 22),
  ...rows(`axios.patch axios.head axios.options got.put got.delete got.patch got.head got.stream
    superagent.get superagent.post superagent.put superagent.delete superagent.patch superagent.head
    undici.fetch fetch request.get request.post request.put request.delete`, 918),
  ...rows(`lodash.template _.template doT.template eta.compile eta.renderString liquid.parse
    nunjucks.compile handlebars.precompile Handlebars.compile Handlebars.precompile
    ejs.renderFile ejs.compileClient pug.compileFile pug.renderFile nunjucks.render
    eta.renderFile liquid.parseFile liquid.renderFile mustache.render Mustache.render`, 1336),
  ...rows(`mysql.query mysql2.query sqlite.exec sqlite.prepare betterSqlite.prepare
    sql.query sql.execute database.query database.execute database.exec`, 89),
  ...rows(`cp.exec cp.execSync cp.execFile cp.execFileSync cp.spawn cp.spawnSync
    shelljs.exec execa.sync exec execSync`, 78),
);
pySinks.push(
  ...rows(`os.open os.chmod os.chown os.stat os.lstat os.access os.makedirs os.mkdir
    os.rename os.replace os.readlink os.symlink os.walk os.truncate
    shutil.copy shutil.copy2 shutil.copytree shutil.chown pathlib.PurePath Path`, 22),
  ...rows(`httpx.delete httpx.head httpx.options httpx.patch session.get session.post session.put
    session.delete session.head session.patch client.get client.post client.put client.delete
    client.head client.patch wget.download urllib.request.urlretrieve
    urllib.request.URLopener.open urllib.request.FancyURLopener.open`, 918),
  ...rows(`db.execute db.executemany db.executescript db.query database.execute database.fetch_all
    database.fetch_one database.fetch_val engine.execute session.execute text RawSQL
    django.db.models.expressions.RawSQL pandas.read_sql pandas.read_sql_query pandas.read_sql_table
    pd.read_sql pd.read_sql_query psycopg.sql.SQL SQL`, 89),
  ...rows(`pickle.loads dill.loads cloudpickle.loads marshal.loads jsonpickle.decode
    yaml.unsafe_load pickle.load dill.load yaml.unsafe_load_all cloudpickle.load
    shelve.open pandas.read_csv torch.load torch.jit.load joblib.load
    numpy.load numpy.loadtxt numpy.genfromtxt pandas.read_pickle pd.read_pickle`, 502),
  ...rows(`importlib.import_module __import__ runpy.run_path runpy.run_module
    ctypes.CDLL ctypes.PyDLL ctypes.WinDLL ctypes.OleDLL
    builtins.eval builtins.exec`, 94),
  ...rows(`bottle.template bottle.SimpleTemplate tornado.template.Template
    tornado.template.Loader django.template.Engine.from_string
    environment.from_string env.from_string template.Template Template
    jinja2.Environment.from_string`, 1336),
);
const phpSinks: Sink[] = [
  ...rows(`exec shell_exec system passthru popen proc_open pcntl_exec`, 78),
  ...rows(`eval assert create_function`, 94),
  ...rows(`mysqli_query mysqli_multi_query pg_query pg_send_query sqlite_query
    $pdo->query $pdo->exec $mysqli->query $mysqli->multi_query $db->query`, 89),
  ...rows(`file_get_contents file fopen readfile file_put_contents unlink rmdir mkdir
    scandir glob opendir chmod chown rename copy move_uploaded_file parse_ini_file
    simplexml_load_file DOMDocument::load`, 22),
  ...rows(`unserialize igbinary_unserialize yaml_parse yaml_parse_file`, 502),
  ...rows(`curl_init $client->get $client->post $client->delete`, 918),
  ...rows(`$twig->createTemplate $blade->compileString`, 1336),
  ...rows(`header`, 113),
];
const rbSinks: Sink[] = [
  ...rows(`system exec spawn IO.popen Open3.capture2 Open3.capture2e Open3.capture3
    Open3.popen2 Open3.popen2e Open3.popen3`, 78),
  ...rows(`eval instance_eval class_eval module_eval Kernel.eval`, 94),
  ...rows(`ActiveRecord::Base.connection.execute ActiveRecord::Base.connection.exec_query
    connection.execute connection.exec_query connection.select_all
    DB.fetch DB.run database.execute`, 89),
  ...rows(`File.read File.binread File.write File.binwrite File.open File.delete File.unlink
    File.rename FileUtils.rm FileUtils.rm_rf FileUtils.cp FileUtils.mv
    Dir.entries Dir.glob Dir.mkdir Dir.rmdir`, 22),
  ...rows(`Marshal.load Marshal.restore YAML.load YAML.unsafe_load YAML.load_file`, 502),
  ...rows(`URI.open Net::HTTP.get Net::HTTP.get_response RestClient.get RestClient.post`, 918),
  ...rows(`ERB.new`, 1336),
];
const phpSources = ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER",
  "$request->query", "$request->request", "$request->cookies", "$request->headers", "$request->server"];
const rbSources = ["params", "request.params", "request.GET", "request.POST", "request.cookies",
  "request.env", "request.query_parameters", "request.request_parameters", "request.path_parameters", "cookies"];
const escape = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const pathApis = new Set(`ejs.renderFile pug.compileFile pug.renderFile nunjucks.render eta.renderFile
  liquid.parseFile liquid.renderFile shelve.open pandas.read_csv numpy.loadtxt numpy.genfromtxt
  tornado.template.Loader yaml_parse_file YAML.load_file numpy.load torch.load`.split(/\s+/));
const advice: Record<number, string> = {
  78: "Выбирайте исполняемый файл из фиксированного списка, отключайте shell и передавайте проверенные аргументы отдельно.",
  94: "Не выполняйте HTTP-ввод как код: используйте фиксированные операции и отдельные проверенные данные.",
  95: "Замените eval разбором данных и фиксированным набором разрешённых операций.",
  1336: "Используйте фиксированный доверенный шаблон, передавайте HTTP-ввод только как данные шаблона.",
  89: "Используйте фиксированный SQL с параметрами; имена таблиц и столбцов выбирайте из разрешённого списка.",
  918: "Разрешайте только доверенные схемы и узлы; проверяйте DNS, частные адреса и каждый redirect.",
  22: "Нормализуйте путь и проверяйте его принадлежность разрешённому каталогу; учитывайте символические ссылки и права доступа.",
  502: "Не десериализуйте недоверенные объекты; используйте безопасный формат данных, строгую схему и доверенные файлы.",
  113: "Не формируйте HTTP-заголовок из сырого ввода; проверяйте имя и значение, запрещайте CR и LF.",
};

/** A necessary literal for each HTTP regex; used to skip APIs absent from a file. */
export function getHttpRuleApi(id: string): string | undefined {
  const match = /^HTTP(JS|PY|PHP|RB)(\d+)$/.exec(id);
  if (!match) return undefined;
  const sinks = { JS: jsSinks, PY: pySinks, PHP: phpSinks, RB: rbSinks }[match[1]];
  return sinks?.[Math.floor((Number(match[2]) - 1) / 10)]?.[0];
}

export function createHttpRules(): Rule[] {
  return [
    { prefix: "HTTPJS", sinks: jsSinks, sources: jsSources, languages: ["javascript", "typescript"] },
    { prefix: "HTTPPY", sinks: pySinks, sources: pySources, languages: ["python"] },
    { prefix: "HTTPPHP", sinks: phpSinks, sources: phpSources, languages: ["php"] },
    { prefix: "HTTPRB", sinks: rbSinks, sources: rbSources, languages: ["ruby"] },
  ].flatMap(({ prefix, sinks, sources, languages }) => sinks.map(([api, cwe]): Sink =>
    [api, pathApis.has(api) ? 22 : cwe]).flatMap(([api, cwe], sinkIndex) =>
    sources.map((source, sourceIndex): Rule => ({
      id: `${prefix}${String(sinkIndex * sources.length + sourceIndex + 1).padStart(3, "0")}`,
      languages,
      title: `${api}: HTTP-ввод из ${source}`,
      description: `Прямой HTTP-ввод из ${source} передан первым аргументом в ${api}. Это сигнал для проверки: доверие к данным и предшествующая валидация не устанавливаются регулярным выражением.`,
      severity: cwe === 22 || cwe === 918 ? "high" : "critical",
      cwe: `CWE-${cwe}`,
      owasp: cwe === 918 ? "A10:2021" : cwe === 22 ? "A01:2021" : cwe === 502 ? "A08:2021" : "A03:2021",
      confidence: "medium",
      // No broad argument wildcard: avoid crossing calls, literals, or sanitizer wrappers.
      pattern: new RegExp(prefix === "HTTPPHP" || prefix === "HTTPRB"
        ? `(?<![\\w$.:>])${escape(api)}\\s*\\(\\s*${escape(source)}(?=\\s*(?:->|\\.|\\[|[,)]))`
        : `(?<![\\w$.])${escape(api)}\\s*\\(\\s*${escape(source)}(?=\\s*(?:\\.|\\[|[,)]))`),
      category: cwe === 22 ? "validation" : cwe === 918 ? "ssrf" : cwe === 502 ? "deserialization" : "injection",
      recommendation: advice[cwe],
      references: [`https://cwe.mitre.org/data/definitions/${cwe}.html`],
    }))));
}
