import type { Rule } from "./sast-engine.ts";

const newLanguages = ["c", "cpp", "dart", "elixir", "lua", "powershell"];
type Spec = [id: string, title: string, cwe: number, category: string, pattern: RegExp, recommendation: string];
const groups: Record<string, Spec[]> = {
  c: [
    ["C001", "C: чтение gets без ограничения длины", 120, "validation", /\bgets\s*\(/, "Замените gets на fgets с размером буфера и обработайте ошибку и усечение ввода."],
    ["C002", "C: копирование без размера буфера", 120, "validation", /\b(?:strcpy|strcat|sprintf)\s*\(/, "Проверьте ёмкость буфера; используйте snprintf с контролем возвращённой длины или копирование с явной проверкой границ."],
    ["C003", "C: динамическая строка формата", 134, "injection", /\bprintf\s*\(\s*[A-Za-z_]\w*(?:\s*\[[^\]\n]+\])?\s*[,)]/, "Передавайте фиксированный формат: printf(\"%s\", value); не используйте ввод как строку формата."],
    ["C004", "C: динамическая команда оболочки", 78, "injection", /\b(?:system|popen)\s*\(\s*[A-Za-z_]\w*(?:\s*\[[^\]\n]+\])?\s*[,)]/, "Запускайте фиксированную программу через execve/posix_spawn с отдельными проверенными аргументами без shell."],
    ["C005", "C: слабый хеш MD5 или SHA-1", 327, "crypto", /\b(?:MD5|MD5_Init|SHA1|SHA1_Init|EVP_md5|EVP_sha1)\s*\(/, "Для криптографической целостности применяйте SHA-256/HMAC; пароли храните с подходящим password KDF."],
  ],
  cpp: [
    ["CPP001", "C++: копирование без размера буфера", 120, "validation", /\b(?:strcpy|strcat|sprintf|gets)\s*\(/, "Используйте std::string либо проверьте размеры и границы перед записью в буфер."],
    ["CPP002", "C++: динамическая строка формата", 134, "injection", /\bprintf\s*\(\s*[A-Za-z_]\w*(?:\s*\[[^\]\n]+\])?\s*[,)]/, "Используйте фиксированный формат printf(\"%s\", value) или типизированное форматирование."],
    ["CPP003", "C++: динамическая команда оболочки", 78, "injection", /\b(?:system|popen)\s*\(\s*[A-Za-z_]\w*(?:\s*\.\s*c_str\s*\(\s*\))?\s*[,)]/, "Запускайте фиксированную программу без shell и передавайте проверенные аргументы отдельно."],
    ["CPP004", "C++: небезопасное имя временного файла", 377, "validation", /\b(?:tmpnam|tempnam|mktemp)\s*\(/, "Создавайте и открывайте временный файл атомарно через mkstemp или безопасный API платформы."],
    ["CPP005", "C++: слабый хеш MD5 или SHA-1", 327, "crypto", /\b(?:MD5|MD5_Init|SHA1|SHA1_Init|EVP_md5|EVP_sha1)\s*\(/, "Используйте SHA-256/HMAC для криптографической целостности и password KDF для паролей."],
  ],
  dart: [
    ["DART001", "Dart: принимается любой TLS-сертификат", 295, "transport", /\bbadCertificateCallback\s*=\s*\([^\n;]*\)\s*(?:=>\s*true\b|\{\s*return\s+true\s*;)/, "Сохраняйте проверку сертификата и имени сервера; настройте доверенный CA вместо безусловного true."],
    ["DART002", "Dart: процесс запускается через shell", 78, "injection", /\bProcess\.(?:run|runSync|start)\s*\([^\n;]*\brunInShell\s*:\s*true\b/, "Используйте runInShell: false, фиксированный executable и список проверенных аргументов; отдельно проверьте batch-файлы Windows."],
    ["DART003", "Dart: интерполяция в SQL-запросе", 89, "injection", /\braw(?:Query|Insert|Update|Delete)\s*\(\s*["'][^\n]*\$\{?[A-Za-z_]\w*/, "Используйте SQL placeholders и список bind-аргументов вместо интерполяции."],
    ["DART004", "Dart: слабый хеш MD5 или SHA-1", 327, "crypto", /\b(?:md5|sha1)\.convert\s*\(/, "Используйте SHA-256/HMAC для целостности; для паролей применяйте password KDF."],
    ["DART005", "Dart: предсказуемое случайное значение секрета", 338, "crypto", /\b(?:token|nonce|secret|password|sessionId)\s*=\s*Random\s*\(\s*\)\s*\./i, "Для секретов и nonce используйте Random.secure() и достаточное число случайных байтов."],
  ],
  elixir: [
    ["ELIXIR001", "Elixir: выполнение динамического кода", 95, "injection", /\b(?:Code|EEx)\.eval_(?:string|quoted|file)\s*\(/, "Не выполняйте недоверенный код; используйте фиксированные шаблоны или явный список разрешённых операций."],
    ["ELIXIR002", "Elixir: динамическая команда оболочки", 78, "injection", /(?:\bSystem\.shell|:os\.cmd)\s*\(\s*(?:[a-z_]\w*|"[^"\n]*#\{)/, "Используйте System.cmd с фиксированным executable и отдельными проверенными аргументами."],
    ["ELIXIR003", "Elixir: интерполяция SQL в Ecto", 89, "injection", /\bEcto\.Adapters\.SQL\.query!?\s*\(\s*[^,\n]+,\s*"[^"\n]*#\{/, "Используйте placeholders $1, $2 и список параметров Ecto.Adapters.SQL.query."],
    ["ELIXIR004", "Elixir: десериализация Erlang-термов", 502, "deserialization", /:erlang\.binary_to_term\s*\(/, "Для внешних данных используйте JSON со схемой либо Plug.Crypto.non_executable_binary_to_term с [:safe]; одного [:safe] недостаточно."],
    ["ELIXIR005", "Elixir: динамическое создание атомов", 400, "validation", /\bString\.to_atom\s*\(\s*[a-z_]\w*(?:\s*\[[^\]\n]+\])?\s*\)/, "Используйте строки или фиксированный allowlist; to_existing_atom допустим только после проверки разрешённых значений."],
  ],
  lua: [
    ["LUA001", "Lua: динамическая команда оболочки", 78, "injection", /\bos\.execute\s*\(\s*(?:[A-Za-z_]\w*|["'][^\n]*["']\s*\.\.)/, "Не передавайте недоверенный ввод в shell; используйте API нужной операции или фиксированную программу с проверенными аргументами."],
    ["LUA002", "Lua: динамическая команда io.popen", 78, "injection", /\bio\.popen\s*\(\s*(?:[A-Za-z_]\w*|["'][^\n]*["']\s*\.\.)/, "Исключите сборку команды из внешнего ввода; предпочитайте API без интерпретации shell."],
    ["LUA003", "Lua: загрузка динамического кода", 95, "injection", /\b(?:load|loadstring)\s*\(\s*[A-Za-z_]\w*/, "Разбирайте данные вместо загрузки кода; ограничение environment не делает недоверенный Lua-код безопасным."],
    ["LUA004", "Lua: SQL собирается конкатенацией", 89, "injection", /(?:\:execute|\.query)\s*\(\s*["'][^\n]*["']\s*\.\./, "Применяйте параметры запроса поддерживаемого драйвера вместо конкатенации SQL."],
    ["LUA005", "Lua: HTML из параметров OpenResty", 79, "xss", /\bngx\.(?:say|print)\s*\(\s*ngx\.var\.arg_[A-Za-z_]\w*/, "Экранируйте HTML по контексту или отдавайте данные как JSON с соответствующим Content-Type."],
  ],
  powershell: [
    ["PS001", "PowerShell: выполнение строки как кода", 95, "injection", /\b(?:Invoke-Expression|iex)\b\s+(?:-Command\s+)?[^\r\n;]+/i, "Используйте прямой вызов команды и отдельные аргументы; не выполняйте строку из внешнего источника."],
    ["PS002", "PowerShell: отключена проверка TLS", 295, "transport", /\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\r\n;]*-SkipCertificateCheck\b(?!\s*:\s*\$false\b)/i, "Удалите SkipCertificateCheck и настройте доверенный CA и корректное имя сервера."],
    ["PS003", "PowerShell: пароль в открытом строковом литерале", 798, "secrets", /\bConvertTo-SecureString\b\s+(?:-String\s+)?["'][^"'\r\n]{6,}["'][^\r\n;]*-AsPlainText\b/i, "Получайте секрет через Read-Host -AsSecureString или хранилище секретов; удалите литерал и смените раскрытый пароль."],
    ["PS004", "PowerShell: безусловный callback сертификата", 295, "transport", /\bServerCertificateValidationCallback\s*=\s*\{\s*\$true\s*\}/i, "Сохраняйте штатную проверку TLS и настройте доверенный CA вместо безусловного callback."],
    ["PS005", "PowerShell: интерполяция в SQL-команде", 89, "injection", /\bCommandText\s*=\s*"[^"\r\n]*\$(?:[A-Za-z_]\w*|\{)/i, "Используйте фиксированный CommandText и SqlParameter вместо интерполяции SQL."],
  ],
};
const shared: Spec[] = [
  ["NEWSEC001", "Секрет в исходном коде", 798, "secrets", /\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*["'][^"'\r\n]{6,}["']/i, "Удалите секрет из кода, отзовите его и загружайте новое значение из защищённого хранилища."],
  ["NEWSEC002", "Приватный ключ в исходном коде", 321, "secrets", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, "Удалите и перевыпустите ключ; храните его вне репозитория с минимальными правами доступа."],
  ["NEWSEC003", "AWS access key в исходном коде", 798, "secrets", /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/, "Проверьте использование и отзовите ключ AWS; используйте IAM role или защищённое хранилище."],
  ["NEWSEC004", "GitHub token в исходном коде", 798, "secrets", /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/, "Отзовите токен GitHub, проверьте доступ и выдайте минимальные permissions новому токену."],
  ["NEWSEC005", "GitLab token в исходном коде", 798, "secrets", /\bglpat-[A-Za-z0-9_-]{20,255}\b/, "Отзовите токен GitLab и проверьте операции с репозиториями."],
  ["NEWSEC006", "Пароль в URI базы данных", 798, "secrets", /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s:@/]+:[^\s@/]+@/i, "Уберите пароль из исходников и смените его; загружайте URI подключения из хранилища секретов."],
];
const references: Record<string, string> = {
  c: "https://wiki.sei.cmu.edu/confluence/display/c/STR31-C.+Guarantee+that+storage+for+strings+has+sufficient+space+for+character+data+and+the+null+terminator",
  cpp: "https://wiki.sei.cmu.edu/confluence/display/c/FIO30-C.+Exclude+user+input+from+format+strings",
  dart: "https://api.dart.dev/dart-io/HttpClient/badCertificateCallback.html",
  elixir: "https://phoenix.hexdocs.pm/security.html",
  lua: "https://www.lua.org/manual/5.4/manual.html",
  powershell: "https://learn.microsoft.com/en-us/powershell/scripting/security/preventing-script-injection",
};

function toRule(spec: Spec, languages: string[], reference?: string): Rule {
  const [id, title, cwe, category, pattern, recommendation] = spec;
  return {
    id, title, languages, pattern, recommendation, category, cwe: `CWE-${cwe}`,
    description: `${title}. Проверьте доверие к данным и условия использования; сигнатура не доказывает эксплуатацию.`,
    severity: category === "secrets" || [78, 89, 95].includes(cwe) ? "critical" : "high",
    confidence: "medium",
    owasp: category === "secrets" ? "A07:2021" : ["crypto", "transport"].includes(category) ? "A02:2021" : category === "deserialization" ? "A08:2021" : "A03:2021",
    references: [`https://cwe.mitre.org/data/definitions/${cwe}.html`, ...(reference ? [reference] : [])],
    ...(id === "NEWSEC001" ? { exclude: /(?:example|sample|placeholder|changeme|your[_-]|\$\{|\*{3,})/i } : {}),
  };
}

/** Append-only pack: historical catalog definitions and order remain intact. */
export function createCoverageRules(): Rule[] {
  return [
    ...Object.entries(groups).flatMap(([language, specs]) => specs.map((spec) => toRule(spec, [language], references[language]))),
    ...shared.map((spec) => toRule(spec, [...newLanguages])),
  ];
}
