import { createExtendedRules } from "./sast-rules.ts";
import { createExpansionRules } from "./sast-rules-expansion.ts";
import { createAdditionalRules } from "./sast-rules-additional.ts";
import { createAdvancedRules } from "./sast-rules-advanced.ts";
import { createHttpRules, getHttpRuleApi } from "./sast-rules-http.ts";
import { createFrameworkRules, getFrameworkRuleApi } from "./sast-rules-framework.ts";
import { createComposedRules, getComposedRuleApi } from "./sast-rules-composed.ts";
import { createExpressionRules, getExpressionRuleApi } from "./sast-rules-expressions.ts";
import { createCoverageRules } from "./sast-rules-coverage.ts";
import { languageByExtension } from "./sast-languages.ts";
export { languageLabels, supportedLanguageCount } from "./sast-languages.ts";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Finding = {
  id: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  owasp: string;
  confidence: "high" | "medium";
  line: number;
  column: number;
  snippet: string;
  recommendation: string;
  references: string[];
  category: string;
  context?: string;
  filename?: string;
};

export type ScanSummary = {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  score: number;
};

export type ScanResult = {
  language: string;
  scannedLines: number;
  durationMs: number;
  summary: ScanSummary;
  findings: Finding[];
  filesScanned?: number;
};

export type Rule = {
  id: string;
  languages: string[];
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  owasp: string;
  confidence: "high" | "medium";
  pattern: RegExp;
  recommendation: string;
  references: string[];
  exclude?: RegExp;
  category?: string;
  scope?: "line" | "file";
};

const ALL = [
  "javascript", "typescript", "python", "java", "php", "go", "csharp", "ruby",
  "kotlin", "rust", "swift", "scala", "shell", "config", "unknown",
];

const rules: Rule[] = [
  {
    id: "SEC001",
    languages: ALL,
    title: "Секрет в исходном коде",
    description: "Обнаружено значение, похожее на пароль, токен или секретный ключ. Секреты в репозитории могут попасть в историю версий и журналы сборки.",
    severity: "critical",
    cwe: "CWE-798",
    owasp: "A07:2021",
    confidence: "high",
    pattern: /(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*["'`](?!\s|\$\{|process\.|os\.|env\.|getenv)([^"'`]{6,})["'`]/i,
    exclude: /(?:example|sample|placeholder|changeme|your[_-]|<.*>|\*{3,})/i,
    recommendation: "Удалите секрет из кода, отзовите его и загружайте новое значение из защищённого хранилища или переменной окружения.",
    references: ["https://cwe.mitre.org/data/definitions/798.html"],
  },
  {
    id: "SEC002",
    languages: ALL,
    title: "Приватный ключ в файле",
    description: "В коде найден заголовок приватного криптографического ключа.",
    severity: "critical",
    cwe: "CWE-321",
    owasp: "A02:2021",
    confidence: "high",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i,
    recommendation: "Немедленно удалите и перевыпустите ключ. Храните ключевой материал вне репозитория с минимальными правами доступа.",
    references: ["https://cwe.mitre.org/data/definitions/321.html"],
  },
  {
    id: "JS001",
    languages: ["javascript", "typescript"],
    title: "Выполнение динамического кода",
    description: "eval() выполняет строку как код и часто превращает контролируемый пользователем ввод в удалённое выполнение кода.",
    severity: "critical",
    cwe: "CWE-95",
    owasp: "A03:2021",
    confidence: "high",
    pattern: /\beval\s*\(/,
    recommendation: "Замените eval() безопасным парсером или явным сопоставлением разрешённых операций.",
    references: ["https://cwe.mitre.org/data/definitions/95.html"],
  },
  {
    id: "JS002",
    languages: ["javascript", "typescript"],
    title: "Командная инъекция",
    description: "Запуск команды оболочки с динамически собранным аргументом может позволить выполнить произвольную системную команду.",
    severity: "critical",
    cwe: "CWE-78",
    owasp: "A03:2021",
    confidence: "high",
    pattern: /(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[^,]*(?:\+|\$\{))/,
    recommendation: "Используйте execFile/spawn без shell, передавайте аргументы массивом и проверяйте их по allowlist.",
    references: ["https://cwe.mitre.org/data/definitions/78.html"],
  },
  {
    id: "JS003",
    languages: ["javascript", "typescript"],
    title: "Потенциальный DOM XSS",
    description: "Запись динамического HTML в DOM может исполнить внедрённый JavaScript.",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021",
    confidence: "medium",
    pattern: /(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(/,
    recommendation: "Используйте textContent или безопасные DOM API. Если HTML необходим — очищайте его проверенным sanitizer с allowlist.",
    references: ["https://cwe.mitre.org/data/definitions/79.html"],
  },
  {
    id: "JS004",
    languages: ["javascript", "typescript"],
    title: "Небезопасная десериализация",
    description: "Десериализация недоверенных данных библиотекой node-serialize может привести к выполнению кода.",
    severity: "critical",
    cwe: "CWE-502",
    owasp: "A08:2021",
    confidence: "high",
    pattern: /(?:node-serialize|serialize-javascript).*|\.unserialize\s*\(/,
    recommendation: "Откажитесь от исполняемой десериализации. Используйте JSON и проверяйте данные по строгой схеме.",
    references: ["https://cwe.mitre.org/data/definitions/502.html"],
  },
  {
    id: "JS005",
    languages: ["javascript", "typescript"],
    title: "Слабый генератор случайных значений",
    description: "Некриптографический генератор непригоден для токенов, идентификаторов сессий и других security-sensitive значений.",
    severity: "medium",
    cwe: "CWE-338",
    owasp: "A02:2021",
    confidence: "medium",
    pattern: /\bMath\.random\s*\(/,
    recommendation: "Для секретных значений используйте crypto.randomBytes() или crypto.getRandomValues().",
    references: ["https://cwe.mitre.org/data/definitions/338.html"],
  },
  {
    id: "PY001",
    languages: ["python"],
    title: "Выполнение динамического кода",
    description: "eval/exec с недоверенным вводом может привести к выполнению произвольного Python-кода.",
    severity: "critical",
    cwe: "CWE-95",
    owasp: "A03:2021",
    confidence: "high",
    pattern: /\b(?:eval|exec)\s*\(/,
    recommendation: "Используйте ast.literal_eval для литералов или явный разбор разрешённого формата.",
    references: ["https://cwe.mitre.org/data/definitions/95.html"],
  },
  {
    id: "PY002",
    languages: ["python"],
    title: "Небезопасная десериализация YAML",
    description: "yaml.load без SafeLoader способен создавать произвольные Python-объекты.",
    severity: "high",
    cwe: "CWE-502",
    owasp: "A08:2021",
    confidence: "high",
    pattern: /yaml\.load\s*\(/,
    exclude: /SafeLoader|safe_load/,
    recommendation: "Используйте yaml.safe_load() и дополнительно проверяйте структуру результата.",
    references: ["https://cwe.mitre.org/data/definitions/502.html"],
  },
  {
    id: "PY003",
    languages: ["python"],
    title: "Небезопасный запуск shell",
    description: "shell=True расширяет поверхность командной инъекции, особенно с динамическими аргументами.",
    severity: "high",
    cwe: "CWE-78",
    owasp: "A03:2021",
    confidence: "high",
    pattern: /(?:subprocess\.|os\.system\s*\().*shell\s*=\s*True|os\.system\s*\(/,
    recommendation: "Отключите shell, передавайте команду и аргументы массивом, валидируйте значения по allowlist.",
    references: ["https://cwe.mitre.org/data/definitions/78.html"],
  },
  {
    id: "PY004",
    languages: ["python"],
    title: "Отключена проверка TLS",
    description: "verify=False отключает проверку сертификата и позволяет атакующему подменить защищённое соединение.",
    severity: "high",
    cwe: "CWE-295",
    owasp: "A02:2021",
    confidence: "high",
    pattern: /verify\s*=\s*False/,
    recommendation: "Включите проверку сертификата и настройте доверенный CA bundle для частной инфраструктуры.",
    references: ["https://cwe.mitre.org/data/definitions/295.html"],
  },
  {
    id: "SQL001",
    languages: ["javascript", "typescript", "python", "java", "php", "go", "csharp", "ruby"],
    title: "Возможная SQL-инъекция",
    description: "SQL-запрос формируется конкатенацией или интерполяцией данных, что может изменить структуру запроса.",
    severity: "critical",
    cwe: "CWE-89",
    owasp: "A03:2021",
    confidence: "medium",
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE)\b.{0,120}(?:\+\s*[a-z_$]|\$\{|%s|\.format\s*\(|f["'])/i,
    recommendation: "Используйте параметризованный запрос или prepared statement. Не собирайте SQL строковой конкатенацией.",
    references: ["https://cwe.mitre.org/data/definitions/89.html"],
  },
  {
    id: "JAVA001",
    languages: ["java"],
    title: "Командная инъекция",
    description: "Runtime.exec или ProcessBuilder с динамическим аргументом может выполнить команды атакующего.",
    severity: "critical",
    cwe: "CWE-78",
    owasp: "A03:2021",
    confidence: "medium",
    pattern: /(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\([^)]*\+/,
    recommendation: "Не вызывайте shell; передавайте фиксированную программу и отдельно валидированные аргументы.",
    references: ["https://cwe.mitre.org/data/definitions/78.html"],
  },
  {
    id: "PHP001",
    languages: ["php"],
    title: "Опасное выполнение команды",
    description: "Функция выполнения системных команд вызывается с потенциально динамическими данными.",
    severity: "critical",
    cwe: "CWE-78",
    owasp: "A03:2021",
    confidence: "medium",
    pattern: /\b(?:system|exec|shell_exec|passthru|popen)\s*\(/i,
    recommendation: "Исключите системный вызов либо примените строгий allowlist и escapeshellarg для каждого аргумента.",
    references: ["https://cwe.mitre.org/data/definitions/78.html"],
  },
  {
    id: "PATH001",
    languages: ["javascript", "typescript", "python", "java", "php", "go", "csharp", "ruby"],
    title: "Возможный path traversal",
    description: "Путь к файлу строится из данных запроса без видимой нормализации и проверки базовой директории.",
    severity: "high",
    cwe: "CWE-22",
    owasp: "A01:2021",
    confidence: "medium",
    pattern: /\b(?:readFile|readFileSync|sendFile|open|FileInputStream|file_get_contents)\s*\([^)]*(?:\breq\.|\brequest\.|\bparams\b|\bquery\b|\bargv\b|\$_?(?:GET|POST)\b)/i,
    recommendation: "Нормализуйте путь, разрешайте только ожидаемые имена и проверяйте, что результат остаётся внутри фиксированной базовой директории.",
    references: ["https://cwe.mitre.org/data/definitions/22.html"],
  },
  {
    id: "CRYPTO001",
    languages: ALL,
    title: "Слабый криптографический алгоритм",
    description: "MD5 или SHA-1 не следует использовать для паролей, подписей и других защитных механизмов.",
    severity: "medium",
    cwe: "CWE-327",
    owasp: "A02:2021",
    confidence: "medium",
    pattern: /(?:createHash\s*\(\s*["'](?:md5|sha1)|hashlib\.(?:md5|sha1)|MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)|md5\s*\()/i,
    recommendation: "Для паролей используйте Argon2id/scrypt/bcrypt, для целостности — SHA-256 или более современный алгоритм.",
    references: ["https://cwe.mitre.org/data/definitions/327.html"],
  },
  {
    id: "LOG001",
    languages: ALL,
    title: "Чувствительные данные в журнале",
    description: "В журнал может попадать пароль, токен или иной секрет.",
    severity: "medium",
    cwe: "CWE-532",
    owasp: "A09:2021",
    confidence: "medium",
    pattern: /(?:console\.log|logger\.(?:info|debug|warn)|print\s*\().*(?:password|passwd|token|secret|authorization)/i,
    recommendation: "Не журналируйте секреты. Маскируйте чувствительные поля централизованным фильтром логгера.",
    references: ["https://cwe.mitre.org/data/definitions/532.html"],
  },
  {
    id: "CORS001",
    languages: ALL,
    title: "Избыточно разрешающий CORS",
    description: "Wildcard origin разрешает читать ответы любому сайту и опасен для API с чувствительными данными.",
    severity: "medium",
    cwe: "CWE-942",
    owasp: "A05:2021",
    confidence: "high",
    pattern: /(?:Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*|origin\s*:\s*["']\*)/i,
    recommendation: "Укажите точный allowlist доверенных origins и не сочетайте wildcard с credentialed-запросами.",
    references: ["https://cwe.mitre.org/data/definitions/942.html"],
  },
  {
    id: "DEBUG001",
    languages: ["python", "php"],
    title: "Режим отладки включён",
    description: "Production-сервер в debug-режиме может раскрыть конфигурацию, исходный код и интерактивную консоль.",
    severity: "high",
    cwe: "CWE-489",
    owasp: "A05:2021",
    confidence: "high",
    pattern: /(?:debug\s*=\s*True|display_errors\s*[,=]\s*(?:1|On|true))/i,
    recommendation: "Отключите debug в production и управляйте режимом через проверенную конфигурацию окружения.",
    references: ["https://cwe.mitre.org/data/definitions/489.html"],
  },
];

function addRule(
  id: string,
  languages: string[],
  title: string,
  description: string,
  severity: Severity,
  cwe: string,
  pattern: RegExp,
  recommendation: string,
  options: Partial<Pick<Rule, "confidence" | "exclude" | "category" | "scope" | "owasp">> = {},
) {
  rules.push({
    id, languages, title, description, severity, cwe, pattern, recommendation,
    owasp: options.owasp ?? "A03:2021",
    confidence: options.confidence ?? "high",
    references: [`https://cwe.mitre.org/data/definitions/${cwe.replace("CWE-", "")}.html`],
    exclude: options.exclude,
    category: options.category,
    scope: options.scope,
  });
}

addRule("SEC003", ALL, "Ключ доступа AWS", "В исходном коде найден идентификатор ключа AWS.", "critical", "CWE-798",
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/, "Отзовите ключ в IAM, проверьте CloudTrail и храните новый ключ в secret manager.", { category: "secrets" });
addRule("SEC004", ALL, "Токен GitHub", "Найден токен доступа GitHub с узнаваемым префиксом.", "critical", "CWE-798",
  /\b(?:gh[opusr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255})\b/, "Немедленно отзовите токен, проверьте журнал аудита и используйте GitHub Actions secrets.", { category: "secrets" });
addRule("SEC005", ALL, "Токен Slack", "Найден секрет Slack с узнаваемым форматом.", "critical", "CWE-798",
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, "Отзовите токен в Slack и перенесите секрет в защищённое хранилище.", { category: "secrets" });
addRule("SEC006", ALL, "Приватный ключ или seed", "Найдено значение, похожее на приватный ключ, seed или mnemonic.", "critical", "CWE-321",
  /(?:PRIVATE[_-]?KEY|MNEMONIC|SEED[_-]?PHRASE)\s*[:=]\s*["'][^"']{16,}["']/i, "Считайте ключ скомпрометированным, перевыпустите его и исключите из истории Git.", { category: "secrets" });
addRule("SEC007", ALL, "Учётные данные в URL базы данных", "URI подключения содержит имя пользователя и пароль.", "critical", "CWE-798",
  /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s:"']+:[^\s@"']+@/i, "Передавайте URI через secret manager или переменную окружения и смените пароль.", { category: "secrets" });
addRule("SEC008", ALL, "Жёстко заданный Bearer-токен", "Заголовок авторизации содержит статический токен.", "critical", "CWE-798",
  /(?:Authorization|authorization)\s*[:=]\s*["']Bearer\s+[A-Za-z0-9._~+\/-]{12,}["']/i, "Отзовите токен и загружайте его из защищённой конфигурации.", { category: "secrets" });
addRule("SEC009", ALL, "JWT в исходном коде", "Найден сериализованный JWT, который может предоставлять доступ.", "high", "CWE-798",
  /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/, "Удалите и отзовите токен; не храните сессионные артефакты в репозитории.", { confidence: "medium", category: "secrets" });

addRule("JS006", ["javascript", "typescript"], "Конструктор динамической функции", "new Function компилирует строку как JavaScript и допускает инъекцию кода.", "critical", "CWE-95",
  /\bnew\s+Function\s*\(/, "Замените динамическое выполнение явным диспетчером разрешённых операций.", { category: "injection" });
addRule("JS007", ["javascript", "typescript"], "Выполнение кода через VM", "VM API выполняет динамически сформированный JavaScript.", "critical", "CWE-95",
  /\bvm\.(?:runInNewContext|runInContext|runInThisContext|compileFunction)\s*\(/, "Не используйте VM как границу безопасности; изолируйте недоверенный код вне процесса.", { category: "injection" });
addRule("JS008", ["javascript", "typescript"], "React XSS sink", "dangerouslySetInnerHTML может вставить в страницу непроверенный HTML.", "high", "CWE-79",
  /dangerouslySetInnerHTML\s*=|__html\s*:/, "Удалите HTML sink либо очищайте данные проверенным sanitizer с allowlist.", { confidence: "medium", category: "xss" });
addRule("JS009", ["javascript", "typescript"], "Отключена проверка TLS", "rejectUnauthorized=false принимает недоверенные сертификаты.", "high", "CWE-295",
  /rejectUnauthorized\s*:\s*false/, "Включите проверку сертификата и настройте доверенный CA.", { category: "transport" });
addRule("JS010", ["javascript", "typescript"], "Небезопасная проверка JWT", "Проверка подписи JWT отключена или разрешён алгоритм none.", "critical", "CWE-347",
  /(?:algorithms?\s*:\s*\[[^\]]*["']none["']|ignoreExpiration\s*:\s*true|jwt\.decode\s*\()/i, "Используйте jwt.verify, фиксированный allowlist алгоритмов, issuer и audience.", { category: "authentication" });
addRule("JS011", ["javascript", "typescript"], "SSRF через сетевой запрос", "URL сетевого запроса берётся непосредственно из HTTP-запроса.", "high", "CWE-918",
  /(?:fetch|axios\.(?:get|post|request)|https?\.(?:get|request))\s*\([^\n)]*(?:req\.|request\.|params|query|body)/i, "Разрешайте только известные схемы, хосты и порты; блокируйте private/link-local адреса.", { confidence: "medium", category: "ssrf" });
addRule("JS012", ["javascript", "typescript"], "Небезопасный redirect", "Цель перенаправления контролируется параметрами запроса.", "medium", "CWE-601",
  /(?:res\.|response\.)redirect\s*\([^\n)]*(?:req\.|request\.|params|query|body)/i, "Используйте относительные пути или allowlist доверенных назначений.", { confidence: "medium", category: "validation" });
addRule("JS013", ["javascript", "typescript"], "Prototype pollution", "Контролируемый ключ записывается в объект и может изменить его прототип.", "high", "CWE-1321",
  /\w+\s*\[\s*(?:req\.|request\.|params|query|body)[^\]]*\]\s*=/i, "Запрещайте __proto__, constructor и prototype; используйте Map или объекты без прототипа.", { confidence: "medium", category: "injection" });
addRule("JS014", ["javascript", "typescript"], "Слабые параметры cookie", "Cookie явно разрешает передачу без HttpOnly, Secure или с SameSite=None без Secure.", "medium", "CWE-614",
  /(?:httpOnly\s*:\s*false|secure\s*:\s*false|sameSite\s*:\s*["']none["'][\s\S]{0,100}secure\s*:\s*false)/i, "Для сессионных cookie включите HttpOnly, Secure и подходящий SameSite.", { category: "session", scope: "file" });
addRule("JS015", ["javascript", "typescript"], "NoSQL-инъекция", "Объект фильтра MongoDB строится непосредственно из данных запроса.", "high", "CWE-943",
  /\.(?:find|findOne|findOneAndUpdate|deleteMany|updateMany)\s*\(\s*(?:req\.(?:body|query)|request\.)/i, "Валидируйте схему и типы, удаляйте операторы с $ и собирайте фильтр из разрешённых полей.", { confidence: "medium", category: "injection" });

addRule("PY005", ["python"], "Небезопасная десериализация Pickle", "pickle может выполнить код при загрузке недоверенных данных.", "critical", "CWE-502",
  /\b(?:pickle|cPickle|dill)\.loads?\s*\(/, "Используйте JSON со строгой схемой; никогда не загружайте pickle из недоверенного источника.", { category: "deserialization" });
addRule("PY006", ["python"], "Шаблонная инъекция Flask/Jinja", "Строка шаблона формируется во время выполнения.", "high", "CWE-1336",
  /\brender_template_string\s*\(/, "Используйте статические файлы шаблонов и передавайте данные только как параметры.", { confidence: "medium", category: "injection" });
addRule("PY007", ["python"], "Слабая генерация security-токена", "Модуль random не является криптографически стойким.", "medium", "CWE-338",
  /\brandom\.(?:random|randint|randrange|choice|choices|getrandbits)\s*\(/, "Для токенов и ключей используйте secrets или os.urandom.", { confidence: "medium", category: "crypto" });
addRule("PY008", ["python"], "SSRF через requests", "URL запроса получен напрямую из web-параметра.", "high", "CWE-918",
  /requests\.(?:get|post|put|delete|request)\s*\([^\n)]*(?:request\.|args\.|form\.|json)/i, "Проверяйте схему, DNS/IP после резолвинга и allowlist назначений.", { confidence: "medium", category: "ssrf" });
addRule("PY009", ["python"], "Небезопасный XML-парсер", "Стандартный XML-парсер используется для потенциально недоверенных данных.", "high", "CWE-611",
  /(?:xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.sax)\.(?:parse|fromstring|parseString)\s*\(/, "Используйте defusedxml и запретите DTD/внешние сущности.", { confidence: "medium", category: "xxe" });
addRule("PY010", ["python"], "Слабое хеширование пароля", "Пароль хешируется быстрым общим алгоритмом.", "high", "CWE-916",
  /(?:md5|sha1|sha256)\s*\([^\n]*(?:password|passwd)|hashlib\.(?:md5|sha1|sha256)\s*\([^\n]*(?:password|passwd)/i, "Используйте Argon2id, scrypt или bcrypt с уникальной солью.", { confidence: "medium", category: "crypto" });

addRule("PY011", ["python"], "Небезопасный временный файл", "tempfile.mktemp создаёт имя отдельно от открытия файла и допускает race condition.", "medium", "CWE-377",
  /\btempfile\.mktemp\s*\(/, "Используйте NamedTemporaryFile или mkstemp и сохраняйте открытый файловый дескриптор.", { category: "filesystem" });
addRule("PY012", ["python"], "Небезопасная распаковка архива", "extractall может записать файл за пределами каталога назначения через traversal-путь.", "high", "CWE-22",
  /\b(?:tarfile|zipfile)[^\n]*\.extractall\s*\(/, "Проверяйте каждый нормализованный путь участника архива и отклоняйте выход за каталог назначения.", { confidence: "medium", category: "validation" });
addRule("PY013", ["python"], "Обход HTML-экранирования", "mark_safe или Markup помечает строку доверенным HTML.", "high", "CWE-79",
  /\b(?:mark_safe|Markup)\s*\(/, "Не помечайте пользовательские данные безопасными; используйте контекстное экранирование.", { confidence: "medium", category: "xss" });
addRule("PY014", ["python"], "JWT без проверки подписи", "Проверка подписи JWT явно отключена или разрешён алгоритм none.", "critical", "CWE-347",
  /jwt\.decode\s*\([^\n]*(?:verify_signature["']?\s*:\s*False|verify\s*=\s*False|algorithms\s*=\s*\[[^\]]*["']none["'])/i, "Всегда проверяйте подпись, issuer, audience и используйте фиксированный allowlist алгоритмов.", { category: "authentication" });
addRule("PY015", ["python"], "Слабая криптографическая хеш-функция", "MD5 или SHA-1 не обеспечивают стойкость к коллизиям.", "medium", "CWE-327",
  /\bhashlib\.(?:md5|sha1)\s*\(/i, "Используйте SHA-256/512 для целостности или Argon2id/scrypt/bcrypt для паролей.", { category: "crypto" });
addRule("PY016", ["python"], "Чувствительные данные в журнале", "В журнал может попасть пароль, токен или секрет.", "medium", "CWE-532",
  /\b(?:logging|logger)\.(?:debug|info|warning|error|critical)\s*\([^\n]*(?:password|passwd|token|secret)/i, "Не журналируйте секреты; маскируйте чувствительные поля до передачи логгеру.", { confidence: "medium", category: "logging" });

addRule("JAVA002", ["java", "kotlin"], "Небезопасная Java-десериализация", "ObjectInputStream может создать опасную цепочку объектов.", "critical", "CWE-502",
  /\b(?:(?:new\s+)?ObjectInputStream\s*\(|\.readObject\s*\()/, "Откажитесь от native serialization или применяйте строгий JEP 290 allowlist.", { category: "deserialization" });
addRule("JAVA003", ["java", "kotlin"], "XXE в XML parser", "XML factory создаётся без видимого запрета DTD и внешних сущностей.", "high", "CWE-611",
  /(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\(/, "Запретите DTD и внешние сущности; включите secure processing.", { confidence: "medium", category: "xxe" });
addRule("JAVA004", ["java", "kotlin"], "Отключена проверка hostname", "HostnameVerifier безусловно принимает имя узла.", "high", "CWE-297",
  /HostnameVerifier[\s\S]{0,160}(?:return\s+true|->\s*true)/, "Используйте стандартную проверку hostname и доверенное хранилище сертификатов.", { category: "transport", scope: "file" });

addRule("JAVA005", ["java", "kotlin"], "Выполнение динамического скрипта", "ScriptEngine.eval выполняет динамически сформированный код.", "critical", "CWE-95",
  /\b(?:ScriptEngine|scriptEngine|engine)\.eval\s*\(/, "Не выполняйте недоверенный код; используйте явное сопоставление разрешённых операций.", { confidence: "medium", category: "injection" });
addRule("JAVA006", ["java", "kotlin"], "Слабый генератор случайных значений", "java.util.Random и Math.random непригодны для токенов и ключей.", "medium", "CWE-338",
  /\b(?:new\s+(?:java\.util\.)?Random\s*\(|Math\.random\s*\()/, "Для security-sensitive значений используйте SecureRandom.", { confidence: "medium", category: "crypto" });
addRule("JAVA007", ["java", "kotlin"], "TrustManager принимает любой сертификат", "Пустая проверка checkServerTrusted отключает аутентификацию TLS-сервера.", "high", "CWE-295",
  /checkServerTrusted\s*\([^)]*\)\s*\{\s*\}/, "Используйте системный TrustManager или выполняйте полную проверку цепочки сертификатов.", { category: "transport", scope: "file" });
addRule("JAVA008", ["java", "kotlin"], "SQL-инъекция через Statement", "SQL-команда для Statement строится конкатенацией.", "critical", "CWE-89",
  /\b(?:execute|executeQuery|executeUpdate)\s*\([^\n)]*(?:\+|String\.format\s*\()/, "Используйте PreparedStatement и bind-параметры.", { confidence: "medium", category: "injection" });
addRule("JAVA009", ["java", "kotlin"], "Path traversal из HTTP-параметра", "Путь к файлу напрямую зависит от параметра HTTP-запроса.", "high", "CWE-22",
  /\b(?:new\s+File|Paths\.get|Path\.of)\s*\([^\n)]*(?:getParameter|request\.|params\[)/i, "Нормализуйте путь и убедитесь, что он остаётся внутри фиксированного базового каталога.", { confidence: "medium", category: "validation" });
addRule("JAVA010", ["java", "kotlin"], "Слабая криптографическая хеш-функция", "MessageDigest использует MD5 или SHA-1.", "medium", "CWE-327",
  /MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']\s*\)/i, "Используйте SHA-256/512 для целостности или специализированный password hashing.", { category: "crypto" });

addRule("PHP002", ["php"], "Небезопасная PHP-десериализация", "unserialize над недоверенными данными может активировать magic methods.", "critical", "CWE-502",
  /\bunserialize\s*\(/i, "Используйте JSON; если невозможно — allowed_classes=false и строгая проверка источника.", { category: "deserialization" });
addRule("PHP003", ["php"], "Локальное/удалённое включение файла", "Имя подключаемого файла зависит от пользовательского ввода.", "critical", "CWE-98",
  /\b(?:include|include_once|require|require_once)\s*\(?[^;\n]*(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)/i, "Выбирайте файл только по ключу из фиксированного allowlist.", { category: "injection" });
addRule("PHP004", ["php"], "SQL-инъекция через superglobal", "SQL API получает запрос с непосредственным пользовательским вводом.", "critical", "CWE-89",
  /(?:mysqli_query|->query|mysql_query)\s*\([^;\n]*(?:\$_GET|\$_POST|\$_REQUEST)/i, "Используйте prepared statements с bind-параметрами.", { category: "injection" });

addRule("GO001", ["go"], "Команда через shell", "Запуск sh -c или cmd /c повышает риск командной инъекции.", "high", "CWE-78",
  /exec\.Command\s*\(\s*["'](?:sh|bash|cmd)["']\s*,\s*["'](?:-c|\/c)["']/i, "Запускайте фиксированный бинарник и передавайте проверенные аргументы отдельно.", { category: "injection" });
addRule("GO002", ["go"], "Отключена проверка TLS", "InsecureSkipVerify отключает аутентификацию сервера.", "high", "CWE-295",
  /InsecureSkipVerify\s*:\s*true/, "Удалите InsecureSkipVerify и настройте RootCAs/ServerName.", { category: "transport" });
addRule("GO003", ["go"], "Обход HTML-экранирования", "template.HTML помечает строку доверенным HTML.", "high", "CWE-79",
  /template\.(?:HTML|HTMLAttr|JS|URL)\s*\(/, "Не приводите недоверенные строки к trusted template-типам.", { confidence: "medium", category: "xss" });

addRule("GO004", ["go"], "Слабая криптографическая хеш-функция", "crypto/md5 или crypto/sha1 не обеспечивают стойкость к коллизиям.", "medium", "CWE-327",
  /\b(?:md5|sha1)\.(?:New|Sum)\s*\(/, "Используйте crypto/sha256 или crypto/sha512; для паролей применяйте Argon2id/scrypt/bcrypt.", { category: "crypto" });
addRule("GO005", ["go"], "HTTP-сервер без TLS", "ListenAndServe запускает незашифрованный HTTP-сервер.", "medium", "CWE-319",
  /\bhttp\.ListenAndServe\s*\(/, "Используйте ListenAndServeTLS либо завершайте TLS на доверенном reverse proxy.", { confidence: "medium", category: "transport" });
addRule("GO006", ["go"], "Небезопасные права создаваемого файла", "Файл создаётся с правами 0777 или 0666.", "high", "CWE-732",
  /\bos\.(?:WriteFile|OpenFile|Mkdir|MkdirAll)\s*\([^\n]*(?:0?777|0?666)\b/, "Назначьте минимально необходимые права, обычно 0600 для файлов и 0700/0750 для каталогов.", { category: "configuration" });
addRule("GO007", ["go"], "JWT разобран без проверки подписи", "ParseUnverified возвращает claims без криптографической проверки.", "critical", "CWE-347",
  /\bParseUnverified\s*\(/, "Используйте ParseWithClaims/Parse и проверяйте метод подписи, issuer, audience и срок действия.", { category: "authentication" });
addRule("GO008", ["go"], "Path traversal из HTTP-параметра", "Путь к файлу строится напрямую из параметра HTTP-запроса.", "high", "CWE-22",
  /filepath\.Join\s*\([^\n]*(?:r\.URL\.Query|FormValue|PathValue)\s*\(/, "Очистите и нормализуйте значение, затем проверьте принадлежность фиксированному базовому каталогу.", { confidence: "medium", category: "validation" });
addRule("GO009", ["go"], "SQL-инъекция через fmt", "SQL-команда формируется через fmt.Sprintf перед выполнением.", "critical", "CWE-89",
  /\b(?:Query|QueryRow|Exec)(?:Context)?\s*\([^\n]*fmt\.Sprintf\s*\(/, "Передавайте значения отдельными аргументами параметризованного запроса.", { confidence: "medium", category: "injection" });

addRule("CS001", ["csharp"], "Небезопасная .NET-десериализация", "BinaryFormatter или NetDataContractSerializer допускает выполнение кода.", "critical", "CWE-502",
  /\b(?:BinaryFormatter|NetDataContractSerializer|LosFormatter|SoapFormatter)\b/, "Удалите опасный formatter и используйте System.Text.Json со строгими DTO.", { category: "deserialization" });
addRule("CS002", ["csharp"], "Отключена проверка сертификата", "Callback безусловно принимает любой TLS-сертификат.", "high", "CWE-295",
  /ServerCertificateValidationCallback[\s\S]{0,160}(?:=>\s*true|return\s+true)/, "Удалите callback или выполняйте полноценную проверку цепочки и hostname.", { category: "transport", scope: "file" });
addRule("CS003", ["csharp"], "Командная инъекция .NET", "Process.Start получает динамически собранную команду.", "critical", "CWE-78",
  /Process\.Start\s*\([^\n)]*(?:\+|\$")/, "Фиксируйте FileName, используйте ArgumentList и allowlist значений.", { confidence: "medium", category: "injection" });

addRule("RB001", ["ruby"], "Небезопасная Ruby-десериализация", "Marshal.load или YAML.load может создавать произвольные объекты.", "critical", "CWE-502",
  /\b(?:Marshal\.load|YAML\.(?:load|unsafe_load))\s*\(/, "Используйте JSON или YAML.safe_load с разрешёнными классами.", { category: "deserialization" });
addRule("RB002", ["ruby"], "Командная инъекция Ruby", "Shell-команда содержит интерполяцию или пользовательский параметр.", "critical", "CWE-78",
  /(?:system|exec|spawn)\s*\([^\n]*(?:#\{|params\[)|`[^`]*(?:#\{|params\[)/, "Используйте массив аргументов без shell и проверяйте значения по allowlist.", { confidence: "medium", category: "injection" });

addRule("CFG001", ALL, "Привилегированный контейнер", "Контейнер запускается в privileged-режиме.", "high", "CWE-250",
  /(?:privileged\s*:\s*true|--privileged\b)/i, "Удалите privileged, сбросьте capabilities и включите read-only root filesystem.", { category: "configuration" });
addRule("CFG002", ALL, "Публичный административный интерфейс", "Сервис разработки или администрирования привязан ко всем интерфейсам.", "medium", "CWE-668",
  /(?:listen|host|bind|address)\s*[:=]\s*["']?0\.0\.0\.0|--host\s+0\.0\.0\.0/i, "Ограничьте bind loopback/private-интерфейсом и защитите доступ аутентификацией.", { confidence: "medium", category: "configuration" });
addRule("CFG003", ALL, "Небезопасные права доступа", "Файлу назначаются права 0777 или эквивалентный chmod.", "high", "CWE-732",
  /(?:chmod\s+(?:-R\s+)?777\b|chmod\s*\([^\n,]+,\s*0?777\)|mode\s*:\s*0?777)/i, "Назначьте минимально необходимые права и отдельного владельца.", { category: "configuration" });
addRule("CRYPTO002", ALL, "Режим шифрования ECB", "ECB раскрывает структуру повторяющихся блоков данных.", "high", "CWE-327",
  /(?:AES|DES)[-_/]?(?:\d+[-_/]?)?ECB|MODE_ECB|\/ECB\//i, "Используйте AEAD: AES-GCM или ChaCha20-Poly1305 с уникальным nonce.", { category: "crypto" });
addRule("CRYPTO003", ALL, "Статический IV или nonce", "IV/nonce задан константой и может повторяться при шифровании.", "high", "CWE-329",
  /(?:iv|nonce|initializationVector)\s*[:=]\s*(?:["'][A-Za-z0-9+/=_-]{8,}["']|Buffer\.alloc\s*\([^)]*\))/i, "Генерируйте уникальный nonce криптографическим RNG для каждой операции.", { confidence: "medium", category: "crypto" });
addRule("AUTH001", ALL, "Сравнение секрета без constant-time", "Секрет или подпись сравнивается обычным оператором.", "medium", "CWE-208",
  /(?:password|token|signature|hmac|secret)\s*(?:===?|!==?)\s*[A-Za-z_$"']/i, "Для MAC, токенов и ключей используйте constant-time compare.", { confidence: "medium", category: "authentication" });

addRule("RS001", ["rust"], "Команда через системную оболочку", "Rust-приложение запускает shell с текстовой командой, что повышает риск командной инъекции.", "high", "CWE-78",
  /Command::new\s*\(\s*"(?:sh|bash)"\s*\)[\s\S]{0,240}\.arg\s*\(\s*"-c"\s*\)/, "Запускайте фиксированный бинарник напрямую и передавайте проверенные аргументы отдельными вызовами arg/args.", { category: "injection", scope: "file" });
addRule("RS002", ["rust"], "Отключена проверка TLS", "HTTP-клиент принимает недействительные TLS-сертификаты.", "high", "CWE-295",
  /danger_accept_invalid_(?:certs|hostnames)\s*\(\s*true\s*\)/, "Включите проверку сертификата и имени узла, при необходимости настройте доверенный корневой сертификат.", { category: "transport" });
addRule("RS003", ["rust"], "Небезопасная десериализация бинарных данных", "Десериализация bincode из недоверенного источника может вызвать отказ в обслуживании или неконтролируемое выделение памяти.", "medium", "CWE-502",
  /\bbincode::deserialize(?:_from)?\s*\(/, "Ограничьте размер входа, применяйте лимиты bincode и проверяйте структуру результата.", { confidence: "medium", category: "deserialization" });
addRule("RS004", ["rust"], "SQL-запрос через format!", "SQL-команда формируется строковой интерполяцией перед выполнением.", "critical", "CWE-89",
  /(?:query|execute|query_as)\s*\(\s*&?format!\s*\(/, "Используйте параметризованный запрос и bind-параметры вместо format!.", { confidence: "medium", category: "injection" });

addRule("SWIFT001", ["swift"], "Команда через shell", "Process запускает системную оболочку с командной строкой.", "high", "CWE-78",
  /executableURL\s*=\s*URL\s*\(\s*fileURLWithPath:\s*"\/(?:bin\/(?:sh|bash)|usr\/bin\/env)"\s*\)[\s\S]{0,320}(?:"-c"|"bash"|"sh")/, "Запускайте требуемый executable напрямую и передавайте проверенные аргументы массивом.", { confidence: "medium", category: "injection", scope: "file" });
addRule("SWIFT002", ["swift"], "Отключена проверка TLS", "Обработчик URLSession безусловно принимает серверный сертификат.", "high", "CWE-295",
  /useCredential\s*,\s*credential:\s*URLCredential\s*\(\s*trust:/, "Используйте performDefaultHandling или явно проверьте trust, hostname и цепочку сертификатов.", { confidence: "medium", category: "transport" });
addRule("SWIFT003", ["swift"], "Слабая криптографическая хеш-функция", "Приложение использует MD5 или SHA-1.", "medium", "CWE-327",
  /\b(?:Insecure\.)?(?:MD5|SHA1)\.(?:hash|init)\s*\(|CC_(?:MD5|SHA1)\s*\(/, "Используйте SHA-256/512 для целостности; для паролей применяйте специализированный password hashing.", { category: "crypto" });
addRule("SWIFT004", ["swift"], "Динамический JavaScript в WebView", "WKWebView выполняет динамически сформированную строку JavaScript.", "high", "CWE-95",
  /evaluateJavaScript\s*\([^\n)]*(?:\+|\\\(|interpolat)/, "Не собирайте JavaScript из недоверенных данных; используйте структурированный message handler и строгую проверку значений.", { confidence: "medium", category: "injection" });

addRule("SCALA001", ["scala"], "Командная инъекция Scala", "Shell-команда формируется интерполяцией перед запуском процесса.", "critical", "CWE-78",
  /s["'][^"'\n]*\$[^"'\n]*["']\s*\.!{1,2}\b|Process\s*\(\s*s["'][^"'\n]*\$/, "Передавайте executable и проверенные аргументы последовательностью без shell-интерпретации.", { confidence: "medium", category: "injection" });
addRule("SCALA002", ["scala"], "Небезопасная Java-десериализация", "ObjectInputStream может создать опасную цепочку объектов из недоверенных данных.", "critical", "CWE-502",
  /\b(?:new\s+)?ObjectInputStream\s*\(|\.readObject\s*\(/, "Откажитесь от Java serialization либо используйте строгий ObjectInputFilter allowlist.", { category: "deserialization" });
addRule("SCALA003", ["scala"], "SQL-запрос через интерполяцию", "SQL-команда строится из интерполированной строки.", "critical", "CWE-89",
  /(?:executeQuery|executeUpdate|execute|sql)\s*\(\s*s["'][^"'\n]*\$/, "Используйте prepared statement или типобезопасные bind-параметры.", { confidence: "medium", category: "injection" });

addRule("SH001", ["shell"], "Выполнение загруженного скрипта", "Данные из сети напрямую передаются интерпретатору команд.", "critical", "CWE-494",
  /\b(?:curl|wget)\b[^\n|]*(?:\||-O\s*-)[^\n]*\b(?:sh|bash|zsh)\b/, "Загрузите файл отдельно, проверьте подпись или хеш и только затем запускайте зафиксированную версию.", { category: "supply-chain" });
addRule("SH002", ["shell"], "eval с подстановкой переменной", "eval повторно интерпретирует содержимое переменной как shell-код.", "critical", "CWE-95",
  /\beval\s+["']?\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/, "Удалите eval; используйте массив аргументов, case или явное сопоставление разрешённых команд.", { category: "injection" });
addRule("SH003", ["shell"], "Небезопасное имя временного файла", "mktemp -u возвращает имя без атомарного создания файла и допускает race condition.", "medium", "CWE-377",
  /\bmktemp\s+(?:[^\n]*\s)?-u\b|\bmktemp\s+-u\b/, "Создавайте временный файл обычным mktemp и сохраняйте созданный путь с ограниченными правами.", { category: "filesystem" });
addRule("SH004", ["shell"], "Отключена проверка TLS", "curl или wget принимает недоверенный TLS-сертификат.", "high", "CWE-295",
  /\b(?:curl\s+[^\n]*(?:--insecure|-k)\b|wget\s+[^\n]*--no-check-certificate\b)/, "Удалите отключение проверки TLS и настройте доверенный CA bundle.", { category: "transport" });

addRule("CFG004", ["config"], "Контейнер запускается от root", "Dockerfile или конфигурация контейнера явно выбирает пользователя root.", "high", "CWE-250",
  /^(?:\s*USER\s+(?:root|0)\s*$|\s*runAsUser\s*:\s*0\s*$)/im, "Создайте непривилегированного пользователя и запускайте процесс с минимальными правами.", { category: "configuration", scope: "file" });
addRule("CFG005", ["config"], "Разрешено повышение привилегий", "Контейнер Kubernetes разрешает процессу получать дополнительные привилегии.", "high", "CWE-250",
  /allowPrivilegeEscalation\s*:\s*true/i, "Установите allowPrivilegeEscalation: false и удалите ненужные capabilities.", { category: "configuration" });
addRule("CFG006", ["config"], "Host namespace в Kubernetes", "Pod использует сетевое, процессное или IPC-пространство имён узла.", "high", "CWE-250",
  /\bhost(?:Network|PID|IPC)\s*:\s*true/i, "Изолируйте pod от namespace узла; включайте host namespace только для обоснованных системных компонентов.", { category: "configuration" });
addRule("CFG007", ["config"], "Публичный доступ из любой сети", "Сетевое правило разрешает входящий доступ со всех IPv4-адресов.", "high", "CWE-284",
  /(?:cidr_blocks?|sourceRanges?|ipBlock|CidrIp)\s*[:=][^\n]*(?:0\.0\.0\.0\/0)|-\s*0\.0\.0\.0\/0/i, "Ограничьте CIDR доверенными сетями и откройте только необходимые порты.", { confidence: "medium", category: "configuration" });
addRule("CFG008", ["config"], "Плавающий тег контейнерного образа", "Конфигурация использует изменяемый тег latest и не фиксирует содержимое образа.", "low", "CWE-1104",
  /\bimage\s*:\s*["']?[A-Za-z0-9._\/-]+:latest\b/i, "Закрепите образ по неизменяемому digest или конкретной проверенной версии.", { category: "supply-chain" });

addRule("JS020", ["javascript", "typescript"], "Отключена проверка TLS в Node.js", "HTTP-запросы принимают недействительные TLS-сертификаты.", "high", "CWE-295",
  /\brejectUnauthorized\s*:\s*false\b/, "Оставьте проверку сертификата включённой и настройте доверенный CA.", { category: "transport" });
addRule("PY020", ["python"], "Отключена проверка TLS в requests", "Клиент requests принимает недействительные TLS-сертификаты.", "high", "CWE-295",
  /\brequests\.(?:get|post|put|patch|delete|request)\s*\([^\n]*\bverify\s*=\s*False\b/, "Удалите verify=False и настройте доверенный CA.", { category: "transport" });
addRule("GO020", ["go"], "Отключена проверка TLS в Go", "TLS-клиент пропускает проверку сертификата и имени сервера.", "high", "CWE-295",
  /\bInsecureSkipVerify\s*:\s*true\b/, "Оставьте проверку TLS включённой и задайте RootCAs при необходимости.", { category: "transport" });
addRule("JAVA020", ["java"], "Небезопасный генератор случайных чисел", "java.util.Random используется для генерации токена или ключа.", "medium", "CWE-338",
  /\b(?:token|secret|key|nonce)\w*\s*=\s*(?:new\s+)?Random\s*\(/i, "Для секретов используйте java.security.SecureRandom.", { confidence: "medium", category: "crypto" });

addRule("JS021", ["javascript", "typescript"], "Запуск процесса через shell", "spawn или execFile явно включает оболочку; недоверенные аргументы могут стать командами.", "high", "CWE-78",
  /\b(?:spawn|spawnSync|execFile|execFileSync)\s*\([^;{}]{0,600}\{[^{}]{0,400}\bshell\s*:\s*true\b/, "Используйте shell: false, фиксированный executable и массив проверенных аргументов.", { confidence: "medium", category: "injection", scope: "file" });
addRule("PY021", ["python"], "Небезопасный SSL-контекст", "SSL-контекст создаётся без проверки сертификата либо проверка явно отключена.", "high", "CWE-295",
  /\bssl\._create_unverified_context\s*\(|\bverify_mode\s*=\s*ssl\.CERT_NONE\b/, "Используйте ssl.create_default_context(), CERT_REQUIRED и проверку имени сервера.", { category: "transport", scope: "file", owasp: "A02:2021" });
addRule("PY022", ["python"], "Отключено экранирование Jinja", "Jinja Environment явно отключает автоматическое экранирование; при выводе недоверенных данных в HTML возможен XSS.", "high", "CWE-79",
  /\b(?:jinja2\.)?Environment\s*\((?:[^();]|\([^()]*\)){0,400}?\bautoescape\s*=\s*False\b/, "Для HTML-шаблонов включите autoescape или select_autoescape(['html', 'htm', 'xml']).", { confidence: "medium", category: "xss", scope: "file" });
addRule("JAVA021", ["java", "kotlin"], "Небезопасная десериализация XMLDecoder", "XMLDecoder создаёт объекты и вызывает методы из XML; недоверенный документ может выполнить код.", "critical", "CWE-502",
  /\b(?:new\s+(?:java\.beans\.)?XMLDecoder|java\.beans\.XMLDecoder|XMLDecoder)\s*\(/, "Не передавайте недоверенные документы в XMLDecoder; используйте формат данных со строгой схемой без создания произвольных объектов.", { category: "deserialization", owasp: "A08:2021" });
addRule("CS004", ["csharp"], "Разрешены типы из JSON", "Newtonsoft.Json TypeNameHandling разрешает создавать типы, указанные в JSON; без строгого binder это опасно для недоверенного ввода.", "high", "CWE-502",
  /\bTypeNameHandling\s*=\s*(?:Newtonsoft\.Json\.)?TypeNameHandling\.(?:All|Auto|Objects|Arrays)\b/, "Установите TypeNameHandling.None; при необходимой полиморфности применяйте строгий allowlist в ISerializationBinder.", { confidence: "medium", category: "deserialization", scope: "file", owasp: "A08:2021" });
addRule("CS005", ["csharp"], "Разрешена обработка DTD", "XML-парсер разрешает DTD; внешние сущности и расширение сущностей требуют дополнительных ограничений.", "medium", "CWE-611",
  /\bDtdProcessing\s*=\s*(?:System\.Xml\.)?DtdProcessing\.Parse\b/, "Установите DtdProcessing.Prohibit и XmlResolver = null; ограничьте размер документа и расширение сущностей.", { confidence: "medium", category: "xxe", scope: "file", owasp: "A05:2021" });
addRule("PHP008", ["php"], "Отключена проверка TLS в cURL", "cURL явно отключает проверку сертификата или имени TLS-сервера.", "high", "CWE-295",
  /\bCURLOPT_SSL_VERIFY(?:PEER|HOST)\s*(?:,|=>)\s*(?:false|0)\b/i, "Включите CURLOPT_SSL_VERIFYPEER и установите CURLOPT_SSL_VERIFYHOST = 2; настройте доверенный CA.", { category: "transport", scope: "file", owasp: "A02:2021" });
addRule("CFG009", ["config"], "Docker socket доступен контейнеру", "Конфигурация монтирует сокет Docker daemon; доступ к нему может дать управление контейнерами и узлом даже при read-only mount.", "high", "CWE-250",
  /^\s*(?:-\s*["']?\/(?:var\/)?run\/docker\.sock\s*:|(?:source|path)\s*:\s*["']?\/(?:var\/)?run\/docker\.sock["']?\s*(?:#.*)?$)/m, "Уберите Docker socket из контейнера или используйте отдельный proxy с минимальным набором разрешённых API.", { category: "configuration", scope: "file", owasp: "A05:2021" });
addRule("CFG010", ["config"], "Опасные capabilities контейнера", "Контейнер получает SYS_ADMIN или полный набор capabilities, что значительно расширяет его привилегии.", "high", "CWE-250",
  /\b(?:cap_add|add)\s*:\s*(?:\[[^\]\n]*\b(?:SYS_ADMIN|ALL)\b[^\]\n]*\]|(?:\r?\n\s*-\s*["']?[A-Z_]+["']?\s*)*\r?\n\s*-\s*["']?(?:SYS_ADMIN|ALL)["']?\b)/, "Удалите SYS_ADMIN и ALL; сбросьте capabilities и добавьте только необходимые для конкретной операции.", { category: "configuration", scope: "file", owasp: "A05:2021" });
addRule("CFG011", ["config"], "Отключён seccomp контейнера", "Контейнер явно запускается без фильтра системных вызовов seccomp.", "high", "CWE-693",
  /\bseccomp\s*[:=]\s*unconfined\b|\bseccompProfile\s*:\s*(?:\{\s*type\s*:\s*["']?Unconfined["']?\s*\}|\s*\n\s*type\s*:\s*["']?Unconfined["']?\b)/i, "Используйте seccompProfile.type: RuntimeDefault или ограниченный профиль Localhost; удалите seccomp=unconfined.", { category: "configuration", scope: "file", owasp: "A05:2021" });

export function detectLanguage(filename: string, code: string): string {
  if (/^(?:dockerfile|compose\.ya?ml)$/i.test(filename.split(/[\\/]/).pop() ?? "")) return "config";
  const extension = filename.toLowerCase().split(".").pop() ?? "";
  const cppContent = /\bstd::|\b(?:namespace\s+\w+|template\s*<|using\s+namespace\s+std)\b|#\s*include\s*<iostream>/;
  // .h is shared by C and C++; an uppercase .C conventionally denotes C++.
  if (filename.endsWith(".C") || (extension === "h" && cppContent.test(code))) return "cpp";
  if (languageByExtension[extension]) return languageByExtension[extension];
  if (cppContent.test(code)) return "cpp";
  if (/^\s*#\s*include\s*[<"]|\bint\s+main\s*\(/m.test(code)) return "c";
  if (/\bimport\s+['"](?:dart:|package:flutter\/)|\bvoid\s+main\s*\(\s*\)\s*(?:async\s*)?\{/m.test(code)) return "dart";
  if (/^\s*defmodule\s+\w|\b(?:Code\.eval_(?:string|quoted)|Ecto\.Adapters\.SQL\.)/m.test(code)) return "elixir";
  if (/^\s*local\s+\w+\s*=|\b(?:os\.execute|io\.popen|ngx\.req\.)/m.test(code)) return "lua";
  if (/^\s*(?:param\s*\(|function\s+[A-Za-z][\w-]*\s*\{)|\b(?:Invoke-Expression|Invoke-WebRequest|ConvertTo-SecureString|Write-Host)\b/im.test(code)) return "powershell";
  if (/^\s*<\?php/m.test(code)) return "php";
  if (/^\s*(?:from\s+\w+\s+import|import\s+\w+|def\s+\w+\s*\()/m.test(code)) return "python";
  if (/\bpackage\s+main\b|\bfunc\s+main\s*\(/m.test(code)) return "go";
  if (/\bpublic\s+(?:static\s+)?class\s+\w+/m.test(code)) return "java";
  if (/\busing\s+System\b|\bnamespace\s+\w+/m.test(code)) return "csharp";
  if (/^\s*#!.*\b(?:ba|z|k)?sh\b/m.test(code)) return "shell";
  if (/\bfun\s+main\s*\(|\bval\s+\w+\s*=/m.test(code)) return "kotlin";
  if (/\bfn\s+main\s*\(|\blet\s+mut\s+\w+/m.test(code)) return "rust";
  if (/\b(?:const|let|var)\s+\w+|=>|require\s*\(/m.test(code)) return "javascript";
  return "unknown";
}

rules.push(...createExtendedRules(ALL));
rules.push(...createExpansionRules(ALL));
rules.push(...createAdditionalRules());
rules.push(...createAdvancedRules());
rules.push(...createHttpRules());
rules.push(...createFrameworkRules());
rules.push(...createComposedRules());
rules.push(...createExpressionRules());
rules.push(...createCoverageRules());

export const ruleCount = rules.length;
export const staticRuleIds: readonly string[] = rules.map((rule) => rule.id);

// Index the immutable catalog once. Absent APIs skip entire HTTP/framework groups.
const ruleOrder = new Map(rules.map((rule, index) => [rule.id, index]));
const ruleGroupsByLanguage = new Map<string, Map<string, Rule[]>>();
for (const rule of rules) {
  const api = getHttpRuleApi(rule.id) ?? getFrameworkRuleApi(rule.id) ?? getComposedRuleApi(rule.id) ?? getExpressionRuleApi(rule.id) ?? "";
  for (const language of rule.languages) {
    if (!ruleGroupsByLanguage.has(language)) ruleGroupsByLanguage.set(language, new Map());
    const groups = ruleGroupsByLanguage.get(language)!;
    if (!groups.has(api)) groups.set(api, []);
    groups.get(api)!.push(rule);
  }
}

/** A detached copy of the built-in catalog for persistence and tooling. */
export function getStaticRules(): Rule[] {
  return rules.map((rule) => ({
    ...rule,
    languages: [...rule.languages],
    references: [...rule.references],
    pattern: new RegExp(rule.pattern.source, rule.pattern.flags),
    exclude: rule.exclude ? new RegExp(rule.exclude.source, rule.exclude.flags) : undefined,
  }));
}

function calculateScore(findings: Finding[]): number {
  const weights: Record<Severity, number> = { critical: 28, high: 16, medium: 8, low: 3, info: 1 };
  const penalty = findings.reduce((total, finding) => total + weights[finding.severity], 0);
  return Math.max(0, 100 - Math.min(100, penalty));
}

/** Physical source lines, including blanks/comments, without a phantom line after EOF. */
export function countSourceLines(code: string): number {
  if (!code.length) return 0;
  const normalized = code.replace(/\r\n?/g, "\n");
  return normalized.split("\n").length - (normalized.endsWith("\n") ? 1 : 0);
}

export function scanCode(code: string, filename = "code.txt", selectedLanguage = "auto"): ScanResult {
  const started = performance.now();
  const language = selectedLanguage === "auto" ? detectLanguage(filename, code) : selectedLanguage;
  const normalizedCode = code.replace(/\r\n?/g, "\n");
  const lines = normalizedCode.split("\n");
  const findings: Finding[] = [];

  const positionAt = (offset: number) => {
    const before = normalizedCode.slice(0, offset);
    const line = before.split("\n").length;
    const lastBreak = before.lastIndexOf("\n");
    return { line, column: offset - lastBreak };
  };

  const pushFinding = (rule: Rule, offset: number, matchedText = "") => {
    const position = positionAt(offset);
    const sourceLine = lines[position.line - 1] ?? matchedText;
    if (findings.some((item) => item.ruleId === rule.id && item.line === position.line && item.column === position.column)) return;
    findings.push({
      id: rule.id + "-" + position.line + "-" + position.column,
      ruleId: rule.id,
      title: rule.title,
      description: rule.description,
      severity: rule.severity,
      cwe: rule.cwe,
      owasp: rule.owasp,
      confidence: rule.confidence,
      line: position.line,
      column: position.column,
      snippet: sourceLine.trim().slice(0, 220),
      context: lines.slice(Math.max(0, position.line - 2), Math.min(lines.length, position.line + 1)).join("\n").slice(0, 600),
      recommendation: rule.recommendation,
      references: rule.references,
      category: rule.category ?? "security",
    });
  };

  const activeRules = [...(ruleGroupsByLanguage.get(language) ?? new Map<string, Rule[]>())]
    .flatMap(([api, group]) => !api || normalizedCode.includes(api) ? group : [])
    .sort((left, right) => ruleOrder.get(left.id)! - ruleOrder.get(right.id)!);
  for (const rule of activeRules) {
    if (rule.scope === "file") {
      const flags = rule.pattern.flags.includes("g") ? rule.pattern.flags : rule.pattern.flags + "g";
      const matcher = new RegExp(rule.pattern.source, flags);
      for (const match of normalizedCode.matchAll(matcher)) {
        const matchText = match[0] ?? "";
        if (rule.exclude?.test(matchText)) continue;
        pushFinding(rule, match.index ?? 0, matchText);
      }
      continue;
    }

    let offset = 0;
    const matcher = new RegExp(rule.pattern.source, rule.pattern.flags.replace("g", ""));
    lines.forEach((line) => {
      const match = matcher.exec(line);
      if (match && !rule.exclude?.test(line)) pushFinding(rule, offset + (match.index ?? 0), match[0]);
      offset += line.length + 1;
    });
  }

  // Lightweight inter-line taint tracking catches common source-to-sink flows
  // while keeping the scanner dependency-free and fully local.
  const sourcePatterns: RegExp[] = [
    /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:req|request)\.(?:body|query|params|headers|cookies)/,
    /^\s*([A-Za-z_]\w*)\s*=\s*request\.(?:args|form|json|values|headers)/,
    /^\s*([A-Za-z_]\w*)\s*=\s*(?:input\s*\(|sys\.argv|os\.environ)/,
    /^\s*([A-Za-z_]\w*)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE|FILES)/,
    /^\s*([A-Za-z_]\w*)\s*=\s*params\[/,
  ];
  const sinks = [
    { id: "FLOW-SQL", title: "Поток данных в SQL-запрос", cwe: "CWE-89", severity: "critical" as Severity, category: "injection", pattern: /(?:query|execute|raw|execSQL)\s*\(/i, recommendation: "Используйте bind-параметры/prepared statement и не интерполируйте входные данные." },
    { id: "FLOW-CMD", title: "Поток данных в системную команду", cwe: "CWE-78", severity: "critical" as Severity, category: "injection", pattern: /(?:exec|execSync|system|popen|spawn|Process\.Start|Runtime\.getRuntime)\s*\(/i, recommendation: "Не используйте shell; передавайте проверенные аргументы отдельно." },
    { id: "FLOW-XSS", title: "Поток данных в HTML sink", cwe: "CWE-79", severity: "high" as Severity, category: "xss", pattern: /(?:innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML|render_template_string)/i, recommendation: "Экранируйте по контексту или применяйте проверенный HTML sanitizer." },
    { id: "FLOW-PATH", title: "Поток данных в файловую систему", cwe: "CWE-22", severity: "high" as Severity, category: "validation", pattern: /(?:readFile|writeFile|sendFile|createReadStream|open|FileInputStream|file_get_contents)\s*\(/i, recommendation: "Нормализуйте путь и проверьте, что он остаётся внутри фиксированного base directory." },
    { id: "FLOW-SSRF", title: "Поток данных в сетевой запрос", cwe: "CWE-918", severity: "high" as Severity, category: "ssrf", pattern: /(?:fetch|axios|requests\.|http\.(?:get|request)|urlopen)\s*\(/i, recommendation: "Используйте allowlist назначений и блокируйте private, loopback и link-local адреса." },
    { id: "FLOW-REDIRECT", title: "Поток данных в redirect", cwe: "CWE-601", severity: "medium" as Severity, category: "validation", pattern: /(?:redirect|Redirect)\s*\(/, recommendation: "Разрешайте только локальные пути или заранее известные URL." },
  ];
  const lineOffsets: number[] = [];
  lines.reduce((offset, line) => { lineOffsets.push(offset); return offset + line.length + 1; }, 0);

  lines.forEach((line, sourceIndex) => {
    let variable = "";
    for (const pattern of sourcePatterns) {
      const match = line.match(pattern);
      if (match?.[1]) { variable = match[1]; break; }
    }
    if (!variable) return;
    const escapedVariable = variable.replace(/[.*+?^$()|[\]{}]/g, "\\$&");
    const variableUse = new RegExp("\\b" + escapedVariable + "\\b");
    for (let sinkIndex = sourceIndex + 1; sinkIndex < Math.min(lines.length, sourceIndex + 61); sinkIndex += 1) {
      const candidate = lines[sinkIndex];
      if (new RegExp("^(?:\\s*)(?:const|let|var)?\\s*" + escapedVariable + "\\s*=").test(candidate)) break;
      if (variableUse.test(candidate) && /\b(?:sanitize|escape|validate|allowlist|normalize|resolve)[A-Za-z0-9_$]*\s*\(/i.test(candidate)) break;
      const sink = sinks.find((item) => item.pattern.test(candidate) && variableUse.test(candidate));
      if (!sink) continue;
      const pseudoRule: Rule = {
        id: sink.id,
        languages: [language],
        title: sink.title,
        description: "Недоверенные данные из строки " + (sourceIndex + 1) + " достигают чувствительной операции без видимой проверки.",
        severity: sink.severity,
        cwe: sink.cwe,
        owasp: "A03:2021",
        confidence: "medium",
        pattern: sink.pattern,
        recommendation: sink.recommendation,
        references: ["https://cwe.mitre.org/data/definitions/" + sink.cwe.replace("CWE-", "") + ".html"],
        category: sink.category,
      };
      if (!findings.some((item) => item.cwe === sink.cwe && item.line === sinkIndex + 1)) {
        pushFinding(pseudoRule, lineOffsets[sinkIndex] + Math.max(0, candidate.search(sink.pattern)));
      }
      break;
    }
  });

  const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.line - b.line);
  const summary = findings.reduce<ScanSummary>((acc, item) => {
    acc.total += 1;
    acc[item.severity] += 1;
    return acc;
  }, { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, score: 100 });
  summary.score = calculateScore(findings);

  return {
    language,
    scannedLines: countSourceLines(normalizedCode),
    filesScanned: 1,
    durationMs: Math.max(1, Math.round(performance.now() - started)),
    summary,
    findings,
  };
}

export function scanFiles(files: Array<{ name: string; code: string }>): ScanResult {
  const started = performance.now();
  const results = files.map((file) => scanCode(file.code, file.name, "auto"));
  const findings = results.flatMap((result, fileIndex) => result.findings.map((finding) => ({
    ...finding, id: `${fileIndex}-${finding.id}`, filename: files[fileIndex].name,
  })));
  const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((left, right) => order[left.severity] - order[right.severity]
    || (left.filename ?? "").localeCompare(right.filename ?? "") || left.line - right.line);
  const summary = findings.reduce<ScanSummary>((acc, finding) => {
    acc.total += 1; acc[finding.severity] += 1; return acc;
  }, { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, score: 100 });
  summary.score = calculateScore(findings);
  const languages = new Set(results.map((result) => result.language));
  return {
    language: languages.size === 1 ? results[0]?.language ?? "unknown" : "multiple",
    scannedLines: results.reduce((total, result) => total + result.scannedLines, 0),
    durationMs: Math.max(1, Math.round(performance.now() - started)), summary, findings, filesScanned: files.length,
  };
}
