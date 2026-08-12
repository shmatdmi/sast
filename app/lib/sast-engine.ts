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
};

type Rule = {
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
};

const ALL = ["javascript", "typescript", "python", "java", "php", "go", "csharp", "ruby", "unknown"];

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
    description: "Math.random() непригоден для токенов, идентификаторов сессий и других security-sensitive значений.",
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
    pattern: /(?:readFile|readFileSync|sendFile|open|FileInputStream|file_get_contents)\s*\([^)]*(?:req\.|request\.|params|query|argv|GET|POST)/i,
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

const languageByExtension: Record<string, string> = {
  js: "javascript", jsx: "javascript", mjs: "javascript", cjs: "javascript",
  ts: "typescript", tsx: "typescript", mts: "typescript", cts: "typescript",
  py: "python", java: "java", php: "php", go: "go", cs: "csharp", rb: "ruby",
};

export const languageLabels: Record<string, string> = {
  auto: "Автоопределение",
  javascript: "JavaScript",
  typescript: "TypeScript",
  python: "Python",
  java: "Java",
  php: "PHP",
  go: "Go",
  csharp: "C#",
  ruby: "Ruby",
  unknown: "Универсальный",
};

export function detectLanguage(filename: string, code: string): string {
  const extension = filename.toLowerCase().split(".").pop() ?? "";
  if (languageByExtension[extension]) return languageByExtension[extension];
  if (/^\s*<\?php/m.test(code)) return "php";
  if (/^\s*(?:from\s+\w+\s+import|import\s+\w+|def\s+\w+\s*\()/m.test(code)) return "python";
  if (/\bpackage\s+main\b|\bfunc\s+main\s*\(/m.test(code)) return "go";
  if (/\bpublic\s+(?:static\s+)?class\s+\w+/m.test(code)) return "java";
  if (/\busing\s+System\b|\bnamespace\s+\w+/m.test(code)) return "csharp";
  if (/\b(?:const|let|var)\s+\w+|=>|require\s*\(/m.test(code)) return "javascript";
  return "unknown";
}

function calculateScore(findings: Finding[]): number {
  const weights: Record<Severity, number> = { critical: 28, high: 16, medium: 8, low: 3, info: 1 };
  const penalty = findings.reduce((total, finding) => total + weights[finding.severity], 0);
  return Math.max(0, 100 - Math.min(100, penalty));
}

export function scanCode(code: string, filename = "code.txt", selectedLanguage = "auto"): ScanResult {
  const started = performance.now();
  const language = selectedLanguage === "auto" ? detectLanguage(filename, code) : selectedLanguage;
  const lines = code.replace(/\r\n/g, "\n").split("\n");
  const findings: Finding[] = [];

  lines.forEach((line, index) => {
    rules
      .filter((rule) => rule.languages.includes(language) || (language === "unknown" && rule.languages.includes("unknown")))
      .forEach((rule) => {
        const match = line.match(rule.pattern);
        if (!match || (rule.exclude && rule.exclude.test(line))) return;
        findings.push({
          id: `${rule.id}-${index + 1}-${match.index ?? 0}`,
          ruleId: rule.id,
          title: rule.title,
          description: rule.description,
          severity: rule.severity,
          cwe: rule.cwe,
          owasp: rule.owasp,
          confidence: rule.confidence,
          line: index + 1,
          column: (match.index ?? 0) + 1,
          snippet: line.trim().slice(0, 220),
          recommendation: rule.recommendation,
          references: rule.references,
        });
      });
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
    scannedLines: lines.length,
    durationMs: Math.max(1, Math.round(performance.now() - started)),
    summary,
    findings,
  };
}
