import type { Rule, Severity } from "./sast-engine.ts";

// Keep the pack separate from the scanner. Patterns intentionally match explicit
// risky APIs/settings; medium confidence means the data and deployment need review.
export function createExtendedRules(allLanguages: string[]): Rule[] {
  const pack: Rule[] = [];
  const js = ["javascript", "typescript"];
  const py = ["python"];
  const java = ["java", "kotlin"];
  const php = ["php"];
  const go = ["go"];
  const cs = ["csharp"];
  const rb = ["ruby"];
  const rs = ["rust"];
  const swift = ["swift"];
  const scala = ["scala"];
  const sh = ["shell"];
  const cfg = ["config"];
  const owaspByCategory: Record<string, string> = {
    secrets: "A07:2021", crypto: "A02:2021", transport: "A02:2021",
    configuration: "A05:2021", deserialization: "A08:2021", authentication: "A07:2021",
    csrf: "A01:2021", authorization: "A01:2021", logging: "A09:2021",
    injection: "A03:2021", xss: "A03:2021", xxe: "A05:2021", validation: "A01:2021",
  };
  function add(id: string, languages: string[], title: string, description: string,
    severity: Severity, cwe: number, category: string, pattern: RegExp, recommendation: string,
    options: Partial<Pick<Rule, "confidence" | "scope" | "exclude">> = {}) {
    pack.push({ id, languages, title, description, severity, cwe: `CWE-${cwe}`,
      category, pattern, recommendation, owasp: owaspByCategory[category] ?? "A05:2021",
      confidence: "medium", references: [`https://cwe.mitre.org/data/definitions/${cwe}.html`], ...options });
  }

  // Provider credentials: only secret formats, never public/publishable keys.
  add("SEC010", allLanguages, "Секретный ключ Stripe", "Найден ключ Stripe для production API.", "critical", 798, "secrets",
    /\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b/, "Отзовите ключ Stripe и загрузите новый из хранилища секретов.", { confidence: "high" });
  add("SEC011", allLanguages, "API-ключ Google", "Найден ключ Google API; проверьте ограничения API, адресов и приложений.", "high", 798, "secrets",
    /\bAIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/, "Удалите ключ из исходников, ограничьте его назначение и перевыпустите при утечке.");
  add("SEC012", allLanguages, "Токен GitLab", "Найден personal access token GitLab.", "critical", 798, "secrets",
    /\bglpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/, "Отзовите токен GitLab и перенесите новое значение в CI secrets.", { confidence: "high" });
  add("SEC013", allLanguages, "Токен npm", "Найден токен доступа к npm registry.", "critical", 798, "secrets",
    /\bnpm_[A-Za-z0-9]{36}\b/, "Отзовите токен npm, проверьте публикации пакетов и используйте защищённые CI credentials.", { confidence: "high" });
  add("SEC014", allLanguages, "API-ключ SendGrid", "Найден ключ API SendGrid с узнаваемой структурой.", "critical", 798, "secrets",
    /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/, "Отзовите ключ SendGrid и ограничьте права нового ключа.", { confidence: "high" });
  add("SEC015", allLanguages, "Ключ Azure Storage", "Строка подключения Azure содержит AccountKey.", "critical", 798, "secrets",
    /\bAccountKey\s*=\s*[A-Za-z0-9+/]{86}==/, "Смените ключ Storage Account; используйте managed identity или хранилище секретов.", { confidence: "high" });

  add("JS030", js, "Динамический HTML через document.write", "document.write получает динамическое значение, которое может содержать HTML или скрипт.", "high", 79, "xss",
    /\bdocument\.write(?:ln)?\s*\(\s*(?:[A-Za-z_$]|`[^`\n]*\$\{|["'][^"'\n]*["']\s*\+)/, "Используйте textContent или безопасное построение DOM; очищайте необходимый HTML.");
  add("JS031", js, "Строковый код в таймере", "setTimeout/setInterval получает строку кода вместо функции.", "high", 95, "injection",
    /\bset(?:Timeout|Interval)\s*\(\s*["'`]/, "Передавайте callback-функцию, а данные — отдельными аргументами.");
  add("JS032", js, "postMessage без ограничения origin", "Сообщение может быть доставлено окну любого origin.", "medium", 346, "authorization",
    /\.postMessage\s*\([^;\n]{0,300},\s*["']\*["']\s*[,)]/, "Укажите точный targetOrigin и проверяйте origin входящих сообщений.");
  add("JS033", js, "Node.js integration в Electron", "Renderer Electron получает доступ к Node.js; XSS в недоверенном контенте может выполнить системный код.", "high", 94, "configuration",
    /\bnodeIntegration\s*:\s*true\b/, "Отключите nodeIntegration и предоставляйте минимальные API через contextBridge.");
  add("JS034", js, "Отключена изоляция контекста Electron", "Preload и страница Electron используют общий JavaScript-контекст.", "high", 749, "configuration",
    /\bcontextIsolation\s*:\s*false\b/, "Включите contextIsolation и проверяйте аргументы API из contextBridge.");
  add("JS035", js, "Отключена web security Electron", "Electron отключает ограничения same-origin для renderer.", "high", 346, "configuration",
    /\bwebSecurity\s*:\s*false\b/, "Включите webSecurity; используйте ограниченный IPC для необходимых обращений.");
  add("JS036", js, "Регулярное выражение из HTTP-ввода", "HTTP-параметр становится шаблоном регулярного выражения; возможны инъекция шаблона и чрезмерное время обработки.", "medium", 1333, "validation",
    /\bnew\s+RegExp\s*\(\s*(?:req|request)\.(?:query|body|params)\b/, "Экранируйте метасимволы, ограничьте длину и сложность шаблона либо используйте фиксированное выражение.");
  add("JS037", js, "Отражение HTTP-ввода в HTML", "res.send получает значение прямо из запроса; если ответ HTML, возможен отражённый XSS.", "high", 79, "xss",
    /\b(?:res|response)\.send\s*\(\s*(?:req|request)\.(?:query|body|params)\b/, "Возвращайте структурированный JSON или экранируйте данные в HTML-контексте.");
  add("JS038", js, "Отключён sandbox Electron", "Renderer Electron явно запускается без process sandbox.", "high", 693, "configuration",
    /\bwebPreferences\s*:\s*\{[^{}]{0,400}\bsandbox\s*:\s*false\b/, "Включите sandbox и предоставляйте renderer только необходимые IPC API.", { scope: "file" });
  add("JS039", js, "Секрет в localStorage", "Пароль, токен или секрет сохраняется в localStorage и доступен скриптам страницы.", "medium", 922, "authentication",
    /\blocalStorage\.setItem\s*\(\s*["'](?:access[_-]?token|refresh[_-]?token|token|password|secret)["']\s*,/i, "Сократите хранение токенов в браузере; для сессий используйте защищённые HttpOnly cookie с CSRF-защитой.");

  add("PY030", py, "SSH принимает неизвестный host key", "Paramiko автоматически принимает неизвестный ключ SSH-сервера.", "high", 295, "transport",
    /\b(?:paramiko\.)?AutoAddPolicy\s*\(/, "Загрузите доверенные host keys и используйте RejectPolicy.");
  add("PY031", py, "Отключена CSRF-защита Django", "csrf_exempt исключает обработчик из проверки CSRF.", "medium", 352, "csrf",
    /@(?:[A-Za-z_]\w*\.)*csrf_exempt\b|\bcsrf_exempt\s*\(/, "Сохраните CSRF-защиту для cookie-аутентификации; исключения разрешайте только с независимой проверкой клиента.");
  add("PY032", py, "lxml разрешает внешние сущности", "XMLParser явно включает разрешение XML-сущностей.", "high", 611, "xxe",
    /\b(?:etree\.)?XMLParser\s*\([^\n)]*\bresolve_entities\s*=\s*True\b/, "Установите resolve_entities=False, no_network=True и ограничьте размер XML.");
  add("PY033", py, "Динамический SQL в Django raw", "raw/RawSQL получает f-строку или конкатенацию SQL.", "critical", 89, "injection",
    /(?:\.raw|\bRawSQL)\s*\(\s*(?:f["']|["'][^"'\n]*["']\s*\+)/, "Используйте ORM или передавайте значения через параметры SQL.");
  add("PY034", py, "Flask отдаёт файл по HTTP-параметру", "Имя отдаваемого файла напрямую зависит от запроса.", "high", 22, "validation",
    /\b(?:send_file|send_from_directory)\s*\([^\n)]*\brequest\.(?:args|form|values|json)\b/, "Выбирайте файл из фиксированного каталога по разрешённому идентификатору; проверяйте нормализованный путь.");
  add("PY035", py, "Ослаблены сессионные cookie Python", "Настройки сессионных cookie явно отключают Secure или HttpOnly.", "medium", 614, "authentication",
    /\bSESSION_COOKIE_(?:SECURE|HTTPONLY)["']?\s*(?:=|:)\s*False\b/, "Включите SESSION_COOKIE_SECURE и SESSION_COOKIE_HTTPONLY для production-сессий.");
  add("PY036", py, "PyTorch загружает произвольные объекты", "torch.load явно отключает weights_only и допускает десериализацию Python-объектов.", "high", 502, "deserialization",
    /\btorch\.load\s*\([^\n)]*\bweights_only\s*=\s*False\b/, "Используйте weights_only=True либо safetensors; загружайте только доверенные модели.");
  add("PY037", py, "Десериализация Pickle через pandas", "read_pickle может выполнить код из недоверенного файла.", "high", 502, "deserialization",
    /\b(?:pd|pandas)\.read_pickle\s*\(/, "Используйте формат данных без исполняемой десериализации и проверяйте происхождение файла.");
  add("PY038", py, "Django принимает любой Host", "ALLOWED_HOSTS содержит wildcard и отключает ограничение HTTP Host.", "medium", 346, "configuration",
    /\bALLOWED_HOSTS\s*=\s*\[[^\]\n]*["']\*["']/, "Укажите явный список допустимых имён приложения и проверяйте Host на reverse proxy.");
  add("PY039", py, "Слабый password hasher Django", "Использован MD5PasswordHasher или UnsaltedMD5PasswordHasher; для production-паролей это небезопасно.", "high", 916, "crypto",
    /\b(?:Unsalted)?MD5PasswordHasher\b/, "Используйте Argon2PasswordHasher или актуальный PBKDF2PasswordHasher; мигрируйте старые хеши.");

  add("JAVA030", java, "Устаревший шифр Java", "Cipher выбирает DES, DESede, RC2 или RC4.", "high", 327, "crypto",
    /\bCipher\.getInstance\s*\(\s*"(?:DES|DESede|RC2|RC4)(?:\/[^"\n]*)?"/, "Используйте AES-GCM с уникальным nonce и проверкой authentication tag.", { confidence: "high" });
  add("JAVA031", java, "Отключена CSRF-защита Spring", "Конфигурация Spring явно отключает CSRF.", "medium", 352, "csrf",
    /\.csrf\s*\(\s*\)\s*\.disable\s*\(|\.csrf\s*\(\s*(?:[A-Za-z_]\w*\s*->\s*[A-Za-z_]\w*\.disable\s*\(\s*\)|[A-Za-z_.]*AbstractHttpConfigurer::disable)/, "Сохраните CSRF для cookie-аутентификации; документируйте отдельную защиту stateless API.");
  add("JAVA032", java, "Spring разрешает все запросы", "anyRequest().permitAll() открывает все маршруты без проверки доступа.", "high", 862, "authorization",
    /\.anyRequest\s*\(\s*\)\s*\.permitAll\s*\(/, "Разрешайте публичные маршруты явно, а остальные защищайте authenticated/hasRole.");
  add("JAVA033", java, "LDAP-фильтр через конкатенацию", "Фильтр LDAP search собирается конкатенацией строк.", "high", 90, "injection",
    /\b(?:context|ctx|ldapContext)\.search\s*\([^;\n]{0,300}["'][^"'\n]*["']\s*\+/, "Используйте параметризованный LDAP search и экранирование значений фильтра.");
  add("JAVA034", java, "WebView разрешает mixed content", "Android WebView допускает HTTP-ресурсы внутри HTTPS-страницы.", "high", 319, "transport",
    /\bsetMixedContentMode\s*\(\s*(?:WebSettings\.)?MIXED_CONTENT_ALWAYS_ALLOW\s*\)/, "Используйте MIXED_CONTENT_NEVER_ALLOW и загружайте ресурсы по HTTPS.");
  add("JAVA035", java, "Java bridge в Android WebView", "addJavascriptInterface открывает объект Java для JavaScript страницы; недоверенный контент требует отдельной проверки.", "medium", 749, "configuration",
    /\.addJavascriptInterface\s*\(/, "Не подключайте bridge к недоверенным страницам; ограничьте интерфейс и проверяйте источники навигации.");
  add("JAVA036", java, "WebView даёт file URL доступ к сети", "JavaScript локальной страницы может обращаться к произвольным origins.", "high", 346, "configuration",
    /\bsetAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)/, "Отключите universal access; используйте WebViewAssetLoader для локальных ресурсов.", { confidence: "high" });
  add("JAVA037", java, "Слабый размер RSA-ключа Java", "RSAKeyGenParameterSpec задаёт ключ короче 2048 бит.", "high", 326, "crypto",
    /\bRSAKeyGenParameterSpec\s*\(\s*(?:512|768|1024)\s*,/, "Используйте RSA не менее 2048 бит и актуальные параметры криптографического протокола.", { confidence: "high" });

  add("PHP030", php, "PHP XML разрешает сущности и DTD", "LIBXML_NOENT или LIBXML_DTDLOAD разрешает обработку сущностей или загрузку DTD.", "high", 611, "xxe",
    /\bLIBXML_(?:NOENT|DTDLOAD)\b/, "Удалите обработку внешних сущностей и DTD, используйте LIBXML_NONET и лимиты XML.");
  add("PHP031", php, "Выполнение выражения через preg_replace", "Legacy PHP preg_replace использует модификатор e для выполнения replacement как кода.", "critical", 95, "injection",
    /\bpreg_replace\s*\(\s*["']\/[^\n]*?\/[imsxuADSUXJ]*e[imsxuADSUXJ]*["']/, "Замените legacy /e на preg_replace_callback с фиксированной callback-функцией.");
  add("PHP032", php, "Слабая генерация security-токена PHP", "rand, mt_rand или uniqid используется для токена, пароля или nonce.", "medium", 338, "crypto",
    /\$(?:token|secret|password|nonce)[A-Za-z0-9_]*\s*=\s*(?:mt_rand|rand|uniqid)\s*\(/i, "Используйте random_bytes или random_int для секретных значений.");
  add("PHP033", php, "Небезопасный redirect PHP", "Location напрямую содержит значение из HTTP-запроса.", "medium", 601, "validation",
    /\bheader\s*\(\s*["']Location:\s*["']\s*\.\s*\$_(?:GET|POST|REQUEST)\b/i, "Разрешайте только локальные пути или URL из фиксированного списка.");
  add("PHP034", php, "Ослаблены сессионные cookie PHP", "ini_set явно отключает Secure или HttpOnly для сессионного cookie.", "medium", 614, "authentication",
    /\bini_set\s*\(\s*["']session\.cookie_(?:secure|httponly)["']\s*,\s*(?:["'](?:0|off)["']|false|0)\s*\)/i, "Включите Secure, HttpOnly и подходящий SameSite в настройках сессии.");
  add("PHP035", php, "LDAP-инъекция PHP", "ldap_search получает фильтр с непосредственным HTTP-вводом.", "high", 90, "injection",
    /\bldap_search\s*\([^;\n]*\$_(?:GET|POST|REQUEST)\b/i, "Экранируйте значения через ldap_escape с LDAP_ESCAPE_FILTER и фиксируйте структуру фильтра.");

  add("GO030", go, "Слабый минимальный TLS в Go", "MinVersion явно допускает TLS 1.0, TLS 1.1 или SSL 3.0.", "high", 326, "transport",
    /\bMinVersion\s*:\s*tls\.Version(?:TLS10|TLS11|SSL30)\b/, "Установите MinVersion: tls.VersionTLS12 или TLS13.", { confidence: "high" });
  add("GO031", go, "Устаревший шифр Go", "Используется DES, TripleDES или RC4.", "high", 327, "crypto",
    /\b(?:des\.(?:NewCipher|NewTripleDESCipher)|rc4\.NewCipher)\s*\(/, "Используйте AES-GCM или ChaCha20-Poly1305.", { confidence: "high" });
  add("GO032", go, "Слабый RSA-ключ Go", "rsa.GenerateKey создаёт ключ короче 2048 бит.", "high", 326, "crypto",
    /\brsa\.GenerateKey\s*\(\s*[^,\n]+,\s*(?:512|768|1024)\s*\)/, "Используйте ключ не менее 2048 бит и crypto/rand.Reader.", { confidence: "high" });
  add("GO033", go, "SSH без проверки host key", "ssh.InsecureIgnoreHostKey отключает проверку SSH-сервера.", "high", 295, "transport",
    /\bssh\.InsecureIgnoreHostKey\s*\(/, "Настройте проверку known_hosts или фиксированный доверенный host key.", { confidence: "high" });
  add("GO034", go, "Открытый файловый сервер Go", "http.FileServer раздаёт текущий каталог либо корень файловой системы.", "high", 552, "configuration",
    /\bhttp\.FileServer\s*\(\s*http\.Dir\s*\(\s*"(?:\.|\/)"\s*\)/, "Раздавайте только отдельный каталог публичных файлов с проверкой доступа.");
  add("GO035", go, "text/template в Go HTTP-коде", "HTTP-код импортирует text/template; если шаблон формирует HTML, данные выводятся без HTML-экранирования.", "medium", 79, "xss",
    /"text\/template"[\s\S]{0,2000}\b(?:http\.HandleFunc|http\.HandlerFunc|http\.ResponseWriter)\b/, "Используйте html/template для HTML-ответов; text/template оставьте для обычного текста.", { scope: "file" });

  add("CS030", cs, "HttpClient принимает любой сертификат", "Использован DangerousAcceptAnyServerCertificateValidator.", "high", 295, "transport",
    /\bDangerousAcceptAnyServerCertificateValidator\b/, "Восстановите системную проверку сертификата и настройте доверенный CA.", { confidence: "high" });
  add("CS031", cs, "SQL через интерполяцию в EF Core", "FromSqlRaw/ExecuteSqlRaw получает интерполированную строку или конкатенацию.", "critical", 89, "injection",
    /\b(?:FromSqlRaw|ExecuteSqlRaw)(?:Async)?\s*\(\s*(?:\$@?"|@\$"|"[^"\n]*"\s*\+)/, "Используйте FromSqlInterpolated/ExecuteSqlInterpolated или bind-параметры raw API.");
  add("CS032", cs, "LDAP-фильтр через конкатенацию .NET", "DirectorySearcher.Filter строится из конкатенации или интерполяции.", "high", 90, "injection",
    /\bFilter\s*=\s*(?:\$"\([^"\n]*|"\([^"\n]*"\s*\+)/, "Фиксируйте LDAP-фильтр и экранируйте специальные символы значения.");
  add("CS033", cs, "Устаревший шифр .NET", "Приложение создаёт DES, TripleDES или RC2.", "high", 327, "crypto",
    /\b(?:DES|TripleDES|RC2)\.Create\s*\(|\bnew\s+(?:DES|TripleDES|RC2)CryptoServiceProvider\s*\(/, "Используйте AesGcm или другой современный AEAD-алгоритм.", { confidence: "high" });
  add("CS034", cs, "Обход HTML-экранирования Razor", "Html.Raw помечает значение как готовый HTML.", "high", 79, "xss",
    /\bHtml\.Raw\s*\(/, "Используйте штатное экранирование Razor; необходимый HTML очищайте по allowlist.");
  add("CS035", cs, "Отключена antiforgery-проверка ASP.NET", "IgnoreAntiforgeryToken исключает обработчик из проверки CSRF.", "medium", 352, "csrf",
    /\[\s*IgnoreAntiforgeryToken(?:Attribute)?(?:\s*\(\s*\))?\s*\]/, "Сохраните antiforgery-проверку для cookie-аутентификации и изменяющих состояние запросов.");

  add("RB030", rb, "Обход HTML-экранирования Rails", "html_safe или raw передаёт строку в HTML без штатного экранирования.", "high", 79, "xss",
    /\.html_safe\b|\braw\s*\(/, "Сохраняйте экранирование Rails; очищайте необходимый HTML через sanitize.");
  add("RB031", rb, "Массовое присваивание всех параметров Rails", "permit! разрешает все поля пользовательского запроса.", "high", 915, "authorization",
    /\bparams(?:\.[A-Za-z_]\w*\([^\n)]*\)|\[[^\]\n]+\])?\.permit!/, "Используйте permit с явным списком редактируемых полей и отдельно проверяйте права.");
  add("RB032", rb, "Отключена CSRF-защита Rails", "Контроллер отключает verify_authenticity_token.", "medium", 352, "csrf",
    /\bskip_before_action\b[^\n]*\bverify_authenticity_token\b|\bskip_forgery_protection\b/, "Сохраните protect_from_forgery для сессий; исключения ограничьте API с независимой аутентификацией.");
  add("RB033", rb, "Ruby OpenSSL не проверяет сертификат", "SSL-клиент использует VERIFY_NONE.", "high", 295, "transport",
    /\bverify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE\b/, "Используйте VERIFY_PEER, доверенные CA и проверку имени сервера.", { confidence: "high" });

  add("RS030", rs, "Rust OpenSSL не проверяет сертификат", "TLS builder использует SslVerifyMode::NONE.", "high", 295, "transport",
    /\.set_verify\s*\(\s*(?:openssl::ssl::)?SslVerifyMode::NONE\s*\)/, "Используйте SslVerifyMode::PEER и проверку имени сервера.", { confidence: "high" });
  add("RS031", rs, "Небезопасный SHA-1 в Rust", "Используется SHA-1, который не обеспечивает стойкость к коллизиям.", "medium", 327, "crypto",
    /\b(?:sha1::)?Sha1::(?:new|digest)\s*\(/, "Используйте SHA-256/512 для целостности; для паролей — Argon2id.");
  add("RS032", rs, "SQL-инъекция rusqlite", "query_row/prepare получает SQL из format!.", "critical", 89, "injection",
    /\.(?:query_row|prepare)\s*\(\s*&?format!\s*\(/, "Используйте статический SQL и параметры rusqlite params!.");
  add("RS033", rs, "Rust создаёт общедоступный файл", "OpenOptionsExt явно задаёт режим 0777 или 0666.", "high", 732, "configuration",
    /\.mode\s*\(\s*0o(?:777|666)\s*\)/, "Задайте минимальные права, например 0o600 для чувствительных файлов.");

  add("SWIFT030", swift, "Keychain доступен при блокировке", "Выбран устаревший уровень Keychain AccessibleAlways.", "high", 922, "configuration",
    /\bkSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b/, "Используйте kSecAttrAccessibleWhenUnlocked или более строгий уровень с учётом фонового доступа.");
  add("SWIFT031", swift, "ECB в CommonCrypto", "CommonCrypto использует режим ECB, который раскрывает структуру повторяющихся блоков.", "high", 327, "crypto",
    /\bkCCOptionECBMode\b/, "Используйте AEAD, например AES-GCM, с уникальным nonce и проверкой authentication tag.", { confidence: "high" });
  add("SWIFT032", swift, "SQL-интерполяция Swift", "SQLite SQL содержит строковую интерполяцию Swift.", "critical", 89, "injection",
    /\b(?:sqlite3_exec|sqlite3_prepare_v2)\s*\([^\n]*"[^"\n]*\\\(/, "Используйте sqlite3_bind_* с placeholders и фиксированный SQL.");
  add("SWIFT033", swift, "Небезопасное unarchive Swift", "Legacy NSKeyedUnarchiver загружает объекты без списка разрешённых классов.", "high", 502, "deserialization",
    /\bNSKeyedUnarchiver\.unarchive(?:Object|TopLevelObjectWithData)\s*\(/, "Используйте unarchivedObject(ofClass:from:) или ofClasses с NSSecureCoding.");

  add("SCALA030", scala, "Слабая генерация security-токена Scala", "Токен создаётся через scala.util.Random.", "medium", 338, "crypto",
    /\b(?:token|secret|nonce|password)\w*\s*=\s*(?:scala\.util\.)?Random\.(?:alphanumeric|nextInt|nextLong|nextBytes)\b/i, "Используйте java.security.SecureRandom для security-sensitive значений.");
  add("SCALA031", scala, "Play WS не проверяет hostname", "SSLLooseConfig явно отключает проверку имени TLS-сервера.", "high", 297, "transport",
    /\bdisableHostnameVerification\s*(?:=|:)\s*true\b/, "Включите проверку hostname и используйте сертификат с корректным SAN.", { confidence: "high" });
  add("SCALA032", scala, "Неэкранированный HTML в Play", "Html создаёт доверенный HTML-фрагмент из динамического значения.", "high", 79, "xss",
    /\b(?:play\.twirl\.api\.)?Html\s*\(\s*(?:[A-Za-z_]|s"[^"\n]*\$)/, "Используйте штатное экранирование Twirl, очищайте необходимый HTML.");
  add("SCALA033", scala, "Play WS принимает любой сертификат", "WS-конфигурация явно принимает любой сертификат.", "high", 295, "transport",
    /\bacceptAnyCertificate\s*(?:=|:)\s*true\b/, "Отключите acceptAnyCertificate и настройте доверенное хранилище CA.", { confidence: "high" });

  add("SH030", sh, "SSH без проверки host key", "SSH отключает проверку ключа сервера.", "high", 295, "transport",
    /\b(?:ssh|scp|sftp)\b[^\n]*\bStrictHostKeyChecking\s*=\s*no\b/i, "Используйте StrictHostKeyChecking=yes и заранее проверенный known_hosts.", { confidence: "high" });
  add("SH031", sh, "Отключён known_hosts SSH", "SSH направляет known_hosts в /dev/null и не сохраняет доверенные ключи.", "medium", 295, "transport",
    /\b(?:ssh|scp|sftp)\b[^\n]*\bUserKnownHostsFile\s*=\s*\/dev\/null\b/, "Храните проверенные ключи серверов в защищённом known_hosts.");
  add("SH032", sh, "Общедоступная umask", "umask 000/0000 позволяет создавать доступные всем файлы.", "high", 732, "configuration",
    /\bumask\s+0{3,4}(?=\s|;|$)/, "Используйте umask 077 для секретных файлов или 027 для ограниченного группового доступа.", { confidence: "high" });
  add("SH033", sh, "Пароль в аргументах shell-команды", "Пароль sshpass/mysql передаётся литералом в аргументах процесса.", "high", 214, "secrets",
    /\bsshpass\s+-p\s+["'][^"'\n]+["']|\bmysql\b[^\n]*--password=["'][^"'\n]+["']/, "Передавайте credentials через защищённый файл или secret store, исключите пароль из argv.");

  add("CFG030", cfg, "Kubernetes отключает non-root policy", "runAsNonRoot явно выключен.", "medium", 250, "configuration",
    /\brunAsNonRoot\s*:\s*false\b/i, "Установите runAsNonRoot: true и непривилегированный UID.");
  add("CFG031", cfg, "Kubernetes монтирует hostPath", "Pod получает доступ к каталогу файловой системы узла.", "medium", 250, "configuration",
    /^\s*(?:-\s*)?hostPath\s*:/m, "Используйте PVC или emptyDir; hostPath ограничивайте выделенным безопасным каталогом.");
  add("CFG032", cfg, "Kubernetes получает SYS_PTRACE", "Capability SYS_PTRACE расширяет возможности наблюдения за процессами.", "high", 250, "configuration",
    /\b(?:cap_add|add)\s*:\s*(?:\[[^\]\n]*\bSYS_PTRACE\b[^\]\n]*\]|(?:\r?\n\s*-\s*["']?[A-Z_]+["']?\s*)*\r?\n\s*-\s*["']?SYS_PTRACE["']?\b)/, "Удалите SYS_PTRACE из production-контейнеров, оставьте диагностический доступ ограниченным.", { scope: "file" });
  add("CFG033", cfg, "AppArmor контейнера отключён", "Контейнер явно использует профиль AppArmor unconfined.", "high", 693, "configuration",
    /\bapparmor\s*[:=]\s*unconfined\b|\bappArmorProfile\s*:\s*\n\s*type\s*:\s*Unconfined\b/i, "Используйте RuntimeDefault или утверждённый профиль AppArmor.", { confidence: "high", scope: "file" });
  add("CFG034", cfg, "Docker использует host PID", "Compose-контейнер получает PID namespace хоста.", "high", 250, "configuration",
    /^\s*pid\s*:\s*["']?host["']?\s*(?:#.*)?$/m, "Используйте отдельный PID namespace и ограничьте диагностику узла.", { confidence: "high" });
  add("CFG035", cfg, "GitHub Actions выдаёт write-all", "Workflow предоставляет токену полный набор write permissions.", "high", 732, "authorization",
    /^\s*permissions\s*:\s*["']?write-all["']?\s*(?:#.*)?$/m, "Задайте минимальные permissions для каждого job, обычно contents: read.", { confidence: "high" });
  add("CFG036", cfg, "GitHub Actions исполняет текст события", "run/script напрямую подставляет пользовательский title/body/head_ref события в скрипт.", "high", 78, "injection",
    /(?:^\s*(?:run|script)\s*:[^\n]*|^\s*(?:echo|printf|bash|sh|node|python|curl|git)\b[^\n]*)\$\{\{\s*github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref)|comment\.body|head_commit\.message)\s*\}\}/, "Передайте поле события через env и используйте переменную как данные с корректным quoting.");
  add("CFG037", cfg, "Отключён TLS PostgreSQL-клиента", "Строка подключения явно выбирает sslmode=disable.", "high", 319, "transport",
    /\bsslmode\s*=\s*disable\b/i, "Используйте sslmode=verify-full с доверенным CA при сетевом доступе к PostgreSQL.");
  add("CFG038", cfg, "Android разрешает cleartext traffic", "Android manifest явно разрешает незашифрованный трафик.", "medium", 319, "transport",
    /\bandroid:usesCleartextTraffic\s*=\s*["']true["']/, "Установите usesCleartextTraffic=false, исключения ограничьте в network security config.");
  add("CFG039", cfg, "CSP разрешает unsafe-eval", "Content Security Policy разрешает выполнение динамических строк как кода.", "medium", 693, "configuration",
    /\b(?:script-src|default-src)\b[^;\n]*["']unsafe-eval["']/, "Удалите unsafe-eval и замените динамическое выполнение кода статическими функциями.");
  add("CFG040", cfg, "Android debug включён в manifest", "Android-приложение явно разрешает подключение отладчика.", "high", 489, "configuration",
    /\bandroid:debuggable\s*=\s*["']true["']/, "Отключите debuggable в release manifest и проверяйте параметры подписанного APK.", { confidence: "high" });
  add("CFG041", cfg, "IAM разрешает все действия", "Allow-policy содержит Action '*'; проверьте ограничения Resource и Condition.", "high", 732, "authorization",
    /"Effect"\s*:\s*"Allow"[^{}]{0,500}"Action"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])|"Action"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])[^{}]{0,500}"Effect"\s*:\s*"Allow"/, "Укажите минимальный список IAM actions, ресурсов и условий доступа.", { scope: "file" });
  add("CFG042", cfg, "Публичный ACL хранилища", "ACL явно разрешает публичное чтение или запись объекта хранилища.", "high", 284, "authorization",
    /["']?\bacl["']?\s*[:=]\s*["']?(?:public-read-write|public-read)["']?(?=\s|,|}|$)/i, "Используйте private ACL и явную политику доступа; включите запрет публичного доступа.");
  add("CFG043", cfg, "Dockerfile загружает удалённый ADD", "ADD скачивает ресурс по HTTP/HTTPS без видимой проверки целостности.", "medium", 494, "configuration",
    /^\s*ADD\s+https?:\/\/\S+/im, "Используйте ADD --checksum с фиксированным SHA-256 либо отдельную загрузку с проверкой подписи.");

  return pack;
}
