# Расширенный набор SAST-правил

В базе 400 статических правил и 6 отдельных source-to-sink проверок.
Этот каталог описывает 86 новых статических правил из app/lib/sast-rules.ts.
Правила работают через общий движок в браузере и API; находки входят в JSON/SARIF
и сохраняются в истории с CWE, OWASP, уровнем уверенности и рекомендацией.

## Как читать находки

Высокая уверенность означает точную сигнатуру секрета или явно опасную настройку.
Средняя уверенность требует проверки происхождения данных и условий эксплуатации:
например, Html.Raw с доверенной константой, WebView bridge для локальной страницы
или отключённый CSRF в API с независимой аутентификацией могут быть обоснованы.
Наличие API или настройки само по себе не доказывает возможность эксплуатации.

Движок использует регулярные выражения и ограниченный межстрочный анализ,
не строит AST и не разрешает алиасы импортов. Правила не покрывают все способы
записи конструкций; комментарии и строковые примеры также могут совпасть.
Секреты распознаются по формату без сетевой проверки действительности.
При анализе ZIP тесты, демо и исходники самого каталога правил исключаются.

Каждое новое правило проверяется независимым опасным примером и безопасной
альтернативой в tests/extended-rules.test.ts. Дополнительно проверяются уникальность
ID, ограничение по языку, позиции строк, агрегирование файлов и скорость анализа.

## SEC: 6 правил

| ID | Проверка | Языки | Риск | CWE / OWASP |
|---|---|---|---|---|
| SEC010 | Секретный ключ Stripe | все языки | critical | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 |
| SEC011 | API-ключ Google | все языки | high | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 |
| SEC012 | Токен GitLab | все языки | critical | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 |
| SEC013 | Токен npm | все языки | critical | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 |
| SEC014 | API-ключ SendGrid | все языки | critical | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 |
| SEC015 | Ключ Azure Storage | все языки | critical | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 |

## JS: 10 правил

| ID | Проверка | Языки | Риск | CWE / OWASP |
|---|---|---|---|---|
| JS030 | Динамический HTML через document.write | javascript, typescript | high | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) / A03:2021 |
| JS031 | Строковый код в таймере | javascript, typescript | high | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) / A03:2021 |
| JS032 | postMessage без ограничения origin | javascript, typescript | medium | [CWE-346](https://cwe.mitre.org/data/definitions/346.html) / A01:2021 |
| JS033 | Node.js integration в Electron | javascript, typescript | high | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) / A05:2021 |
| JS034 | Отключена изоляция контекста Electron | javascript, typescript | high | [CWE-749](https://cwe.mitre.org/data/definitions/749.html) / A05:2021 |
| JS035 | Отключена web security Electron | javascript, typescript | high | [CWE-346](https://cwe.mitre.org/data/definitions/346.html) / A05:2021 |
| JS036 | Регулярное выражение из HTTP-ввода | javascript, typescript | medium | [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html) / A01:2021 |
| JS037 | Отражение HTTP-ввода в HTML | javascript, typescript | high | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) / A03:2021 |
| JS038 | Отключён sandbox Electron | javascript, typescript | high | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) / A05:2021 |
| JS039 | Секрет в localStorage | javascript, typescript | medium | [CWE-922](https://cwe.mitre.org/data/definitions/922.html) / A07:2021 |

## PY: 10 правил

| ID | Проверка | Языки | Риск | CWE / OWASP |
|---|---|---|---|---|
| PY030 | SSH принимает неизвестный host key | python | high | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 |
| PY031 | Отключена CSRF-защита Django | python | medium | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) / A01:2021 |
| PY032 | lxml разрешает внешние сущности | python | high | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) / A05:2021 |
| PY033 | Динамический SQL в Django raw | python | critical | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 |
| PY034 | Flask отдаёт файл по HTTP-параметру | python | high | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 |
| PY035 | Ослаблены сессионные cookie Python | python | medium | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) / A07:2021 |
| PY036 | PyTorch загружает произвольные объекты | python | high | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) / A08:2021 |
| PY037 | Десериализация Pickle через pandas | python | high | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) / A08:2021 |
| PY038 | Django принимает любой Host | python | medium | [CWE-346](https://cwe.mitre.org/data/definitions/346.html) / A05:2021 |
| PY039 | Слабый password hasher Django | python | high | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 |

## JAVA: 8 правил

| ID | Проверка | Языки | Риск | CWE / OWASP |
|---|---|---|---|---|
| JAVA030 | Устаревший шифр Java | java, kotlin | high | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) / A02:2021 |
| JAVA031 | Отключена CSRF-защита Spring | java, kotlin | medium | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) / A01:2021 |
| JAVA032 | Spring разрешает все запросы | java, kotlin | high | [CWE-862](https://cwe.mitre.org/data/definitions/862.html) / A01:2021 |
| JAVA033 | LDAP-фильтр через конкатенацию | java, kotlin | high | [CWE-90](https://cwe.mitre.org/data/definitions/90.html) / A03:2021 |
| JAVA034 | WebView разрешает mixed content | java, kotlin | high | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 |
| JAVA035 | Java bridge в Android WebView | java, kotlin | medium | [CWE-749](https://cwe.mitre.org/data/definitions/749.html) / A05:2021 |
| JAVA036 | WebView даёт file URL доступ к сети | java, kotlin | high | [CWE-346](https://cwe.mitre.org/data/definitions/346.html) / A05:2021 |
| JAVA037 | Слабый размер RSA-ключа Java | java, kotlin | high | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 |

## PHP: 6 правил

| ID | Проверка | Языки | Риск | CWE / OWASP |
|---|---|---|---|---|
| PHP030 | PHP XML разрешает сущности и DTD | php | high | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) / A05:2021 |
| PHP031 | Выполнение выражения через preg_replace | php | critical | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) / A03:2021 |
| PHP032 | Слабая генерация security-токена PHP | php | medium | [CWE-338](https://cwe.mitre.org/data/definitions/338.html) / A02:2021 |
| PHP033 | Небезопасный redirect PHP | php | medium | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) / A01:2021 |
| PHP034 | Ослаблены сессионные cookie PHP | php | medium | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) / A07:2021 |
| PHP035 | LDAP-инъекция PHP | php | high | [CWE-90](https://cwe.mitre.org/data/definitions/90.html) / A03:2021 |

## GO: 6 правил

| ID | Проверка | Языки | Риск | CWE / OWASP |
|---|---|---|---|---|
| GO030 | Слабый минимальный TLS в Go | go | high | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 |
| GO031 | Устаревший шифр Go | go | high | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) / A02:2021 |
| GO032 | Слабый RSA-ключ Go | go | high | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 |
| GO033 | SSH без проверки host key | go | high | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 |
| GO034 | Открытый файловый сервер Go | go | high | [CWE-552](https://cwe.mitre.org/data/definitions/552.html) / A05:2021 |
| GO035 | text/template в Go HTTP-коде | go | medium | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) / A03:2021 |

## CS: 6 правил

| ID | Проверка | Языки | Риск | CWE / OWASP |
|---|---|---|---|---|
| CS030 | HttpClient принимает любой сертификат | csharp | high | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 |
| CS031 | SQL через интерполяцию в EF Core | csharp | critical | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 |
| CS032 | LDAP-фильтр через конкатенацию .NET | csharp | high | [CWE-90](https://cwe.mitre.org/data/definitions/90.html) / A03:2021 |
| CS033 | Устаревший шифр .NET | csharp | high | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) / A02:2021 |
| CS034 | Обход HTML-экранирования Razor | csharp | high | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) / A03:2021 |
| CS035 | Отключена antiforgery-проверка ASP.NET | csharp | medium | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) / A01:2021 |

## RB: 4 правил

| ID | Проверка | Языки | Риск | CWE / OWASP |
|---|---|---|---|---|
| RB030 | Обход HTML-экранирования Rails | ruby | high | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) / A03:2021 |
| RB031 | Массовое присваивание всех параметров Rails | ruby | high | [CWE-915](https://cwe.mitre.org/data/definitions/915.html) / A01:2021 |
| RB032 | Отключена CSRF-защита Rails | ruby | medium | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) / A01:2021 |
| RB033 | Ruby OpenSSL не проверяет сертификат | ruby | high | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 |

## RS: 4 правил

| ID | Проверка | Языки | Риск | CWE / OWASP |
|---|---|---|---|---|
| RS030 | Rust OpenSSL не проверяет сертификат | rust | high | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 |
| RS031 | Небезопасный SHA-1 в Rust | rust | medium | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) / A02:2021 |
| RS032 | SQL-инъекция rusqlite | rust | critical | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 |
| RS033 | Rust создаёт общедоступный файл | rust | high | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) / A05:2021 |

## SWIFT: 4 правил

| ID | Проверка | Языки | Риск | CWE / OWASP |
|---|---|---|---|---|
| SWIFT030 | Keychain доступен при блокировке | swift | high | [CWE-922](https://cwe.mitre.org/data/definitions/922.html) / A05:2021 |
| SWIFT031 | ECB в CommonCrypto | swift | high | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) / A02:2021 |
| SWIFT032 | SQL-интерполяция Swift | swift | critical | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 |
| SWIFT033 | Небезопасное unarchive Swift | swift | high | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) / A08:2021 |

## SCALA: 4 правил

| ID | Проверка | Языки | Риск | CWE / OWASP |
|---|---|---|---|---|
| SCALA030 | Слабая генерация security-токена Scala | scala | medium | [CWE-338](https://cwe.mitre.org/data/definitions/338.html) / A02:2021 |
| SCALA031 | Play WS не проверяет hostname | scala | high | [CWE-297](https://cwe.mitre.org/data/definitions/297.html) / A02:2021 |
| SCALA032 | Неэкранированный HTML в Play | scala | high | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) / A03:2021 |
| SCALA033 | Play WS принимает любой сертификат | scala | high | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 |

## SH: 4 правил

| ID | Проверка | Языки | Риск | CWE / OWASP |
|---|---|---|---|---|
| SH030 | SSH без проверки host key | shell | high | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 |
| SH031 | Отключён known_hosts SSH | shell | medium | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 |
| SH032 | Общедоступная umask | shell | high | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) / A05:2021 |
| SH033 | Пароль в аргументах shell-команды | shell | high | [CWE-214](https://cwe.mitre.org/data/definitions/214.html) / A07:2021 |

## CFG: 14 правил

| ID | Проверка | Языки | Риск | CWE / OWASP |
|---|---|---|---|---|
| CFG030 | Kubernetes отключает non-root policy | config | medium | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) / A05:2021 |
| CFG031 | Kubernetes монтирует hostPath | config | medium | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) / A05:2021 |
| CFG032 | Kubernetes получает SYS_PTRACE | config | high | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) / A05:2021 |
| CFG033 | AppArmor контейнера отключён | config | high | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) / A05:2021 |
| CFG034 | Docker использует host PID | config | high | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) / A05:2021 |
| CFG035 | GitHub Actions выдаёт write-all | config | high | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) / A01:2021 |
| CFG036 | GitHub Actions исполняет текст события | config | high | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) / A03:2021 |
| CFG037 | Отключён TLS PostgreSQL-клиента | config | high | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 |
| CFG038 | Android разрешает cleartext traffic | config | medium | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 |
| CFG039 | CSP разрешает unsafe-eval | config | medium | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) / A05:2021 |
| CFG040 | Android debug включён в manifest | config | high | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) / A05:2021 |
| CFG041 | IAM разрешает все действия | config | high | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) / A01:2021 |
| CFG042 | Публичный ACL хранилища | config | high | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) / A01:2021 |
| CFG043 | Dockerfile загружает удалённый ADD | config | medium | [CWE-494](https://cwe.mitre.org/data/definitions/494.html) / A05:2021 |

## Документация для проверки правил

- [Electron security](https://www.electronjs.org/docs/latest/tutorial/security): настройки renderer и изоляция.
- [Microsoft security analyzers](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/security-warnings): SQL, XML, криптография и TLS в .NET.
- [Rails security](https://guides.rubyonrails.org/security.html): CSRF, strong parameters и HTML-экранирование.
- [Bandit SSH host keys](https://bandit.readthedocs.io/en/1.5.1/plugins/b507_ssh_no_host_key_verification.html): Paramiko AutoAddPolicy.
- [pandas read_pickle](https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.read_pickle.html): риск недоверенного Pickle.
- [PyTorch serialization](https://docs.pytorch.org/docs/stable/notes/serialization): weights_only и десериализация моделей.
- [PHP session security](https://www.php.net/manual/en/session.security.ini.php): флаги сессионных cookie.
- [Go TLS](https://pkg.go.dev/crypto/tls): настройка версии протокола.
- [Play SSLLooseConfig](https://www.playframework.com/documentation/2.4.7/api/scala/play/api/libs/ws/ssl/SSLLooseConfig.html): проверка сертификата и hostname.
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/): capabilities, hostPath, seccomp и AppArmor.
- [Docker ADD](https://docs.docker.com/reference/dockerfile/#add---checksum): проверка целостности удалённых ресурсов.
- [GitLab detected secrets](https://docs.gitlab.com/user/application_security/secret_detection/detected_secrets/): форматы credentials.
