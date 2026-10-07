# CodeSentry Local SAST

Команды модульных и интеграционных тестов и границы отчёта покрытия:
[тестирование](docs/testing.md).

Две крупные SQL-миграции хранятся через Git LFS. Перед клонированием
установите Git LFS (`git lfs install`); для уже клонированного репозитория
выполните `git lfs pull` перед сборкой и запуском миграций.

Локальный анализатор исходного кода. При работе через интерфейс исходники
анализируются в браузере; результаты сохраняются на сервере в истории.
При вызове API исходники передаются на сервер приложения для анализа.

## Требования

- Node.js 22.13 или новее

## Запуск

```bash
npm install
npm run dev
```

Откройте адрес, который появится в терминале.

## Возможности

- загрузка файла до 1 МБ, ZIP-архива проекта до 10 МБ или вставка фрагмента кода;
- локальная распаковка и совместный анализ до 500 исходников из ZIP с путём файла в JSON/SARIF;
- подсчёт физических строк проверенных исходников (включая комментарии и пустые строки)
  с отображением в результатах SAST и истории и сохранением в `scan_runs.scanned_lines`
  после завершения сканирования; пустой файл содержит 0 строк, завершающий перенос
  не добавляет строку, пропущенные файлы ZIP не учитываются;
- 20 групп языков и форматов: JavaScript, TypeScript, Python, Java, PHP, Go, C#, Ruby,
  Kotlin, Rust, Swift, Scala, Shell, C, C++, Dart, Elixir, Lua, PowerShell и конфигурационные файлы;
- 150036 статических правил для поиска секретов, SQL/NoSQL/command/template/LDAP-инъекций,
  XSS, SSRF, XXE, path traversal, prototype pollution, небезопасной
  десериализации, слабой криптографии, TLS/JWT/cookie-ошибок и опасных
  container/runtime-настроек;
- проверки XMLDecoder, Newtonsoft.Json TypeNameHandling, обработки DTD,
  экранирования Jinja, SSL-контекстов Python, TLS в PHP cURL, shell в Node.js,
  монтирования Docker socket, опасных capabilities и отключения seccomp;
- сигнатуры токенов AWS, GitHub, GitLab, Slack, npm, Stripe, SendGrid, Google API,
  Azure Storage, JWT, приватных ключей и URI баз данных;
- проверки CSRF в Django/Spring/Rails/ASP.NET, Electron и Android WebView,
  SSH host keys, IAM/S3 policies и GitHub Actions;
  [каталог набора из 86 правил](docs/security-rules.md), [каталог ещё 200 правил](docs/security-rules-expansion.md),
  [каталог следующих 300 правил](docs/security-rules-additional.md)
  и [каталог ещё 300 правил](docs/security-rules-advanced.md);
- загрузка Vue/Svelte и конфигураций `.conf`, `.ini`, `.toml`, `.tf`, `.hcl`, `.plist`;
- загрузка исходников и заголовков C/C++, `.dart`, `.ex`/`.exs`, `.lua`,
  `.ps1`/`.psm1`/`.psd1`; [36 проверок новых языков](docs/security-rules-coverage.md)
  включают секреты, опасные операции с памятью, shell, SQL, TLS и динамическим кодом;
- дополнительные проверки JWT claims/signatures, password hashing, Java XML/JNDI/XSLT,
  Rails/Play/Actix, gRPC, Phar/Psych/Oj и конфигураций Nginx/HAProxy/Redis/MongoDB/Elasticsearch;
- многострочные правила и лёгкий межстрочный source-to-sink анализ потоков
  недоверенных данных;
- привязка находок к CWE и OWASP;
- фильтрация по серьёзности, контекст и рекомендации по исправлению;
- экспорт JSON и SARIF 2.1.0 для GitHub Code Scanning и CI;
- анализ в браузере или на сервере через API, сохранение результатов в PostgreSQL.

## Ограничения

CodeSentry выполняет быстрый эвристический анализ в браузере и не строит полный
AST/CFG проекта. Он может выдавать ложные срабатывания и не видит зависимости
между файлами. Для защиты production-проекта дополняйте его dependency/secret
scanning, компиляторным SAST, DAST, fuzzing и ручным code review.

Из архивов анализируются поддерживаемые текстовые файлы размером до 1 МБ каждый
(не более 20 МБ после распаковки). Каталоги зависимостей и сборки, включая
`node_modules`, `vendor`, `dist` и `build`, пропускаются.

## Проверка

```bash
npm run lint
npm test
```

Автоматический анализ не заменяет ручной аудит, dependency scanning и code review.

## API проверки ZIP-архива

Авторизованный пользователь может отправить архив исходного кода в
`POST /api/scans/archive` как `multipart/form-data`. Обязательные поля:

- `archive` — ZIP-архив размером до 10 МБ;
- `release` — идентификатор вида `test-456`.

Поле `projectName` необязательно; без него используется имя архива. Результат
сохраняется в истории и возвращается в ответе вместе с `scanId`, сводкой и
массивом находок.

```bash
curl -c cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-password"}' \
  http://localhost/api/auth/login

curl -b cookies.txt \
  -F "archive=@project.zip;type=application/zip" \
  -F "release=TEST-1" \
  -F "projectName=Example project" \
  http://localhost/api/scans/archive
```

## API проверки исходников через JSON

`POST /api/scans/json` запускает SAST-анализ исходников на сервере и сохраняет
результат в истории. Нужна сессия авторизованного пользователя (cookie после
`POST /api/auth/login`, как в примере выше) и `Content-Type: application/json`.
Все три поля обязательны:

```json
{
  "projectName": "Example project",
  "release": "TEST-1",
  "files": [
    { "name": "src/app.js", "code": "eval(req.query.code);\n" },
    { "name": "src/main.py", "code": "print('hello')\n" }
  ]
}
```

Сохраните JSON в `request.json` в UTF-8 и отправьте:

```bash
curl -b cookies.txt \
  -H "Content-Type: application/json" \
  --data-binary @request.json \
  http://localhost/api/scans/json
```

`projectName` — 1–512 символов; `release` — 2–4 латинские буквы, дефис и число
1–9999. `files` — от 1 до 500 файлов; каждый содержит относительный путь `name`
и строку `code` (допускается пустой файл). Язык определяется по имени и коду.
Пути должны быть уникальными, без `..`; поддерживаются те же расширения,
что при загрузке исходников через интерфейс. Все явно переданные файлы
анализируются, включая тесты и файлы из каталогов зависимостей.
Лимиты: 1 МБ UTF-8 на файл, 20 МБ исходников суммарно, 25 МБ на всё тело JSON.
Символы переноса строки и кавычки в `code` должны быть экранированы по правилам JSON.

Успешный ответ: `201`, поля `scanId`, `createdAt`, `version`, `projectName`,
`release`, `language`, `filesScanned`, `scannedLines`, `durationMs`, `summary`
и `findings`. Результат доступен также через `GET /api/scans?id=<scanId>`.
Ошибки возвращаются как `{ "error": "описание" }`: `400` — некорректный JSON
или поля, `401` — нет сессии, `413` — превышен размер или количество файлов,
`415` — неверный Content-Type, `500` — ошибка анализа или сохранения.

`POST /api/scans` по-прежнему сохраняет уже готовый отчёт; для запуска анализа
используйте `/api/scans/json` или `/api/scans/archive`.

## Docker Compose + PostgreSQL

Каталог текущих 150000 SAST-правил также хранится в отдельной схеме `sast_rules`.
Из них 149000 — сочетания 400 записей опасных API со способами доступа к HTTP-вводу
и формами составных строк.
Дополнительные 15000 определений описаны в [каталоге фреймворков](docs/security-rules-framework.md).
Исходный HTTP-набор из 4000 определений покрывает 400 опасных API × 10 источников HTTP-ввода
в JavaScript/TypeScript, Python, PHP и Ruby; ограничения описаны в [каталоге HTTP](docs/security-rules-http.md).
Её создаёт и наполняет миграция; повторный импорт: `npm run rules:seed`.
Структура, версионирование и SQL-запросы: [каталог правил в БД](docs/sast-rule-database.md).
Подключение сканера к этому каталогу пока не выполнено — анализ использует
встроенный набор правил.

Build a new image with a unique application version:

```bash
npm run image:build
```

To build and push `shmatdmi/codesentry-sast:latest` to Docker Hub, use
`npm run image:publish`.

The command generates a version such as `1.1.0+build.20260920T123456789Z` and
passes it to Docker. The deployed version is shown in the UI and returned by
`GET /api/health`. Set the `APP_BUILD_VERSION` build argument to use an explicit
version in CI.

1. Create the environment file: `Copy-Item .env.example .env` (or `cp .env.example .env` on Linux).
2. Replace `POSTGRES_PASSWORD` and `INITIAL_ADMIN_PASSWORD` in `.env` with long random passwords.
3. Start the stack: `docker compose up -d --build`.
4. Check it: `docker compose ps` and open `http://localhost:3000/api/health`.

PostgreSQL is available only inside the Compose network and does not publish port 5432 on the host, so it does not conflict with another PostgreSQL container on the server. Data is stored in the named volume `codesentry-sast_sast_postgres_data`. Migrations run automatically before the application starts.

The first login creates the initial administrator from `INITIAL_ADMIN_USERNAME`
and `INITIAL_ADMIN_PASSWORD`. Further accounts are managed in the
**Пользователи** section. When the service is exposed through HTTPS, set
`AUTH_COOKIE_SECURE=true`; leave it `false` only for the current plain-HTTP
deployment.

To expose the application on another host port, set `APP_PORT` in `.env`. Do not delete the database volume unless the stored scan metadata is no longer needed.

Ещё 50000 определений для составных строк описаны в [каталоге](docs/security-rules-composed.md).

Набор до 150000 расширен ещё на 80000 форм выражений: [каталог](docs/security-rules-expressions.md).
