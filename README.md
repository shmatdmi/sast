# CodeSentry Local SAST

Локальный анализатор исходного кода, который работает целиком в браузере. Код и
загруженные файлы не отправляются на сервер.

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
- автоопределение JavaScript, TypeScript, Python, Java, PHP, Go, C#, Ruby,
  Kotlin, Rust, Swift, Scala, Shell и конфигурационных файлов;
- более 50 правил для поиска секретов, SQL/NoSQL/command/template-инъекций,
  XSS, SSRF, XXE, path traversal, prototype pollution, небезопасной
  десериализации, слабой криптографии, TLS/JWT/cookie-ошибок и опасных
  container/runtime-настроек;
- сигнатуры токенов AWS, GitHub, Slack, JWT, приватных ключей и URI баз данных;
- многострочные правила и лёгкий межстрочный source-to-sink анализ потоков
  недоверенных данных;
- привязка находок к CWE и OWASP;
- фильтрация по серьёзности, контекст и рекомендации по исправлению;
- экспорт JSON и SARIF 2.1.0 для GitHub Code Scanning и CI;
- полностью локальный анализ без базы данных и серверной загрузки файлов.

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

## Docker Compose + PostgreSQL

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
2. Replace `POSTGRES_PASSWORD` in `.env` with a long random password.
3. Start the stack: `docker compose up -d --build`.
4. Check it: `docker compose ps` and open `http://localhost:3000/api/health`.

PostgreSQL is available only inside the Compose network and does not publish port 5432 on the host, so it does not conflict with another PostgreSQL container on the server. Data is stored in the named volume `codesentry-sast_sast_postgres_data`. Migrations run automatically before the application starts.

To expose the application on another host port, set `APP_PORT` in `.env`. Do not delete the database volume unless the stored scan metadata is no longer needed.
