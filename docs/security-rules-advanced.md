# Ещё 300 SAST-правил

Общая база: **150036 статических правил** и 6 отдельных source-to-sink проверок.
Этот набор находится в app/lib/sast-rules-advanced.ts, ID начинаются с 300.
Правила подключены к общему движку браузера и API; находки входят в JSON/SARIF и историю.
Обновление каталогов: npm run rules:catalog.

Все проверки эвристические: регулярные выражения не строят AST, не разрешают алиасы
и не доказывают эксплуатацию. Комментарии и строковые примеры также могут совпасть.
Проверки unsafe API требуют анализа доверия к данным; инфраструктурные политики,
аудит и резервные копии требуют оценки production окружения. Legacy API учитываются
для старых проектов. Ограниченные шаблоны вызовов не покрывают все формы записи
вложенных аргументов и переносов строк. Безопасная альтернатива относится к конкретной
проверке и не доказывает безопасность всего приложения.
Сигнатуры токенов проверяют формат без сетевой валидации действительности credential.

## Распределение

| Семейство | Правил |
|---|---:|
| SEC | 40 |
| JS | 25 |
| PY | 25 |
| JAVA | 25 |
| PHP | 20 |
| GO | 20 |
| CS | 20 |
| RB | 15 |
| RS | 15 |
| SWIFT | 10 |
| SCALA | 10 |
| SH | 15 |
| CFG | 60 |

## SEC

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| SEC300 | Personal access token Airtable | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC301 | Reference token Artifactory | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC302 | Access key Authress | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC303 | Long-lived API key Amazon Bedrock | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC304 | Cloud secret key ClickHouse | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC305 | Deploy token Clojars | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC306 | Origin CA key Cloudflare | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC307 | OAuth access token DigitalOcean | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC308 | OAuth refresh token DigitalOcean | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC309 | Live API token Duffel | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC310 | API token Dynatrace | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC311 | Production API token EasyPost | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC312 | Access token Fly.io | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC313 | API token Frame.io | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC314 | CI job token GitLab | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC315 | Deploy token GitLab | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC316 | Incoming mail token GitLab | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC317 | Kubernetes agent token GitLab | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC318 | OAuth application secret GitLab | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC319 | Pipeline trigger token GitLab | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC320 | Legacy runner registration token GitLab | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC321 | Runner authentication token GitLab | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC322 | SCIM token GitLab | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC323 | Cloud API token Grafana | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC324 | API key Harness | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC325 | API token Terraform Cloud | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC326 | API key Heroku v2 | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC327 | Access token Hugging Face | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC328 | Organization token Hugging Face | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC329 | API token Infracost | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC330 | Client secret Intra42 | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC331 | API key Linear | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC332 | API token Notion | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC333 | API key Octopus Deploy | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC334 | API key Perplexity | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC335 | API token PlanetScale | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC336 | OAuth token PlanetScale | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC337 | Пароль PlanetScale | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC338 | API token Prefect | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |
| SEC339 | API token RubyGems | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите найденный токен или смените ключ/пароль, проверьте доступ и загрузите новое значение из хранилища секретов. |

## JS

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| JS300 | Fastify сериализует HTTP schema | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) / A03:2021 | critical / medium | Безопасная альтернатива: reply.compileSerializationSchema(profileSchema); Проверьте доверие к данным и применимость настройки в production. |
| JS301 | Fastify валидатор HTTP schema | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) / A03:2021 | critical / medium | Безопасная альтернатива: request.compileValidationSchema(profileSchema); Проверьте доверие к данным и применимость настройки в production. |
| JS302 | AJV компилирует HTTP schema | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) / A03:2021 | critical / medium | Безопасная альтернатива: ajv.compile(profileSchema); Проверьте доверие к данным и применимость настройки в production. |
| JS303 | Express выбирает HTTP view | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: res.render('profile', model); Проверьте доверие к данным и применимость настройки в production. |
| JS304 | Pug renderFile HTTP путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: pug.renderFile(approvedTemplate); Проверьте доверие к данным и применимость настройки в production. |
| JS305 | EJS renderFile HTTP путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: ejs.renderFile(approvedTemplate); Проверьте доверие к данным и применимость настройки в production. |
| JS306 | Nunjucks render HTTP имя | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: nunjucks.render('profile.njk', model); Проверьте доверие к данным и применимость настройки в production. |
| JS307 | Sequelize fn HTTP функция | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: Sequelize.fn('COUNT', col); Проверьте доверие к данным и применимость настройки в production. |
| JS308 | Knex orderByRaw HTTP строка | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: query.orderBy('created_at', 'desc'); Проверьте доверие к данным и применимость настройки в production. |
| JS309 | Knex whereRaw HTTP строка | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: query.where('id', validatedId); Проверьте доверие к данным и применимость настройки в production. |
| JS310 | Knex havingRaw HTTP строка | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: query.having('count', '&gt;', validatedCount); Проверьте доверие к данным и применимость настройки в production. |
| JS311 | Knex joinRaw HTTP строка | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: query.join('profiles', 'profiles.id', 'users.id'); Проверьте доверие к данным и применимость настройки в production. |
| JS312 | TypeORM orderBy HTTP выражение | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: qb.orderBy('user.createdAt', 'DESC'); Проверьте доверие к данным и применимость настройки в production. |
| JS313 | TypeORM addSelect HTTP выражение | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: qb.addSelect('user.name'); Проверьте доверие к данным и применимость настройки в production. |
| JS314 | Needle HTTP URL | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: needle.get(allowedUrl, callback); Проверьте доверие к данным и применимость настройки в production. |
| JS315 | Node net.connect HTTP адрес | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: net.connect({ host: allowedHost, port: 443 }); Проверьте доверие к данным и применимость настройки в production. |
| JS316 | Got HTTP URL | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: got(allowedUrl); Проверьте доверие к данным и применимость настройки в production. |
| JS317 | Undici HTTP URL | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: undici.request(allowedUrl); Проверьте доверие к данным и применимость настройки в production. |
| JS318 | Superagent HTTP URL | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: superagent.get(allowedUrl); Проверьте доверие к данным и применимость настройки в production. |
| JS319 | WebSocket HTTP адрес | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: new WebSocket(allowedUrl); Проверьте доверие к данным и применимость настройки в production. |
| JS320 | Socket.IO слишком большой HTTP buffer | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) / A01:2021 | medium / medium | Безопасная альтернатива: new Server({ maxHttpBufferSize: 65536 }); Проверьте доверие к данным и применимость настройки в production. |
| JS321 | Multer не ограничивает fileSize | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) / A01:2021 | medium / medium | Безопасная альтернатива: multer({ limits: { fileSize: 1048576 } }); Проверьте доверие к данным и применимость настройки в production. |
| JS322 | Crypto scrypt отключает стоимость | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Безопасная альтернатива: crypto.scryptSync(password, salt, 32, calibratedParameters); Проверьте доверие к данным и применимость настройки в production. |
| JS323 | Node RSA PKCS1 v1.5 padding | [CWE-780](https://cwe.mitre.org/data/definitions/780.html) / A02:2021 | medium / medium | Безопасная альтернатива: crypto.publicEncrypt({ key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, data); Проверьте доверие к данным и применимость настройки в production. |
| JS324 | JWT допускает слабые RSA ключи | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 | high / medium | Безопасная альтернатива: jwt.sign(payload, strongKey, { algorithm: 'RS256', allowInsecureKeySizes: false }); Проверьте доверие к данным и применимость настройки в production. |

## PY

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| PY300 | Python os.spawnl HTTP executable | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) / A03:2021 | critical / medium | Безопасная альтернатива: run_allowed_program(program_id) Проверьте доверие к данным и применимость настройки в production. |
| PY301 | Python os.posix_spawn HTTP executable | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) / A03:2021 | critical / medium | Безопасная альтернатива: os.posix_spawn('/usr/bin/tool', checked_argv, clean_env) Проверьте доверие к данным и применимость настройки в production. |
| PY302 | Python subprocess cwd HTTP путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: subprocess.run(['/usr/bin/tool'], cwd=allowed_directory) Проверьте доверие к данным и применимость настройки в production. |
| PY303 | Python ctypes загружает HTTP библиотеку | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) / A03:2021 | medium / medium | Безопасная альтернатива: ctypes.CDLL(approved_library) Проверьте доверие к данным и применимость настройки в production. |
| PY304 | Python ctypes PyDLL HTTP библиотека | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) / A03:2021 | medium / medium | Безопасная альтернатива: ctypes.PyDLL(approved_library) Проверьте доверие к данным и применимость настройки в production. |
| PY305 | Python import spec HTTP путь | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) / A03:2021 | medium / medium | Безопасная альтернатива: importlib.util.spec_from_file_location('plugin', approved_path) Проверьте доверие к данным и применимость настройки в production. |
| PY306 | Python Pydantic обходит HTTP validation | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) / A01:2021 | medium / medium | Безопасная альтернатива: Profile.model_validate(request.json) Проверьте доверие к данным и применимость настройки в production. |
| PY307 | Python Jinja from_string HTTP шаблон | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) / A03:2021 | critical / medium | Безопасная альтернатива: environment.get_template('profile.html') Проверьте доверие к данным и применимость настройки в production. |
| PY308 | Python Bottle SimpleTemplate HTTP шаблон | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) / A03:2021 | critical / medium | Безопасная альтернатива: SimpleTemplate(name='profile') Проверьте доверие к данным и применимость настройки в production. |
| PY309 | Python Tornado HTTP template path | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: self.render('profile.html') Проверьте доверие к данным и применимость настройки в production. |
| PY310 | Python Django database raw cursor | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: cursor.execute('select * from users where id=?', [id]) Проверьте доверие к данным и применимость настройки в production. |
| PY311 | Python psycopg AsIs HTTP SQL | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: sql.Identifier(allowed_column) Проверьте доверие к данным и применимость настройки в production. |
| PY312 | Python SQLAlchemy literal_column HTTP | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: table.c.name Проверьте доверие к данным и применимость настройки в production. |
| PY313 | Python Psycopg SQL HTTP строка | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: sql.SQL('SELECT * FROM users WHERE id = %s') Проверьте доверие к данным и применимость настройки в production. |
| PY314 | Python Peewee SQL HTTP | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: User.id == validated_id Проверьте доверие к данным и применимость настройки в production. |
| PY315 | Python LDAP search HTTP фильтр | [CWE-90](https://cwe.mitre.org/data/definitions/90.html) / A03:2021 | medium / medium | Безопасная альтернатива: conn.search_s(base, ldap.SCOPE_SUBTREE, escaped_filter) Проверьте доверие к данным и применимость настройки в production. |
| PY316 | Python pymongo $where HTTP | [CWE-943](https://cwe.mitre.org/data/definitions/943.html) / A03:2021 | medium / medium | Безопасная альтернатива: users.find({'id': validated_id}) Проверьте доверие к данным и применимость настройки в production. |
| PY317 | Python shutil copyfile HTTP путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: shutil.copyfile(allowed_source, destination) Проверьте доверие к данным и применимость настройки в production. |
| PY318 | Python pathlib unlink HTTP путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: allowed_path.unlink() Проверьте доверие к данным и применимость настройки в production. |
| PY319 | Python ZipFile HTTP архив | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: zipfile.ZipFile(approved_upload) Проверьте доверие к данным и применимость настройки в production. |
| PY320 | Python socket HTTP адрес | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: socket.create_connection((allowed_host, 443)) Проверьте доверие к данным и применимость настройки в production. |
| PY321 | Python ftplib HTTP host | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: ftplib.FTP(allowed_host) Проверьте доверие к данным и применимость настройки в production. |
| PY322 | Python PBKDF2 мало итераций | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Безопасная альтернатива: hashlib.pbkdf2_hmac('sha256', password, salt, calibrated_iterations) Проверьте доверие к данным и применимость настройки в production. |
| PY323 | Python Argon2 отключает time_cost | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Безопасная альтернатива: PasswordHasher(time_cost=calibrated_cost, memory_cost=calibrated_memory) Проверьте доверие к данным и применимость настройки в production. |
| PY324 | Python логирует HTTP session cookie | [CWE-532](https://cwe.mitre.org/data/definitions/532.html) / A09:2021 | medium / medium | Безопасная альтернатива: logger.info('request completed') Проверьте доверие к данным и применимость настройки в production. |

## JAVA

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| JAVA300 | Java JEXL createScript HTTP код | [CWE-917](https://cwe.mitre.org/data/definitions/917.html) / A03:2021 | critical / medium | Безопасная альтернатива: dispatchAllowedAction(action); Проверьте доверие к данным и применимость настройки в production. |
| JAVA301 | Java SpEL parseRaw HTTP выражение | [CWE-917](https://cwe.mitre.org/data/definitions/917.html) / A03:2021 | critical / medium | Безопасная альтернатива: parser.parseRaw("profile.name"); Проверьте доверие к данным и применимость настройки в production. |
| JAVA302 | Java BeanShell source HTTP файл | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) / A03:2021 | critical / medium | Безопасная альтернатива: dispatchAllowedAction(action); Проверьте доверие к данным и применимость настройки в production. |
| JAVA303 | Java BeanUtils mass assignment HTTP | [CWE-915](https://cwe.mitre.org/data/definitions/915.html) / A03:2021 | medium / medium | Безопасная альтернатива: BeanUtils.populate(user, allowedFields); Проверьте доверие к данным и применимость настройки в production. |
| JAVA304 | Java Grape dependency HTTP координаты | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) / A03:2021 | medium / medium | Безопасная альтернатива: loadApprovedDependency(dependencyId); Проверьте доверие к данным и применимость настройки в production. |
| JAVA305 | Java XML external general entities | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) / A05:2021 | high / medium | Безопасная альтернатива: factory.setFeature("http://xml.org/sax/features/external-general-entities", false); Проверьте доверие к данным и применимость настройки в production. |
| JAVA306 | Java XML external parameter entities | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) / A05:2021 | high / medium | Безопасная альтернатива: factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false); Проверьте доверие к данным и применимость настройки в production. |
| JAVA307 | Java XML загружает external DTD | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) / A05:2021 | high / medium | Безопасная альтернатива: factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false); Проверьте доверие к данным и применимость настройки в production. |
| JAVA308 | Java XML отключает secure processing | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) / A05:2021 | high / medium | Безопасная альтернатива: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true); Проверьте доверие к данным и применимость настройки в production. |
| JAVA309 | Java XML external schema unrestricted | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) / A05:2021 | high / medium | Безопасная альтернатива: schema.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, ""); Проверьте доверие к данным и применимость настройки в production. |
| JAVA310 | Java XML external DTD unrestricted | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) / A05:2021 | high / medium | Безопасная альтернатива: factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, ""); Проверьте доверие к данным и применимость настройки в production. |
| JAVA311 | Java Netty доверяет всем certificates | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 | high / medium | Безопасная альтернатива: SslContextBuilder.forClient().trustManager(caFile); Проверьте доверие к данным и применимость настройки в production. |
| JAVA312 | Java Kafka отключает hostname check | [CWE-297](https://cwe.mitre.org/data/definitions/297.html) / A02:2021 | high / medium | Безопасная альтернатива: props.put("ssl.endpoint.identification.algorithm", "https"); Проверьте доверие к данным и применимость настройки в production. |
| JAVA313 | Java TLS явно включает TLSv1 | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 | high / medium | Безопасная альтернатива: socket.setEnabledProtocols(new String[]{"TLSv1.3"}); Проверьте доверие к данным и применимость настройки в production. |
| JAVA314 | Java BCrypt низкая стоимость | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Безопасная альтернатива: new BCryptPasswordEncoder(calibratedCost); Проверьте доверие к данным и применимость настройки в production. |
| JAVA315 | Java PBKDF2 низкие iterations | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Безопасная альтернатива: new PBEKeySpec(password, salt, calibratedIterations, 256); Проверьте доверие к данным и применимость настройки в production. |
| JAVA316 | Java scrypt низкий CPU cost | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Безопасная альтернатива: new SCryptPasswordEncoder(calibratedN, 8, 1, 32, 16); Проверьте доверие к данным и применимость настройки в production. |
| JAVA317 | Java Spring CORS setAllowedOrigins wildcard | [CWE-942](https://cwe.mitre.org/data/definitions/942.html) / A05:2021 | medium / medium | Безопасная альтернатива: cors.setAllowedOrigins(List.of("https://app.example")); Проверьте доверие к данным и применимость настройки в production. |
| JAVA318 | Java Spring CORS all Origin | [CWE-942](https://cwe.mitre.org/data/definitions/942.html) / A05:2021 | medium / medium | Безопасная альтернатива: @CrossOrigin(origins = "https://app.example") Проверьте доверие к данным и применимость настройки в production. |
| JAVA319 | Java RedirectView HTTP URL | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) / A01:2021 | medium / medium | Безопасная альтернатива: new RedirectView("/home"); Проверьте доверие к данным и применимость настройки в production. |
| JAVA320 | Java JAX-RS location HTTP URL | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) / A01:2021 | medium / medium | Безопасная альтернатива: Response.status(302).location(URI.create("/home")); Проверьте доверие к данным и применимость настройки в production. |
| JAVA321 | Java FileUtils HTTP URL | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: FileUtils.copyURLToFile(new URL(allowedUrl), target); Проверьте доверие к данным и применимость настройки в production. |
| JAVA322 | Java Apache HttpGet HTTP URL | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: new HttpGet(allowedUrl); Проверьте доверие к данным и применимость настройки в production. |
| JAVA323 | Java Socket HTTP host | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: new Socket(allowedHost, 443); Проверьте доверие к данным и применимость настройки в production. |
| JAVA324 | Java logger раскрывает HTTP cookies | [CWE-532](https://cwe.mitre.org/data/definitions/532.html) / A09:2021 | medium / medium | Безопасная альтернатива: logger.info("request completed"); Проверьте доверие к данным и применимость настройки в production. |

## PHP

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| PHP300 | PHP Laravel selectRaw HTTP строка | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: $query-&gt;select(['id', 'name']); Проверьте доверие к данным и применимость настройки в production. |
| PHP301 | PHP Laravel havingRaw HTTP строка | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: $query-&gt;having('count', '&gt;', $validatedCount); Проверьте доверие к данным и применимость настройки в production. |
| PHP302 | PHP Laravel groupByRaw HTTP строка | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: $query-&gt;groupBy('country'); Проверьте доверие к данным и применимость настройки в production. |
| PHP303 | PHP Doctrine DQL HTTP строка | [CWE-564](https://cwe.mitre.org/data/definitions/564.html) / A03:2021 | medium / medium | Безопасная альтернатива: $em-&gt;createQuery('SELECT u FROM User u WHERE u.id = :id'); Проверьте доверие к данным и применимость настройки в production. |
| PHP304 | PHP Doctrine DBAL HTTP SQL | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: $db-&gt;executeQuery('SELECT * FROM users WHERE id = ?', [$id]); Проверьте доверие к данным и применимость настройки в production. |
| PHP305 | PHP Doctrine executeStatement HTTP SQL | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: $db-&gt;executeStatement('DELETE FROM users WHERE id = ?', [$id]); Проверьте доверие к данным и применимость настройки в production. |
| PHP306 | PHP Twig load HTTP шаблон | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: $twig-&gt;load('profile.html.twig'); Проверьте доверие к данным и применимость настройки в production. |
| PHP307 | PHP Smarty fetch HTTP шаблон | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: $smarty-&gt;fetch('profile.tpl'); Проверьте доверие к данным и применимость настройки в production. |
| PHP308 | PHP file HTTP путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: file($allowedPath); Проверьте доверие к данным и применимость настройки в production. |
| PHP309 | PHP stream_socket_client HTTP адрес | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: stream_socket_client($allowedAddress); Проверьте доверие к данным и применимость настройки в production. |
| PHP310 | PHP fsockopen HTTP host | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: fsockopen($allowedHost, 443); Проверьте доверие к данным и применимость настройки в production. |
| PHP311 | PHP ftp_connect HTTP host | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: ftp_connect($allowedHost); Проверьте доверие к данным и применимость настройки в production. |
| PHP312 | PHP ZipArchive extractTo HTTP каталог | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: extract_checked_entries($zip, $allowedDirectory); Проверьте доверие к данным и применимость настройки в production. |
| PHP313 | PHP rename HTTP назначение | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: rename($source, $allowedPath); Проверьте доверие к данным и применимость настройки в production. |
| PHP314 | PHP chmod HTTP путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: chmod($allowedPath, 0600); Проверьте доверие к данным и применимость настройки в production. |
| PHP315 | PHP chown HTTP путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: chown($allowedPath, $owner); Проверьте доверие к данным и применимость настройки в production. |
| PHP316 | PHP password_hash слабый Argon2 memory | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Безопасная альтернатива: password_hash($password, PASSWORD_ARGON2ID, ['memory_cost' =&gt; $calibratedMemory]); Проверьте доверие к данным и применимость настройки в production. |
| PHP317 | PHP hash_pbkdf2 мало iterations | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Безопасная альтернатива: hash_pbkdf2('sha256', $password, $salt, $calibratedIterations); Проверьте доверие к данным и применимость настройки в production. |
| PHP318 | PHP session cookie SameSite None | [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html) / A01:2021 | medium / medium | Безопасная альтернатива: session_set_cookie_params(['samesite' =&gt; 'Strict', 'secure' =&gt; true]); Проверьте доверие к данным и применимость настройки в production. |
| PHP319 | PHP логирует HTTP cookies | [CWE-532](https://cwe.mitre.org/data/definitions/532.html) / A09:2021 | medium / medium | Безопасная альтернатива: error_log('request completed'); Проверьте доверие к данным и применимость настройки в production. |

## GO

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| GO300 | Go GORM Group HTTP SQL | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: db.Group("country") Проверьте доверие к данным и применимость настройки в production. |
| GO301 | Go GORM Joins HTTP SQL | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: db.Joins("Profile") Проверьте доверие к данным и применимость настройки в production. |
| GO302 | Go GORM Having HTTP SQL | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: db.Having("count &gt; ?", validatedCount) Проверьте доверие к данным и применимость настройки в production. |
| GO303 | Go GORM Pluck HTTP колонка | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: db.Pluck("name", &amp;values) Проверьте доверие к данным и применимость настройки в production. |
| GO304 | Go GORM Table HTTP таблица | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: db.Table("users") Проверьте доверие к данным и применимость настройки в production. |
| GO305 | Go HTTP NewRequestWithContext HTTP URL | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: http.NewRequestWithContext(ctx, "GET", allowedURL, nil) Проверьте доверие к данным и применимость настройки в production. |
| GO306 | Go net.DialTimeout HTTP адрес | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: net.DialTimeout("tcp", allowedAddress, timeout) Проверьте доверие к данным и применимость настройки в production. |
| GO307 | Go Resty HTTP URL | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: client.R().Get(allowedURL) Проверьте доверие к данным и применимость настройки в production. |
| GO308 | Go HTTP PostForm HTTP URL | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: http.PostForm(allowedURL, values) Проверьте доверие к данным и применимость настройки в production. |
| GO309 | Go Gin Redirect HTTP URL | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) / A01:2021 | medium / medium | Безопасная альтернатива: c.Redirect(302, "/home") Проверьте доверие к данным и применимость настройки в production. |
| GO310 | Go Echo File HTTP путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: c.File(allowedPath) Проверьте доверие к данным и применимость настройки в production. |
| GO311 | Go Echo Attachment HTTP путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: c.Attachment(allowedPath, "download") Проверьте доверие к данным и применимость настройки в production. |
| GO312 | Go Echo Inline HTTP путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: c.Inline(allowedPath, "document") Проверьте доверие к данным и применимость настройки в production. |
| GO313 | Go os.Rename HTTP назначение | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: os.Rename(source, allowedPath) Проверьте доверие к данным и применимость настройки в production. |
| GO314 | Go os.Chmod HTTP путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: os.Chmod(allowedPath, 0600) Проверьте доверие к данным и применимость настройки в production. |
| GO315 | Go os.Chown HTTP путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: os.Chown(allowedPath, uid, gid) Проверьте доверие к данным и применимость настройки в production. |
| GO316 | Go syscall.Exec HTTP executable | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) / A03:2021 | critical / medium | Безопасная альтернатива: syscall.Exec("/usr/bin/tool", checkedArgv, cleanEnv) Проверьте доверие к данным и применимость настройки в production. |
| GO317 | Go scrypt слабая стоимость | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Безопасная альтернатива: scrypt.Key(password, salt, calibratedN, 8, 1, 32) Проверьте доверие к данным и применимость настройки в production. |
| GO318 | Go PBKDF2 слабая стоимость | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Безопасная альтернатива: pbkdf2.Key(password, salt, calibratedIterations, 32, sha256.New) Проверьте доверие к данным и применимость настройки в production. |
| GO319 | Go Argon2 низкая память | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Безопасная альтернатива: argon2.IDKey(password, salt, calibratedTime, calibratedMemory, 1, 32) Проверьте доверие к данным и применимость настройки в production. |

## CS

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| CS300 | .NET File.Move HTTP назначение | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: File.Move(source, allowedPath); Проверьте доверие к данным и применимость настройки в production. |
| CS301 | .NET File.Copy HTTP источник | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: File.Copy(allowedSource, destination); Проверьте доверие к данным и применимость настройки в production. |
| CS302 | .NET File.AppendAllText HTTP путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: File.AppendAllText(allowedPath, data); Проверьте доверие к данным и применимость настройки в production. |
| CS303 | .NET Directory.CreateDirectory HTTP | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: Directory.CreateDirectory(allowedPath); Проверьте доверие к данным и применимость настройки в production. |
| CS304 | .NET ZipFile.ExtractToDirectory HTTP | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: ExtractValidatedEntries(upload, allowedDirectory); Проверьте доверие к данным и применимость настройки в production. |
| CS305 | .NET NativeLibrary.Load HTTP библиотека | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) / A03:2021 | medium / medium | Безопасная альтернатива: NativeLibrary.Load(approvedLibrary); Проверьте доверие к данным и применимость настройки в production. |
| CS306 | .NET Assembly.LoadFile HTTP библиотека | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) / A03:2021 | medium / medium | Безопасная альтернатива: Assembly.LoadFile(approvedAssembly); Проверьте доверие к данным и применимость настройки в production. |
| CS307 | .NET Type.GetType HTTP класс | [CWE-470](https://cwe.mitre.org/data/definitions/470.html) / A03:2021 | medium / medium | Безопасная альтернатива: allowedTypes[typeId]; Проверьте доверие к данным и применимость настройки в production. |
| CS308 | .NET Dynamic LINQ HTTP выражение | [CWE-943](https://cwe.mitre.org/data/definitions/943.html) / A03:2021 | medium / medium | Безопасная альтернатива: BuildAllowedFilter(validatedFields); Проверьте доверие к данным и применимость настройки в production. |
| CS309 | .NET SqlDataAdapter HTTP SQL | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: new SqlDataAdapter(parameterizedCommand); Проверьте доверие к данным и применимость настройки в production. |
| CS310 | .NET OdbcCommand HTTP SQL | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: new OdbcCommand("select * from users where id=?", connection); Проверьте доверие к данным и применимость настройки в production. |
| CS311 | .NET OleDbCommand HTTP SQL | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: new OleDbCommand("select * from users where id=?", connection); Проверьте доверие к данным и применимость настройки в production. |
| CS312 | .NET HttpClient PostAsync HTTP URL | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: client.PostAsync(allowedURL, content); Проверьте доверие к данным и применимость настройки в production. |
| CS313 | .NET WebClient DownloadFile HTTP URL | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: client.DownloadFile(allowedURL, target); Проверьте доверие к данным и применимость настройки в production. |
| CS314 | .NET TCP client HTTP host | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: new TcpClient(allowedHost, 443); Проверьте доверие к данным и применимость настройки в production. |
| CS315 | .NET HttpClient DeleteAsync HTTP URL | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: client.DeleteAsync(allowedURL); Проверьте доверие к данным и применимость настройки в production. |
| CS316 | .NET XPathNavigator HTTP выражение | [CWE-643](https://cwe.mitre.org/data/definitions/643.html) / A03:2021 | medium / medium | Безопасная альтернатива: navigator.Select("/users/user"); Проверьте доверие к данным и применимость настройки в production. |
| CS317 | .NET XSLT разрешает script | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) / A05:2021 | high / medium | Безопасная альтернатива: settings.EnableScript = false; Проверьте доверие к данным и применимость настройки в production. |
| CS318 | .NET XSLT разрешает document() | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) / A05:2021 | high / medium | Безопасная альтернатива: settings.EnableDocumentFunction = false; Проверьте доверие к данным и применимость настройки в production. |
| CS319 | .NET HTTP отключает TLS revocation | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 | high / medium | Безопасная альтернатива: handler.CheckCertificateRevocationList = true; Проверьте доверие к данным и применимость настройки в production. |

## RB

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| RB300 | Rails having HTTP SQL | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: User.having('count &gt; ?', validated_count) Проверьте доверие к данным и применимость настройки в production. |
| RB301 | Rails from HTTP SQL | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: User.from('users') Проверьте доверие к данным и применимость настройки в production. |
| RB302 | Rails reselect HTTP SQL | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: User.reselect(:id, :name) Проверьте доверие к данным и применимость настройки в production. |
| RB303 | Rails rewhere raw HTTP SQL | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: User.where(name: validated_name) Проверьте доверие к данным и применимость настройки в production. |
| RB304 | RubyVM загружает HTTP bytecode | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) / A08:2021 | high / medium | Безопасная альтернатива: JSON.parse(params[:data]) Проверьте доверие к данным и применимость настройки в production. |
| RB305 | Ruby Dir.glob HTTP путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: Dir.glob(allowed_pattern) Проверьте доверие к данным и применимость настройки в production. |
| RB306 | Ruby FileUtils rm_rf HTTP путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: FileUtils.rm_rf(allowed_directory) Проверьте доверие к данным и применимость настройки в production. |
| RB307 | Ruby FileUtils cp HTTP путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: FileUtils.cp(allowed_source, target) Проверьте доверие к данным и применимость настройки в production. |
| RB308 | Ruby FileUtils mv HTTP назначение | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: FileUtils.mv(source, allowed_path) Проверьте доверие к данным и применимость настройки в production. |
| RB309 | Ruby TCPSocket HTTP адрес | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: TCPSocket.new(allowed_host, 443) Проверьте доверие к данным и применимость настройки в production. |
| RB310 | Ruby Socket.tcp HTTP адрес | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: Socket.tcp(allowed_host, 443) Проверьте доверие к данным и применимость настройки в production. |
| RB311 | Ruby Net HTTP post_form HTTP URL | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: Net::HTTP.post_form(URI(allowed_url), values) Проверьте доверие к данным и применимость настройки в production. |
| RB312 | Ruby OpenSSL security level ноль | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 | high / medium | Безопасная альтернатива: context.security_level = 2 Проверьте доверие к данным и применимость настройки в production. |
| RB313 | Ruby PBKDF2 низкие iterations | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Безопасная альтернатива: OpenSSL::KDF.pbkdf2_hmac(password, salt: salt, iterations: calibrated_iterations, length: 32, hash: 'sha256') Проверьте доверие к данным и применимость настройки в production. |
| RB314 | Ruby scrypt низкая стоимость | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Безопасная альтернатива: OpenSSL::KDF.scrypt(password, salt: salt, N: calibrated_n, r: 8, p: 1, length: 32) Проверьте доверие к данным и применимость настройки в production. |

## RS

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| RS300 | Rust HTTP body без практического лимита | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) / A01:2021 | medium / medium | Безопасная альтернатива: RequestBodyLimitLayer::new(1048576); Проверьте доверие к данным и применимость настройки в production. |
| RS301 | Rust OpenSSL security level ноль | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 | high / medium | Безопасная альтернатива: builder.set_security_level(2); Проверьте доверие к данным и применимость настройки в production. |
| RS302 | Rust RSA crate слабый ключ | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 | high / medium | Безопасная альтернатива: RsaPrivateKey::new(&amp;mut rng, 3072); Проверьте доверие к данным и применимость настройки в production. |
| RS303 | Rust bcrypt низкая стоимость | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Безопасная альтернатива: bcrypt::hash(password, calibrated_cost); Проверьте доверие к данным и применимость настройки в production. |
| RS304 | Rust scrypt low log_n | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Безопасная альтернатива: scrypt::Params::new(calibrated_log_n, 8, 1, 32); Проверьте доверие к данным и применимость настройки в production. |
| RS305 | Rust PBKDF2 низкие iterations | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Безопасная альтернатива: pbkdf2_hmac::&lt;Sha256&gt;(password, salt, calibrated_iterations, &amp;mut key); Проверьте доверие к данным и применимость настройки в production. |
| RS306 | Rust libloading HTTP библиотека | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) / A03:2021 | medium / medium | Безопасная альтернатива: unsafe { Library::new(approved_library) }; Проверьте доверие к данным и применимость настройки в production. |
| RS307 | Rust SQLx QueryBuilder raw push HTTP | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Безопасная альтернатива: query_builder.push_bind(validated_value); Проверьте доверие к данным и применимость настройки в production. |
| RS308 | Rust Tokio file HTTP путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: tokio::fs::read(allowed_path).await; Проверьте доверие к данным и применимость настройки в production. |
| RS309 | Rust Tokio remove HTTP каталог | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: tokio::fs::remove_dir_all(allowed_directory).await; Проверьте доверие к данным и применимость настройки в production. |
| RS310 | Rust std file write HTTP путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: std::fs::write(allowed_path, data); Проверьте доверие к данным и применимость настройки в production. |
| RS311 | Rust reqwest HTTP query URL | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: reqwest::get(allowed_url).await; Проверьте доверие к данным и применимость настройки в production. |
| RS312 | Rust TcpStream HTTP адрес | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: TcpStream::connect(allowed_address); Проверьте доверие к данным и применимость настройки в production. |
| RS313 | Rust Tera HTTP template text | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) / A03:2021 | critical / medium | Безопасная альтернатива: tera.render("profile.html", &amp;context); Проверьте доверие к данным и применимость настройки в production. |
| RS314 | Rust UTF-8 mutable unchecked | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) / A01:2021 | medium / medium | Безопасная альтернатива: std::str::from_utf8_mut(user_bytes)?; Проверьте доверие к данным и применимость настройки в production. |

## SWIFT

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| SWIFT300 | Swift RSA signature SHA1 | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) / A02:2021 | medium / medium | Безопасная альтернатива: SecKeyCreateSignature(key, SecKeyAlgorithm.rsaSignatureMessagePSSSHA256, data, &amp;error) Проверьте доверие к данным и применимость настройки в production. |
| SWIFT301 | Swift URLSession ограничивает max TLS | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 | high / medium | Безопасная альтернатива: configuration.tlsMaximumSupportedProtocolVersion = .TLSv13 Проверьте доверие к данным и применимость настройки в production. |
| SWIFT302 | Swift NSPredicate HTTP выражение | [CWE-943](https://cwe.mitre.org/data/definitions/943.html) / A03:2021 | medium / medium | Безопасная альтернатива: NSPredicate(format: "name == %@", validatedName) Проверьте доверие к данным и применимость настройки в production. |
| SWIFT303 | Swift NSExpression внешний код | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) / A03:2021 | critical / medium | Безопасная альтернатива: NSExpression(forConstantValue: validatedValue) Проверьте доверие к данным и применимость настройки в production. |
| SWIFT304 | Swift удаляет внешний путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: FileManager.default.removeItem(atPath: allowedPath) Проверьте доверие к данным и применимость настройки в production. |
| SWIFT305 | Swift копирует внешний путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: FileManager.default.copyItem(atPath: allowedSource, toPath: destination) Проверьте доверие к данным и применимость настройки в production. |
| SWIFT306 | Swift URLSession внешний URL | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: URLSession.shared.dataTask(with: allowedUrl) Проверьте доверие к данным и применимость настройки в production. |
| SWIFT307 | Swift os_log публичный пароль | [CWE-532](https://cwe.mitre.org/data/definitions/532.html) / A09:2021 | medium / medium | Безопасная альтернатива: os_log("authentication completed") Проверьте доверие к данным и применимость настройки в production. |
| SWIFT308 | Swift Regex внешний шаблон | [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html) / A01:2021 | medium / medium | Безопасная альтернатива: NSRegularExpression(pattern: NSRegularExpression.escapedPattern(for: userInput)) Проверьте доверие к данным и применимость настройки в production. |
| SWIFT309 | Swift WebView снимает app-bound navigation | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) / A05:2021 | medium / medium | Безопасная альтернатива: configuration.limitsNavigationsToAppBoundDomains = true Проверьте доверие к данным и применимость настройки в production. |

## SCALA

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| SCALA300 | Scala JEXL HTTP script | [CWE-917](https://cwe.mitre.org/data/definitions/917.html) / A03:2021 | critical / medium | Безопасная альтернатива: dispatchAllowedAction(action) Проверьте доверие к данным и применимость настройки в production. |
| SCALA301 | Scala MVEL HTTP выражение | [CWE-917](https://cwe.mitre.org/data/definitions/917.html) / A03:2021 | critical / medium | Безопасная альтернатива: dispatchAllowedAction(action) Проверьте доверие к данным и применимость настройки в production. |
| SCALA302 | Scala OGNL HTTP выражение | [CWE-917](https://cwe.mitre.org/data/definitions/917.html) / A03:2021 | critical / medium | Безопасная альтернатива: Ognl.parseExpression("profile.name") Проверьте доверие к данным и применимость настройки в production. |
| SCALA303 | Scala ClassLoader HTTP класс | [CWE-470](https://cwe.mitre.org/data/definitions/470.html) / A03:2021 | medium / medium | Безопасная альтернатива: allowedClasses(classId) Проверьте доверие к данным и применимость настройки в production. |
| SCALA304 | Scala Netty trust-all factory | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 | high / medium | Безопасная альтернатива: builder.trustManager(caFile) Проверьте доверие к данным и применимость настройки в production. |
| SCALA305 | Scala слабый RSA key spec | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 | high / medium | Безопасная альтернатива: new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4) Проверьте доверие к данным и применимость настройки в production. |
| SCALA306 | Scala BCrypt слабая стоимость | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Безопасная альтернатива: BCrypt.gensalt(calibratedCost) Проверьте доверие к данным и применимость настройки в production. |
| SCALA307 | Scala Files HTTP move destination | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Безопасная альтернатива: Files.move(source, allowedPath) Проверьте доверие к данным и применимость настройки в production. |
| SCALA308 | Scala Socket HTTP host | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: new Socket(allowedHost, 443) Проверьте доверие к данным и применимость настройки в production. |
| SCALA309 | Scala Play WS HTTP URL | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: ws.url(allowedUrl).get() Проверьте доверие к данным и применимость настройки в production. |

## SH

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| SH300 | AWS CLI отключает certificate check | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 | high / medium | Безопасная альтернатива: aws s3 ls --ca-bundle ca.pem Проверьте доверие к данным и применимость настройки в production. |
| SH301 | Gcloud отключает certificate check | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 | high / medium | Безопасная альтернатива: gcloud config set auth/disable_ssl_validation false Проверьте доверие к данным и применимость настройки в production. |
| SH302 | Ansible отключает SSH host checking | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 | high / medium | Безопасная альтернатива: ANSIBLE_HOST_KEY_CHECKING=True ansible-playbook deploy.yml Проверьте доверие к данным и применимость настройки в production. |
| SH303 | Git environment отключает TLS trust | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 | high / medium | Безопасная альтернатива: git -c http.sslVerify=true fetch Проверьте доверие к данным и применимость настройки в production. |
| SH304 | Python environment отключает HTTPS trust | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 | high / medium | Безопасная альтернатива: python app.py Проверьте доверие к данным и применимость настройки в production. |
| SH305 | Node environment отключает TLS trust | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 | high / medium | Безопасная альтернатива: node app.js Проверьте доверие к данным и применимость настройки в production. |
| SH306 | Node CLI insecure HTTP parser | [CWE-444](https://cwe.mitre.org/data/definitions/444.html) / A01:2021 | medium / medium | Безопасная альтернатива: node app.js Проверьте доверие к данным и применимость настройки в production. |
| SH307 | Node CLI включает legacy provider | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) / A02:2021 | medium / medium | Безопасная альтернатива: node app.js Проверьте доверие к данным и применимость настройки в production. |
| SH308 | Install создаёт world writable файл | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) / A01:2021 | medium / medium | Безопасная альтернатива: install -m 0750 app /srv/app Проверьте доверие к данным и применимость настройки в production. |
| SH309 | Rsync разрешает всем запись | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) / A01:2021 | medium / medium | Безопасная альтернатива: rsync --chmod=Du=rwx,Dgo=,Fu=rw,Fgo= src/ dst/ Проверьте доверие к данным и применимость настройки в production. |
| SH310 | OpenSSL req сохраняет key без encryption | [CWE-312](https://cwe.mitre.org/data/definitions/312.html) / A02:2021 | medium / medium | Безопасная альтернатива: openssl req -new -keyout protected-key.pem Проверьте доверие к данным и применимость настройки в production. |
| SH311 | OpenSSL PKCS12 выводит plaintext key | [CWE-312](https://cwe.mitre.org/data/definitions/312.html) / A02:2021 | medium / medium | Безопасная альтернатива: openssl pkcs12 -in bundle.p12 Проверьте доверие к данным и применимость настройки в production. |
| SH312 | Psql sslmode allow допускает plaintext | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Безопасная альтернатива: psql 'host=db.example sslmode=verify-full' Проверьте доверие к данным и применимость настройки в production. |
| SH313 | MySQL CLI отключает TLS | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Безопасная альтернатива: mysql --ssl-mode=VERIFY_IDENTITY -h db.example Проверьте доверие к данным и применимость настройки в production. |
| SH314 | Redis CLI plaintext URI | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Безопасная альтернатива: redis-cli -u rediss://db.example:6379 Проверьте доверие к данным и применимость настройки в production. |

## CFG

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| CFG300 | Terraform S3 отключает public access block | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) / A01:2021 | medium / medium | Безопасная альтернатива: block_public_acls = true Проверьте доверие к данным и применимость настройки в production. |
| CFG301 | Terraform KMS отключает key rotation | [CWE-320](https://cwe.mitre.org/data/definitions/320.html) / A02:2021 | medium / medium | Безопасная альтернатива: enable_key_rotation = true Проверьте доверие к данным и применимость настройки в production. |
| CFG302 | Terraform CloudTrail отключает logging | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) / A09:2021 | medium / medium | Безопасная альтернатива: enable_logging = true Проверьте доверие к данным и применимость настройки в production. |
| CFG303 | CloudFront viewer допускает HTTP | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Безопасная альтернатива: viewer_protocol_policy = "https-only" Проверьте доверие к данным и применимость настройки в production. |
| CFG304 | CloudFront origin использует HTTP | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Безопасная альтернатива: origin_protocol_policy = "https-only" Проверьте доверие к данным и применимость настройки в production. |
| CFG305 | CloudFront устаревший минимум TLS | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 | high / medium | Безопасная альтернатива: minimum_protocol_version = "TLSv1.2_2021" Проверьте доверие к данным и применимость настройки в production. |
| CFG306 | Lambda function URL без authentication | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) / A07:2021 | high / medium | Безопасная альтернатива: authorization_type = "AWS_IAM" Проверьте доверие к данным и применимость настройки в production. |
| CFG307 | API Gateway метод без authorization | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) / A07:2021 | high / medium | Безопасная альтернатива: authorization = "AWS_IAM" Проверьте доверие к данным и применимость настройки в production. |
| CFG308 | IAM Allow с публичным Principal | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) / A01:2021 | medium / medium | Безопасная альтернатива: {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/reader"},"Action":"s3:GetObject"} Проверьте доверие к данным и применимость настройки в production. |
| CFG309 | IAM PassRole разрешает все ресурсы | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) / A01:2021 | medium / medium | Безопасная альтернатива: {"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::123456789012:role/app"} Проверьте доверие к данным и применимость настройки в production. |
| CFG310 | IAM слишком короткие пароли | [CWE-287](https://cwe.mitre.org/data/definitions/287.html) / A07:2021 | medium / medium | Безопасная альтернатива: minimum_password_length = 16 Проверьте доверие к данным и применимость настройки в production. |
| CFG311 | Terraform RDS без deletion protection | [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) / A05:2021 | medium / medium | Безопасная альтернатива: deletion_protection = true Проверьте доверие к данным и применимость настройки в production. |
| CFG312 | MSK разрешает unauthenticated clients | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) / A07:2021 | high / medium | Безопасная альтернатива: client_authentication { unauthenticated = false } Проверьте доверие к данным и применимость настройки в production. |
| CFG313 | MSK plaintext client broker | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Безопасная альтернатива: client_broker = "TLS" Проверьте доверие к данным и применимость настройки в production. |
| CFG314 | Terraform MQ публичный broker | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) / A01:2021 | medium / medium | Безопасная альтернатива: publicly_accessible = false Проверьте доверие к данным и применимость настройки в production. |
| CFG315 | Terraform удаляет непустой storage | [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) / A05:2021 | medium / medium | Безопасная альтернатива: force_destroy = false Проверьте доверие к данным и применимость настройки в production. |
| CFG316 | Azure App Service не требует HTTPS | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Безопасная альтернатива: https_only = true Проверьте доверие к данным и применимость настройки в production. |
| CFG317 | Azure App Service допускает plain FTP | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Безопасная альтернатива: ftps_state = "FtpsOnly" Проверьте доверие к данным и применимость настройки в production. |
| CFG318 | Azure App Service remote debugging | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) / A05:2021 | medium / medium | Безопасная альтернатива: remote_debugging_enabled = false Проверьте доверие к данным и применимость настройки в production. |
| CFG319 | Azure storage публичные nested items | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) / A01:2021 | medium / medium | Безопасная альтернатива: allow_nested_items_to_be_public = false Проверьте доверие к данным и применимость настройки в production. |
| CFG320 | Azure Container Registry admin account | [CWE-287](https://cwe.mitre.org/data/definitions/287.html) / A07:2021 | medium / medium | Безопасная альтернатива: admin_enabled = false Проверьте доверие к данным и применимость настройки в production. |
| CFG321 | Azure Container Registry anonymous pull | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) / A07:2021 | high / medium | Безопасная альтернатива: anonymous_pull_enabled = false Проверьте доверие к данным и применимость настройки в production. |
| CFG322 | GCP firewall открыт всему IPv6 | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) / A01:2021 | medium / medium | Безопасная альтернатива: source_ranges = ["2001:db8:1234::/64"] Проверьте доверие к данным и применимость настройки в production. |
| CFG323 | GCP IAM выдаёт доступ всем users | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) / A01:2021 | medium / medium | Безопасная альтернатива: member = "serviceAccount:app@example.iam.gserviceaccount.com" Проверьте доверие к данным и применимость настройки в production. |
| CFG324 | GCP Cloud Run публичный ingress | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) / A01:2021 | medium / medium | Безопасная альтернатива: ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY" Проверьте доверие к данным и применимость настройки в production. |
| CFG325 | GCP VM без secure boot | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) / A05:2021 | medium / medium | Безопасная альтернатива: enable_secure_boot = true Проверьте доверие к данным и применимость настройки в production. |
| CFG326 | GCP VM без vTPM | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) / A05:2021 | medium / medium | Безопасная альтернатива: enable_vtpm = true Проверьте доверие к данным и применимость настройки в production. |
| CFG327 | GCP VM без integrity monitoring | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) / A09:2021 | medium / medium | Безопасная альтернатива: enable_integrity_monitoring = true Проверьте доверие к данным и применимость настройки в production. |
| CFG328 | GCP GKE без shielded nodes | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) / A05:2021 | medium / medium | Безопасная альтернатива: enable_shielded_nodes = true Проверьте доверие к данным и применимость настройки в production. |
| CFG329 | GCP VM разрешает project SSH keys | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) / A01:2021 | medium / medium | Безопасная альтернатива: "block-project-ssh-keys" = "true" Проверьте доверие к данным и применимость настройки в production. |
| CFG330 | GCP VM открывает serial console | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) / A05:2021 | medium / medium | Безопасная альтернатива: "serial-port-enable" = "false" Проверьте доверие к данным и применимость настройки в production. |
| CFG331 | GCP VM допускает legacy metadata | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Безопасная альтернатива: "disable-legacy-endpoints" = "true" Проверьте доверие к данным и применимость настройки в production. |
| CFG332 | PostgreSQL HBA trust без пароля | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) / A07:2021 | high / medium | Безопасная альтернатива: hostssl all all 10.0.0.0/8 scram-sha-256 Проверьте доверие к данным и применимость настройки в production. |
| CFG333 | PostgreSQL сервер отключает SSL | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Безопасная альтернатива: ssl = on Проверьте доверие к данным и применимость настройки в production. |
| CFG334 | PostgreSQL пишет все SQL в log | [CWE-532](https://cwe.mitre.org/data/definitions/532.html) / A09:2021 | medium / medium | Безопасная альтернатива: log_statement = 'ddl' Проверьте доверие к данным и применимость настройки в production. |
| CFG335 | MySQL включает local infile | [CWE-73](https://cwe.mitre.org/data/definitions/73.html) / A01:2021 | medium / medium | Безопасная альтернатива: local_infile = OFF Проверьте доверие к данным и применимость настройки в production. |
| CFG336 | MySQL не ограничивает file import/export | [CWE-73](https://cwe.mitre.org/data/definitions/73.html) / A01:2021 | medium / medium | Безопасная альтернатива: secure_file_priv = "/var/lib/mysql-files" Проверьте доверие к данным и применимость настройки в production. |
| CFG337 | MySQL разрешает plaintext connections | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Безопасная альтернатива: require_secure_transport = ON Проверьте доверие к данным и применимость настройки в production. |
| CFG338 | MySQL пишет все запросы в general log | [CWE-532](https://cwe.mitre.org/data/definitions/532.html) / A09:2021 | medium / medium | Безопасная альтернатива: general_log = OFF Проверьте доверие к данным и применимость настройки в production. |
| CFG339 | Redis убирает default пароль | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) / A07:2021 | high / medium | Безопасная альтернатива: include /run/secrets/redis-auth.conf Проверьте доверие к данным и применимость настройки в production. |
| CFG340 | MongoDB отключает TLS mode | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Безопасная альтернатива: tls: { mode: requireTLS } Проверьте доверие к данным и применимость настройки в production. |
| CFG341 | RabbitMQ guest вне loopback | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) / A07:2021 | high / medium | Безопасная альтернатива: loopback_users.guest = true Проверьте доверие к данным и применимость настройки в production. |
| CFG342 | RabbitMQ отключает проверку peer TLS | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 | high / medium | Безопасная альтернатива: ssl_options.verify = verify_peer Проверьте доверие к данным и применимость настройки в production. |
| CFG343 | Kafka открывает ресурсы без ACL | [CWE-862](https://cwe.mitre.org/data/definitions/862.html) / A01:2021 | medium / medium | Безопасная альтернатива: allow.everyone.if.no.acl.found = false Проверьте доверие к данным и применимость настройки в production. |
| CFG344 | Kafka plaintext listener | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Безопасная альтернатива: listeners = SASL_SSL://broker.example:9093 Проверьте доверие к данным и применимость настройки в production. |
| CFG345 | Elasticsearch HTTP без TLS | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Безопасная альтернатива: xpack.security.http.ssl.enabled: true Проверьте доверие к данным и применимость настройки в production. |
| CFG346 | Elasticsearch cluster без TLS | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Безопасная альтернатива: xpack.security.transport.ssl.enabled: true Проверьте доверие к данным и применимость настройки в production. |
| CFG347 | OpenSearch отключает security plugin | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) / A07:2021 | high / medium | Безопасная альтернатива: plugins.security.disabled: false Проверьте доверие к данным и применимость настройки в production. |
| CFG348 | Grafana anonymous access | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) / A07:2021 | high / medium | Безопасная альтернатива: GF_AUTH_ANONYMOUS_ENABLED=false Проверьте доверие к данным и применимость настройки в production. |
| CFG349 | Grafana cookie без Secure | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) / A07:2021 | medium / medium | Безопасная альтернатива: GF_SECURITY_COOKIE_SECURE=true Проверьте доверие к данным и применимость настройки в production. |
| CFG350 | Grafana cookie SameSite none | [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html) / A01:2021 | medium / medium | Безопасная альтернатива: GF_SECURITY_COOKIE_SAMESITE=strict Проверьте доверие к данным и применимость настройки в production. |
| CFG351 | Grafana разрешает embedding | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) / A05:2021 | medium / medium | Безопасная альтернатива: GF_SECURITY_ALLOW_EMBEDDING=false Проверьте доверие к данным и применимость настройки в production. |
| CFG352 | Consul отключает TLS verification | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 | high / medium | Безопасная альтернатива: verify_outgoing = true Проверьте доверие к данным и применимость настройки в production. |
| CFG353 | Vault отключает listener TLS | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Безопасная альтернатива: tls_disable = 0 Проверьте доверие к данным и применимость настройки в production. |
| CFG354 | Traefik insecure API | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) / A07:2021 | high / medium | Безопасная альтернатива: api: { insecure: false } Проверьте доверие к данным и применимость настройки в production. |
| CFG355 | Jenkins отключает authentication | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) / A07:2021 | high / medium | Безопасная альтернатива: &lt;useSecurity&gt;true&lt;/useSecurity&gt; Проверьте доверие к данным и применимость настройки в production. |
| CFG356 | SonarQube legacy authentication off | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) / A07:2021 | high / medium | Безопасная альтернатива: sonar.forceAuthentication=true Проверьте доверие к данным и применимость настройки в production. |
| CFG357 | Docker отключает SELinux labels | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) / A05:2021 | medium / medium | Безопасная альтернатива: security_opt: ["label=type:container_t"] Проверьте доверие к данным и применимость настройки в production. |
| CFG358 | Apache отключает upstream TLS verify | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 | high / medium | Безопасная альтернатива: SSLProxyVerify require Проверьте доверие к данным и применимость настройки в production. |
| CFG359 | Spring Actuator публикует env values | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) / A05:2021 | medium / medium | Безопасная альтернатива: management.endpoint.env.show-values=NEVER Проверьте доверие к данным и применимость настройки в production. |

## Проверки

Для всех 300 правил в tests/fixtures/advanced-rules.json есть опасный пример
и безопасная альтернатива. tests/advanced-rules.test.ts проверяет находки через общий движок,
метаданные, языки, уникальность ID и сигнатур, координаты CRLF, ZIP и время обработки
больших файлов. Опасные примеры также проверяются на отсутствие находок каталога,
существовавшего перед добавлением этого набора.

## Первичные источники

- [Gitleaks: форматы сервисных credentials](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml)
- [Fastify: untrusted schemas](https://fastify.dev/docs/latest/Reference/Validation-and-Serialization/)
- [Pydantic model_construct](https://docs.pydantic.dev/latest/concepts/models/#creating-models-without-validation)
- [RubyVM binary bytecode](https://docs.ruby-lang.org/en/master/RubyVM/InstructionSequence.html#method-c-load_from_binary)
- [JSON Web Token RSA key size](https://github.com/auth0/node-jsonwebtoken)
- [CloudFront HTTPS](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-viewers-to-cloudfront.html)
- [Grafana configuration](https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/)
- [RabbitMQ access control](https://www.rabbitmq.com/docs/access-control)
- [Node.js VM](https://nodejs.org/api/vm.html)
- [DOMPurify](https://github.com/cure53/DOMPurify#can-i-configure-dompurify)
- [WebSocket payload limits](https://github.com/websockets/ws/blob/master/doc/ws.md)
- [Python security](https://docs.python.org/3/library/security_warnings.html)
- [OWASP deserialization](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [OWASP SQL injection prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PHP security](https://www.php.net/manual/en/security.php)
- [Go HTML template](https://pkg.go.dev/html/template)
- [.NET security rules](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/security-warnings)
- [Rails security](https://guides.rubyonrails.org/security.html)
- [Rust unsafe invariants](https://doc.rust-lang.org/nomicon/working-with-unsafe.html)
- [Apple Security](https://developer.apple.com/documentation/security)
- [Play WS](https://www.playframework.com/documentation/3.0.x/ScalaWS)
- [Docker container runtime](https://docs.docker.com/engine/containers/run/)
- [Kubernetes Pod Security](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Terraform Cloud SQL](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance)
