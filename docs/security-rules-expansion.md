# Набор из 200 дополнительных SAST-правил

Общая база содержит 400 статических правил. Этот каталог описывает
app/lib/sast-rules-expansion.ts с ID от 100 в каждой группе.
Обновление каталога: npm run rules:catalog.

Правила используются в браузере и API. Находки содержат CWE, OWASP, риск,
уверенность, координаты и рекомендации, входят в JSON/SARIF и историю.

## Область применения

Высокая уверенность формата секрета не означает действительность credential:
сетевой проверки нет. Для API и конфигураций средняя уверенность требует проверки
происхождения данных, версии библиотеки и условий эксплуатации.

Политики инфраструктуры, например writable root filesystem, token mount,
process namespace и key rotation, отмечают место для проверки production.
Они не доказывают наличие эксплуатируемой уязвимости. Buffer.allocUnsafe безопасен,
если весь буфер заполнен до чтения; HTML, XML и объекты требуют проверки доверия.

Legacy API (create_function, string assert, старые Electron/ASP.NET settings)
нужны для старых проектов. В новых версиях они могут быть удалены или игнорироваться.
Рекомендации следует сверять с версией приложения и библиотеки.

Регулярные выражения не разрешают алиасы и не строят AST. Ограниченные шаблоны
не покрывают все multiline/nested формы; комментарии и строковые примеры могут
совпасть. Safe fixtures проверяют отсутствие конкретной находки, а не общую
безопасность программы. Vue/Svelte анализируются как JavaScript, а
conf/ini/toml/tf/hcl/plist — как конфигурация. ZIP исключает исходники каталога и тесты.

## Распределение

| Группа | Новых правил |
|---|---:|
| SEC | 16 |
| JS | 20 |
| PY | 20 |
| JAVA | 20 |
| PHP | 16 |
| GO | 14 |
| CS | 16 |
| RB | 12 |
| RS | 10 |
| SWIFT | 10 |
| SCALA | 10 |
| SH | 12 |
| CFG | 24 |

## SEC

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| SEC100 | Токен загрузки PyPI | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите токен PyPI и проверьте опубликованные пакеты. |
| SEC101 | Токен Databricks | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите токен Databricks и перенесите credentials в secret manager. |
| SEC102 | Токен DigitalOcean | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите токен DigitalOcean и проверьте изменения инфраструктуры. |
| SEC103 | Токен приложения Shopify | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите токен Shopify и ограничьте permissions нового приложения. |
| SEC104 | Токен Doppler | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите токен Doppler и проверьте доступ к хранилищу секретов. |
| SEC105 | API-токен Postman | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите API-токен Postman и проверьте доступ к workspace. |
| SEC106 | API-токен Pulumi | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите токен Pulumi и проверьте журналы операций со stacks. |
| SEC107 | Service account token Grafana | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите service account token Grafana и ограничьте права нового токена. |
| SEC108 | Пользовательский токен Sentry | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите токен Sentry и исключите его из репозитория. |
| SEC109 | Webhook Slack в исходниках | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Перевыпустите webhook Slack и загружайте URL из защищённой конфигурации. |
| SEC110 | Токен Telegram Bot API | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Перевыпустите токен бота через BotFather и исключите его из исходников. |
| SEC111 | Приватный ключ age | [CWE-321](https://cwe.mitre.org/data/definitions/321.html) / A07:2021 | critical / high | Смените приватный ключ age и проверьте доступ к зашифрованным данным. |
| SEC112 | Secret key 1Password | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Перевыпустите secret key 1Password и проверьте доступ к vault. |
| SEC113 | Service account token 1Password | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите service account token 1Password и проверьте обращения к секретам. |
| SEC114 | API-ключ Artifactory | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Отзовите API-ключ Artifactory и используйте ограниченный access token. |
| SEC115 | Client secret Adobe | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / A07:2021 | critical / high | Перевыпустите client secret Adobe и перенесите его в secret store. |

## JS

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| JS100 | jQuery HTML из HTTP-ввода | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) / A03:2021 | high / medium | Используйте text() или очистку HTML по allowlist. |
| JS101 | Angular обходит проверку HTML | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) / A03:2021 | high / medium | Сохраняйте Angular sanitization; доверяйте только заранее проверенному HTML. |
| JS102 | Vue вставляет сырой HTML | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) / A03:2021 | high / medium | Используйте интерполяцию текста Vue или очищайте HTML до v-html. |
| JS103 | Svelte вставляет сырой HTML | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) / A03:2021 | high / medium | Используйте штатную интерполяцию Svelte или очистку HTML по allowlist. |
| JS104 | Lodash template из HTTP-ввода | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) / A03:2021 | critical / medium | Используйте фиксированный шаблон и передавайте HTTP-ввод только как данные. |
| JS105 | MongoDB $where из HTTP-ввода | [CWE-943](https://cwe.mitre.org/data/definitions/943.html) / A03:2021 | high / medium | Исключите $where и соберите типизированный фильтр из разрешённых полей. |
| JS106 | serialize-javascript отключает экранирование | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) / A03:2021 | high / medium | Оставьте unsafe выключенным и не вставляйте непроверенную сериализацию в HTML. |
| JS107 | Handlebars компилирует HTTP-ввод | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) / A03:2021 | critical / medium | Компилируйте статические шаблоны и передавайте пользовательские значения через контекст. |
| JS108 | EJS шаблон из HTTP-ввода | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) / A03:2021 | critical / medium | Используйте фиксированный EJS template и отдельный объект данных. |
| JS109 | Устаревший password-based Cipher Node.js | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) / A02:2021 | medium / medium | Используйте createCipheriv с AEAD, безопасным KDF и случайным nonce. |
| JS110 | Неинициализированный Buffer | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) / A01:2021 | medium / medium | Используйте Buffer.alloc либо гарантированно заполняйте весь буфер до чтения или отправки. |
| JS111 | Короткий ключ подписи JWT | [CWE-321](https://cwe.mitre.org/data/definitions/321.html) / A07:2021 | medium / medium | Используйте стойкий ключ подписи из secret store; не задавайте короткий строковый секрет. |
| JS112 | Низкая стоимость bcrypt Node.js | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Выберите стоимость bcrypt по измерениям нагрузки, обычно не ниже 10. |
| JS113 | Слишком мало итераций PBKDF2 Node.js | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Выберите актуальную стоимость PBKDF2 для выбранного digest и проверяйте её по времени вычисления. |
| JS114 | Node.js разрешает TLS ниже 1.2 | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 | high / medium | Установите minVersion: 'TLSv1.2' или 'TLSv1.3'. |
| JS115 | Node.js отключает hostname check | [CWE-297](https://cwe.mitre.org/data/definitions/297.html) / A02:2021 | high / medium | Используйте стандартный tls.checkServerIdentity и корректный SAN сертификата. |
| JS116 | Legacy Electron remote module | [CWE-749](https://cwe.mitre.org/data/definitions/749.html) / A05:2021 | medium / medium | Отключите legacy remote module и предоставляйте минимальные IPC-команды. |
| JS117 | Electron разрешает mixed content | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Отключите allowRunningInsecureContent и загружайте ресурсы через HTTPS. |
| JS118 | Загрузка скрипта jQuery из HTTP-ввода | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) / A03:2021 | high / medium | Загружайте только фиксированные доверенные скрипты с проверкой целостности. |
| JS119 | Отключена AngularJS SCE | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) / A03:2021 | high / medium | Сохраните SCE и применяйте проверку HTML, URL и других чувствительных контекстов. |

## PY

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| PY100 | PyYAML unsafe_load | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) / A08:2021 | high / medium | Используйте yaml.safe_load и проверку структуры документа. |
| PY101 | jsonpickle создаёт объекты из JSON | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) / A08:2021 | high / medium | Используйте json.loads с проверенной схемой без произвольного восстановления объектов. |
| PY102 | Десериализация marshal | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) / A08:2021 | high / medium | Не загружайте marshal из недоверенного источника; используйте обычный формат данных. |
| PY103 | Shelve использует Pickle | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) / A08:2021 | high / medium | Открывайте только доверенные shelve-файлы; для внешних данных используйте SQLite или JSON. |
| PY104 | lxml снимает ограничения дерева | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) / A01:2021 | medium / medium | Оставьте huge_tree=False и ограничьте размер и глубину XML. |
| PY105 | defusedxml разрешает DTD | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) / A05:2021 | high / medium | Сохраните forbid_dtd=True для недоверенного XML и запретите внешние сущности. |
| PY106 | Python отключает hostname check | [CWE-297](https://cwe.mitre.org/data/definitions/297.html) / A02:2021 | high / medium | Включите check_hostname и используйте проверяемый SSL-контекст. |
| PY107 | Python выбирает устаревший TLS | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 | high / medium | Используйте PROTOCOL_TLS_CLIENT и minimum_version TLSv1_2. |
| PY108 | DES/ARC4 в Python | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) / A02:2021 | medium / medium | Используйте AES-GCM или ChaCha20-Poly1305 с проверкой tag. |
| PY109 | Слабый размер RSA в Python | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 | medium / medium | Используйте RSA не менее 2048 бит и актуальный криптографический протокол. |
| PY110 | Django extra с динамическим SQL | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Используйте ORM expressions и параметры SQL вместо f-строк в extra. |
| PY111 | Python cursor.execute с f-строкой | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Передавайте значения вторым аргументом execute, SQL оставьте фиксированным. |
| PY112 | Flask-WTF отключает CSRF | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) / A01:2021 | medium / medium | Включите WTF_CSRF_ENABLED для форм с cookie-аутентификацией. |
| PY113 | Flask отключает Jinja autoescape | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) / A03:2021 | high / medium | Сохраните autoescape для HTML; текстовые форматы обрабатывайте отдельными шаблонами. |
| PY114 | aiohttp отключает TLS validation | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 | high / medium | Используйте проверяемый SSLContext и доверенный CA в TCPConnector. |
| PY115 | Paramiko исполняет HTTP-ввод | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) / A03:2021 | critical / medium | Выбирайте фиксированную удалённую команду и проверяйте аргументы по allowlist. |
| PY116 | Сетевой listener logging.config | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) / A03:2021 | critical / medium | Не принимайте произвольную logging-конфигурацию; используйте verify для проверки подписи. |
| PY117 | Python execvp выбирает команду из HTTP-ввода | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) / A03:2021 | critical / medium | Фиксируйте исполняемый файл, передавайте проверенные аргументы отдельно. |
| PY118 | subprocess получает executable из HTTP-ввода | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) / A03:2021 | critical / medium | Не позволяйте HTTP-параметру выбирать бинарник; используйте allowlist операций. |
| PY119 | Legacy PickleSerializer для Django-сессии | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) / A08:2021 | high / medium | Используйте JSONSerializer и перевыпустите сессии при возможной утечке ключа. |

## JAVA

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| JAVA100 | XStream разрешает все типы | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) / A08:2021 | high / medium | Задайте список разрешённых DTO; не разрешайте XStream wildcard '**'. |
| JAVA101 | Java XML расширяет entity references | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) / A05:2021 | high / medium | Отключите entity expansion и запретите DTD/внешние сущности. |
| JAVA102 | Java XML разрешает DOCTYPE | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) / A05:2021 | high / medium | Установите disallow-doctype-decl=true для недоверенных документов. |
| JAVA103 | XML parser включает XInclude | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) / A05:2021 | high / medium | Отключите XInclude и запретите доступ XML-парсера к внешним ресурсам. |
| JAVA104 | StAX разрешает DTD | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) / A05:2021 | high / medium | Установите XMLInputFactory.SUPPORT_DTD=false. |
| JAVA105 | StAX разрешает внешние сущности | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) / A05:2021 | high / medium | Установите IS_SUPPORTING_EXTERNAL_ENTITIES=false и ограничьте XML resolver. |
| JAVA106 | XSLT доступен любой внешний stylesheet | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) / A05:2021 | high / medium | Установите ACCESS_EXTERNAL_STYLESHEET в пустую строку или строгий allowlist протоколов. |
| JAVA107 | JNDI доверяет remote codebase | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) / A03:2021 | critical / medium | Отключите trustURLCodebase и не разрешайте загрузку классов из удалённых источников. |
| JAVA108 | JNDI lookup из HTTP-ввода | [CWE-74](https://cwe.mitre.org/data/definitions/74.html) / A03:2021 | high / medium | Выбирайте JNDI-имя из фиксированного allowlist без пользовательского URL. |
| JAVA109 | Spring Expression из HTTP-ввода | [CWE-917](https://cwe.mitre.org/data/definitions/917.html) / A03:2021 | critical / medium | Используйте фиксированные expressions и ограниченный SimpleEvaluationContext. |
| JAVA110 | Freemarker template из HTTP-ввода | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) / A03:2021 | critical / medium | Загружайте статические Freemarker-шаблоны и передавайте ввод как значения модели. |
| JAVA111 | Velocity исполняет HTTP-шаблон | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) / A03:2021 | critical / medium | Не передавайте HTTP-ввод как исходный текст Velocity-шаблона. |
| JAVA112 | Слабый PBE-алгоритм Java | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) / A02:2021 | medium / medium | Используйте современный KDF и AEAD вместо PBEWithMD5AndDES. |
| JAVA113 | Слабый алгоритм подписи Java | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) / A02:2021 | medium / medium | Используйте RSA-PSS с SHA-256 или современную подпись Ed25519. |
| JAVA114 | HMAC-MD5 в Java | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) / A02:2021 | medium / medium | Перейдите на HmacSHA256 с ключом достаточной длины. |
| JAVA115 | Java выбирает устаревший SSLContext | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 | high / medium | Выберите TLSv1.2 или TLSv1.3 и ограничьте версии протокола. |
| JAVA116 | Java отключает HttpOnly cookie | [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) / A07:2021 | medium / medium | Включите HttpOnly для сессионных cookie, не предоставляйте их JavaScript. |
| JAVA117 | Java отключает Secure cookie | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) / A07:2021 | medium / medium | Включите Secure для cookie, содержащих данные сессии. |
| JAVA118 | Android WebView получает доступ к файлам | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) / A05:2021 | medium / medium | Отключите file access для недоверенного WebView и используйте WebViewAssetLoader. |
| JAVA119 | Android WebView открыт отладчику | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) / A05:2021 | medium / medium | Отключите WebView debugging в release-сборке. |

## PHP

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| PHP100 | Legacy create_function исполняет код | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) / A03:2021 | critical / medium | Замените legacy create_function статической closure-функцией. |
| PHP101 | eval в PHP | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) / A03:2021 | critical / medium | Удалите eval и используйте парсер данных или список разрешённых операций. |
| PHP102 | PHP assert с HTTP-строкой | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) / A03:2021 | critical / medium | Не используйте legacy string assertions; валидируйте ввод явными проверками. |
| PHP103 | Вызов функции по HTTP-параметру | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) / A03:2021 | critical / medium | Выбирайте обработчик из фиксированной карты разрешённых функций. |
| PHP104 | preg_replace callback из HTTP-ввода | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) / A03:2021 | critical / medium | Используйте фиксированный callback вместо имени из пользовательского запроса. |
| PHP105 | Phar десериализует метаданные | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) / A08:2021 | high / medium | Для недоверенного Phar используйте getMetadata(['allowed_classes' => false]) и проверьте структуру метаданных. |
| PHP106 | extract импортирует HTTP-поля в scope | [CWE-915](https://cwe.mitre.org/data/definitions/915.html) / A01:2021 | medium / medium | Читайте разрешённые поля явно; не превращайте HTTP-параметры в локальные переменные. |
| PHP107 | parse_str без массива результата | [CWE-915](https://cwe.mitre.org/data/definitions/915.html) / A01:2021 | medium / medium | В legacy PHP передавайте отдельный массив результата и проверяйте разрешённые ключи. |
| PHP108 | Вывод HTTP-ввода без HTML-экранирования | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) / A03:2021 | high / medium | Используйте htmlspecialchars с ENT_QUOTES и корректной кодировкой для HTML-текста. |
| PHP109 | PHP file_get_contents из HTTP-URL | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Разрешайте только известные назначения, блокируйте локальные сети и опасные схемы. |
| PHP110 | cURL URL из HTTP-параметра | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Проверяйте URL, DNS/IP и каждое перенаправление по allowlist. |
| PHP111 | PHP readfile отдаёт HTTP-путь | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Выбирайте файл внутри фиксированного каталога по безопасному идентификатору. |
| PHP112 | PHP move_uploaded_file выбирает HTTP-путь | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) / A01:2021 | medium / medium | Задавайте серверное имя и каталог загрузки, проверяйте тип и исключите исполнение файлов. |
| PHP113 | Слабый bcrypt cost в PHP | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Выбирайте bcrypt cost по измерениям нагрузки, обычно не ниже 10. |
| PHP114 | Отключён strict mode PHP-сессий | [CWE-384](https://cwe.mitre.org/data/definitions/384.html) / A07:2021 | medium / medium | Включите session.use_strict_mode и обновляйте ID после аутентификации. |
| PHP115 | PHP возвращает session ID в URL | [CWE-598](https://cwe.mitre.org/data/definitions/598.html) / A07:2021 | medium / medium | Отключите trans_sid и передавайте ID только через защищённый cookie. |

## GO

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| GO100 | Токен Go из math/rand | [CWE-338](https://cwe.mitre.org/data/definitions/338.html) / A02:2021 | medium / medium | Используйте crypto/rand для секретов; проверьте импорт и источник RNG. |
| GO101 | Go JWT без проверки claims | [CWE-613](https://cwe.mitre.org/data/definitions/613.html) / A07:2021 | medium / medium | Проверяйте срок действия, issuer и audience после криптографической проверки JWT. |
| GO102 | Go JWT разрешает алгоритм none | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) / A07:2021 | critical / medium | Разрешайте только ожидаемые алгоритмы подписи, исключите none. |
| GO103 | Go JWT использует UnsafeAllowNoneSignatureType | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) / A07:2021 | critical / medium | Не принимайте JWT без подписи; используйте фиксированный signing method. |
| GO104 | Legacy gRPC без TLS | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Используйте grpc.WithTransportCredentials с проверяемым TLS. |
| GO105 | gRPC insecure credentials | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Не передавайте чувствительные данные по plaintext gRPC; настройте TLS credentials. |
| GO106 | Go ограничивает TLS устаревшей версией | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 | high / medium | Разрешите TLS 1.2/1.3 и уберите устаревший MaxVersion. |
| GO107 | Go XML отключает strict parsing | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) / A01:2021 | medium / medium | Сохраняйте strict XML parsing и валидируйте структуру недоверенного документа. |
| GO108 | Go redirect из HTTP-ввода | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) / A01:2021 | medium / medium | Разрешайте только локальные маршруты или известные URL назначения. |
| GO109 | Go ServeFile из HTTP-пути | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Выбирайте файлы по allowlist внутри фиксированного каталога. |
| GO110 | Go RemoveAll из HTTP-пути | [CWE-73](https://cwe.mitre.org/data/definitions/73.html) / A01:2021 | medium / medium | Не позволяйте запросу выбирать каталог удаления; проверяйте владельца и нормализованный путь. |
| GO111 | Go выводит TLS key log в stdout | [CWE-532](https://cwe.mitre.org/data/definitions/532.html) / A05:2021 | medium / medium | Отключите TLS key logging в production и защищайте диагностические ключи. |
| GO112 | Низкая стоимость bcrypt Go | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Выберите стоимость bcrypt по измерениям нагрузки, обычно не ниже 10. |
| GO113 | SSH Go доверяет любой user authority | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 | high / medium | Проверяйте user certificate authority по списку доверенных ключей. |

## CS

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| CS100 | Legacy .NET разрешает DTD | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) / A05:2021 | high / medium | Используйте DtdProcessing.Prohibit и отключённый внешний XmlResolver. |
| CS101 | XML resolver .NET получает доступ к URL | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) / A05:2021 | high / medium | Для недоверенного XML установите XmlResolver=null и запретите внешние ресурсы. |
| CS102 | XSLT .NET включает trusted features | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) / A03:2021 | critical / medium | Используйте XsltSettings.Default и запретите script/document() для недоверенного XSLT. |
| CS103 | ASP.NET отключает request validation | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) / A03:2021 | high / medium | Сохраняйте request validation и контекстное экранирование пользовательского вывода. |
| CS104 | Отключён MAC ASP.NET ViewState | [CWE-345](https://cwe.mitre.org/data/definitions/345.html) / A07:2021 | critical / medium | Включите EnableViewStateMac и защитите machine key. |
| CS105 | ViewState не шифруется | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) / A05:2021 | medium / medium | Не храните секреты в ViewState; при чувствительных данных включите шифрование. |
| CS106 | ASP.NET отключает event validation | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) / A01:2021 | medium / medium | Включите event validation и проверяйте допустимые значения postback. |
| CS107 | CookieOptions отключает HttpOnly | [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) / A07:2021 | medium / medium | Включите HttpOnly для сессионных cookie. |
| CS108 | CookieOptions отключает Secure | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) / A07:2021 | medium / medium | Установите Secure=true для cookie с данными сессии. |
| CS109 | JWT middleware разрешает HTTP metadata | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Загружайте metadata и signing keys только по проверяемому HTTPS. |
| CS110 | JWT отключает проверку signing key | [CWE-345](https://cwe.mitre.org/data/definitions/345.html) / A07:2021 | medium / medium | Проверяйте допустимый signing key; этот флаг не заменяет проверку подписи JWT. |
| CS111 | JWT не требует подписанного токена | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) / A07:2021 | critical / medium | Установите RequireSignedTokens=true и фиксируйте разрешённые алгоритмы. |
| CS112 | JWT отключает проверку lifetime | [CWE-613](https://cwe.mitre.org/data/definitions/613.html) / A07:2021 | medium / medium | Проверяйте exp/nbf и задайте ограниченный clock skew. |
| CS113 | JWT отключает проверку audience | [CWE-346](https://cwe.mitre.org/data/definitions/346.html) / A07:2021 | medium / medium | Включите ValidateAudience и укажите audience приложения. |
| CS114 | JWT отключает проверку issuer | [CWE-346](https://cwe.mitre.org/data/definitions/346.html) / A07:2021 | medium / medium | Включите ValidateIssuer и укажите доверенного издателя токенов. |
| CS115 | Слабый RSA-ключ .NET | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 | medium / medium | Создавайте RSA-ключ не менее 2048 бит с актуальными параметрами подписи. |

## RB

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| RB100 | Psych unsafe_load_file | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) / A08:2021 | high / medium | Используйте safe_load_file с ограниченными классами и проверкой структуры. |
| RB101 | Oj object_load восстанавливает Ruby-объекты | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) / A08:2021 | high / medium | Используйте Oj.strict_load для данных, не восстанавливайте произвольные классы. |
| RB102 | Ruby JSON разрешает additions | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) / A08:2021 | high / medium | Установите create_additions:false и проверяйте JSON по схеме. |
| RB103 | Kernel.open из HTTP-ввода | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) / A03:2021 | critical / medium | Используйте File.open с проверенным локальным путём, исключите pipe-команды. |
| RB104 | ERB template из HTTP-ввода | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) / A03:2021 | critical / medium | Используйте статический ERB template и отдельный binding с данными. |
| RB105 | Ruby задаёт устаревший min TLS | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 | high / medium | Установите min_version TLS1_2_VERSION или TLS1_3_VERSION. |
| RB106 | Rails session cookie без HttpOnly | [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) / A07:2021 | medium / medium | Включите httponly для Rails session store и задайте Secure/SameSite. |
| RB107 | Rails find_by_sql с интерполяцией | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Используйте параметризованный запрос или ActiveRecord query API. |
| RB108 | Rails order из HTTP-ввода | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Выбирайте колонку и направление сортировки из серверного allowlist. |
| RB109 | Rails render inline из HTTP-ввода | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) / A03:2021 | critical / medium | Не компилируйте params как шаблон; используйте фиксированный view. |
| RB110 | Ruby send выбирает HTTP-метод | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) / A03:2021 | critical / medium | Разрешайте dispatch только через карту известных операций. |
| RB111 | Rails send_file из HTTP-параметра | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Выбирайте файл внутри фиксированного каталога и проверяйте права пользователя. |

## RS

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| RS100 | DES в Rust | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) / A02:2021 | medium / medium | Используйте AES-GCM или ChaCha20-Poly1305 с уникальным nonce. |
| RS101 | Rust OpenSSL не проверяет hostname | [CWE-297](https://cwe.mitre.org/data/definitions/297.html) / A02:2021 | high / medium | Включите проверку hostname и используйте корректный SAN сертификата. |
| RS102 | Actix CORS разрешает любой origin | [CWE-942](https://cwe.mitre.org/data/definitions/942.html) / A01:2021 | medium / medium | Задайте явный allowlist origins и ограничьте credentialed-запросы. |
| RS103 | Actix раздаёт корневой каталог | [CWE-552](https://cwe.mitre.org/data/definitions/552.html) / A05:2021 | medium / medium | Раздавайте отдельный каталог публичных файлов, не текущий каталог или корень узла. |
| RS104 | Rocket использует нулевой secret key | [CWE-321](https://cwe.mitre.org/data/definitions/321.html) / A07:2021 | medium / medium | Сгенерируйте случайный SecretKey вне исходников и защищайте session cookies. |
| RS105 | Rust JWT отключает exp validation | [CWE-613](https://cwe.mitre.org/data/definitions/613.html) / A07:2021 | medium / medium | Включите проверку exp и ограничьте clock skew. |
| RS106 | Rust JWT отключает подпись | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) / A07:2021 | critical / medium | Используйте проверку подписи JWT и фиксированный список алгоритмов. |
| RS107 | Rust OpenSSL создаёт слабый RSA | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 | medium / medium | Используйте RSA не менее 2048 бит. |
| RS108 | Низкая память Argon2 Rust | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) / A02:2021 | medium / medium | Выберите memory/time cost Argon2 по актуальным требованиям и измерениям нагрузки. |
| RS109 | RSA PKCS1 v1.5 encryption Rust | [CWE-780](https://cwe.mitre.org/data/definitions/780.html) / A02:2021 | medium / medium | Используйте RSA-OAEP и исключите oracle по ответам ошибок дешифрования. |

## SWIFT

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| SWIFT100 | Credential в UserDefaults | [CWE-922](https://cwe.mitre.org/data/definitions/922.html) / A07:2021 | medium / medium | Храните credentials в Keychain с подходящим уровнем доступности. |
| SWIFT101 | Секрет в NSLog | [CWE-532](https://cwe.mitre.org/data/definitions/532.html) / A05:2021 | medium / medium | Удалите секреты из NSLog и применяйте централизованное маскирование. |
| SWIFT102 | WebView HTML из динамического значения | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) / A03:2021 | high / medium | Не загружайте недоверенный HTML в привилегированный WebView; очистите его и ограничьте навигацию. |
| SWIFT103 | WKWebView разрешает file URL access | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) / A05:2021 | medium / medium | Не включайте доступ file URL для WebView с недоверенным содержимым. |
| SWIFT104 | TLS trust exceptions в Swift | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 | high / medium | Не принимайте произвольные trust exceptions; используйте системную проверку TLS. |
| SWIFT105 | Swift задаёт слабый RSA-ключ | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 | medium / medium | Задайте RSA key size не менее 2048 бит. |
| SWIFT106 | CommonCrypto выбирает DES | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) / A02:2021 | medium / medium | Используйте современный AEAD-алгоритм и проверяйте authentication tag. |
| SWIFT107 | Swift отключает secure coding | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) / A08:2021 | high / medium | Включите requiresSecureCoding и задайте разрешённые классы для unarchiver. |
| SWIFT108 | GRDB SQL через Swift-интерполяцию | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Используйте GRDB arguments и placeholders вместо Swift-интерполяции. |
| SWIFT109 | Общедоступные POSIX permissions Swift | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) / A05:2021 | medium / medium | Назначайте минимальные permissions для файлов и каталогов. |

## SCALA

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| SCALA100 | Scala ToolBox выполняет код | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) / A03:2021 | critical / medium | Не выполняйте недоверенное AST; используйте фиксированную карту операций. |
| SCALA101 | Scala ToolBox разбирает HTTP-код | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) / A03:2021 | critical / medium | Не превращайте HTTP-ввод в компилируемый Scala-код. |
| SCALA102 | Twirl HtmlFormat.raw | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) / A03:2021 | high / medium | Используйте HtmlFormat.escape; очищайте HTML перед созданием raw-фрагмента. |
| SCALA103 | Slick вставляет SQL literal | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) / A03:2021 | critical / medium | Используйте обычную Slick-интерполяцию bind-параметров вместо '#$'. |
| SCALA104 | Akka CORS разрешает все origins | [CWE-942](https://cwe.mitre.org/data/definitions/942.html) / A01:2021 | medium / medium | Укажите ограниченный набор origins для Akka HTTP CORS. |
| SCALA105 | Scala Process запускает shell | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) / A03:2021 | critical / medium | Передавайте executable и аргументы без оболочки. |
| SCALA106 | Scala URL из HTTP-ввода | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) / A10:2021 | high / medium | Проверяйте URL и резолвинг IP по allowlist назначений. |
| SCALA107 | Play redirect из HTTP-ввода | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) / A01:2021 | medium / medium | Перенаправляйте только на разрешённые локальные пути. |
| SCALA108 | Play отдаёт HTTP-путь к файлу | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Выбирайте файл из контролируемого каталога и проверяйте разрешения. |
| SCALA109 | Play WS разрешает слабые шифры | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 | high / medium | Отключите allowWeakCiphers и используйте современный TLS cipher suite. |

## SH

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| SH100 | Shell trace может раскрыть секреты | [CWE-532](https://cwe.mitre.org/data/definitions/532.html) / A05:2021 | medium / medium | Отключайте xtrace перед обработкой секретов и не сохраняйте чувствительные аргументы в CI logs. |
| SH101 | Пароль curl в argv | [CWE-214](https://cwe.mitre.org/data/definitions/214.html) / A07:2021 | medium / medium | Используйте защищённый netrc или механизм credentials вне аргументов процесса. |
| SH102 | Shell использует DES encryption | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) / A02:2021 | medium / medium | Используйте проверенный формат AEAD вместо openssl enc с DES. |
| SH103 | Shell digest MD5 | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) / A02:2021 | medium / medium | Для криптографической целостности используйте SHA-256 или современную подпись. |
| SH104 | Shell создаёт слабый RSA-ключ | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) / A02:2021 | medium / medium | Создавайте RSA-ключ не менее 2048 бит и защищайте приватный файл. |
| SH105 | Shell устанавливает setuid | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) / A05:2021 | medium / medium | Не назначайте setuid без проверенной необходимости; используйте минимальные привилегии. |
| SH106 | Shell разрешает world-write | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) / A05:2021 | medium / medium | Не давайте запись всем пользователям; назначайте отдельную группу владельца. |
| SH107 | Docker CLI добавляет SYS_ADMIN | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) / A05:2021 | medium / medium | Удалите SYS_ADMIN/ALL и выдайте только необходимые capabilities. |
| SH108 | Docker CLI монтирует корень хоста | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) / A05:2021 | medium / medium | Не монтируйте корень узла; используйте выделенный volume с ограниченными правами. |
| SH109 | Docker CLI получает host network | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) / A05:2021 | medium / medium | Используйте отдельную сеть контейнера и явно публикуйте нужные порты. |
| SH110 | curl передаёт credentials через redirect | [CWE-522](https://cwe.mitre.org/data/definitions/522.html) / A02:2021 | high / medium | Используйте --location с проверкой назначения; не пересылайте credentials произвольным хостам. |
| SH111 | tar разрешает абсолютные пути | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) / A01:2021 | medium / medium | Распаковывайте недоверенные архивы с проверкой путей и без --absolute-names. |

## CFG

| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |
|---|---|---|---|---|
| CFG100 | Windows контейнер получает hostProcess | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) / A05:2021 | medium / medium | Отключите hostProcess вне обоснованных системных workloads. |
| CFG101 | Pod автоматически получает API token | [CWE-522](https://cwe.mitre.org/data/definitions/522.html) / A05:2021 | medium / medium | Выключите автоматический token mount, если workload не использует Kubernetes API. |
| CFG102 | Root filesystem контейнера допускает запись | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) / A05:2021 | medium / medium | Используйте readOnlyRootFilesystem=true и отдельные volumes для необходимых записей. |
| CFG103 | Kubernetes отключает proc masking | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) / A05:2021 | medium / medium | Используйте procMount: Default и ограничьте доступ к procfs. |
| CFG104 | Pod разделяет process namespace | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) / A05:2021 | medium / medium | Разделяйте process namespace только для проверенных контейнеров с одинаковой границей доверия. |
| CFG105 | Контейнер получает NET_RAW | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) / A05:2021 | medium / medium | Удалите NET_RAW, если приложение не требует raw sockets. |
| CFG106 | Dashboard разрешает skip login | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) / A07:2021 | high / medium | Отключите skip login и настройте проверяемую аутентификацию Dashboard. |
| CFG107 | Опубликован Docker API port 2375 | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) / A05:2021 | high / medium | Не публикуйте plaintext Docker API; используйте Unix socket или защищённый TLS endpoint. |
| CFG108 | Docker доверяет insecure registry | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Используйте HTTPS registry с доверенным сертификатом. |
| CFG109 | S3 отключает Public Access Block | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) / A01:2021 | medium / medium | Включите Public Access Block; публичный доступ разрешайте только по утверждённой политике. |
| CFG110 | Cloud storage без encryption at rest | [CWE-311](https://cwe.mitre.org/data/definitions/311.html) / A02:2021 | medium / medium | Включите encryption at rest с защищённым KMS-ключом. |
| CFG111 | База данных публично доступна | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) / A01:2021 | medium / medium | Закройте публичный доступ к БД и ограничьте сетевые источники. |
| CFG112 | KMS key rotation отключён | [CWE-320](https://cwe.mitre.org/data/definitions/320.html) / A02:2021 | medium / medium | Включите поддерживаемую rotation policy и контролируйте жизненный цикл ключей. |
| CFG113 | Database deletion protection отключён | [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) / A05:2021 | medium / medium | Включите deletion protection для production-БД и ограничьте право удаления. |
| CFG114 | Redshift не требует SSL | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) / A02:2021 | high / medium | Включите require_ssl и проверяйте сертификат при подключении. |
| CFG115 | Azure разрешает публичные blobs | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) / A01:2021 | medium / medium | Отключите public blob access и используйте ограниченные permissions/SAS. |
| CFG116 | Elasticsearch отключает security | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) / A07:2021 | high / medium | Включите authentication/authorization Elasticsearch и TLS для сетевого доступа. |
| CFG117 | MongoDB отключает authorization | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) / A07:2021 | high / medium | Установите authorization: enabled и ограничьте роли пользователей. |
| CFG118 | Redis отключает protected mode | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) / A07:2021 | high / medium | Включите protected-mode и настройте ACL, bind и TLS. |
| CFG119 | MySQL запускается без grants | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) / A07:2021 | high / medium | Удалите skip-grant-tables из production-конфигурации. |
| CFG120 | Nginx не проверяет upstream TLS | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 | high / medium | Включите proxy_ssl_verify и настройте trusted CA/hostname upstream. |
| CFG121 | HAProxy не проверяет backend TLS | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) / A02:2021 | high / medium | Используйте verify required и доверенный CA для backend TLS. |
| CFG122 | Nginx публикует directory listing | [CWE-548](https://cwe.mitre.org/data/definitions/548.html) / A05:2021 | medium / medium | Отключите autoindex для непубличных каталогов и исключите секретные файлы. |
| CFG123 | Spring Actuator публикует все endpoints | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) / A05:2021 | medium / medium | Публикуйте только необходимые Actuator endpoints с аутентификацией. |

## Проверки

tests/rules-expansion.test.ts содержит независимые опасные/безопасные примеры
для всех 200 правил. Проверяются ID, метаданные, ограничение по языку,
позиции CRLF, несколько файлов, ZIP и скорость больших безопасных сканирований.

## Первичные источники

- [Gitleaks configuration](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml): форматы credentials.
- [Python security](https://docs.python.org/3/library/security_warnings.html): форматы объектов и опасные API.
- [Python logging.config](https://docs.python.org/3/library/logging.config.html): verify сетевой конфигурации.
- [OWASP XML prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html): XML factories, StAX, XSLT.
- [Electron security](https://www.electronjs.org/docs/latest/tutorial/security): renderer и mixed content.
- [Microsoft security rules](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/security-warnings): XML и .NET settings.
- [PHP Phar metadata](https://www.php.net/manual/en/phar.getmetadata.php): getMetadata и unserializeOptions.
- [Go SSH CertChecker](https://pkg.go.dev/golang.org/x/crypto/ssh#CertChecker): trusted user authority.
- [Rust JWT Validation](https://docs.rs/jsonwebtoken/latest/jsonwebtoken/struct.Validation.html): подпись и claims.
- [Apple trust exceptions](https://developer.apple.com/documentation/security/sectrustsetexceptions(_:_:)): TLS trust exceptions.
- [Kubernetes Pod Security](https://kubernetes.io/docs/concepts/security/pod-security-standards/): ограничения контейнеров.
