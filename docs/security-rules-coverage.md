# Охват 20 языков и форматов

Общий каталог: **150036 статических правил**. Добавлены C, C++, Dart, Elixir,
Lua и PowerShell: по 5 отдельных проверок для каждого языка и 6 общих проверок
секретов для всех шести языков, всего 36 новых определений.

Список групп и расширений находится в app/lib/sast-languages.ts. Его используют
карточка «Охват», выбор языка, загрузка файлов и ZIP, определение языка и API.
Заголовок .h определяется как C++, если в нём есть признаки C++ (например namespace
или std::), иначе как C. Расширение .C считается C++.

Проверки эвристические: они не строят AST, не отслеживают все потоки данных и могут
совпасть в комментариях и строковых примерах. Опасные API требуют проверки
границы доверия; слабый хеш может применяться вне криптографии. Уверенность medium.
Проверка формата секрета не проверяет его действительность по сети.

| ID | Проверка | Языки | CWE | Риск |
|---|---|---|---|---|
| C001 | C: чтение gets без ограничения длины | c | [CWE-120](https://cwe.mitre.org/data/definitions/120.html) | high |
| C002 | C: копирование без размера буфера | c | [CWE-120](https://cwe.mitre.org/data/definitions/120.html) | high |
| C003 | C: динамическая строка формата | c | [CWE-134](https://cwe.mitre.org/data/definitions/134.html) | high |
| C004 | C: динамическая команда оболочки | c | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | critical |
| C005 | C: слабый хеш MD5 или SHA-1 | c | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | high |
| CPP001 | C++: копирование без размера буфера | cpp | [CWE-120](https://cwe.mitre.org/data/definitions/120.html) | high |
| CPP002 | C++: динамическая строка формата | cpp | [CWE-134](https://cwe.mitre.org/data/definitions/134.html) | high |
| CPP003 | C++: динамическая команда оболочки | cpp | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | critical |
| CPP004 | C++: небезопасное имя временного файла | cpp | [CWE-377](https://cwe.mitre.org/data/definitions/377.html) | high |
| CPP005 | C++: слабый хеш MD5 или SHA-1 | cpp | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | high |
| DART001 | Dart: принимается любой TLS-сертификат | dart | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | high |
| DART002 | Dart: процесс запускается через shell | dart | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | critical |
| DART003 | Dart: интерполяция в SQL-запросе | dart | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | critical |
| DART004 | Dart: слабый хеш MD5 или SHA-1 | dart | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | high |
| DART005 | Dart: предсказуемое случайное значение секрета | dart | [CWE-338](https://cwe.mitre.org/data/definitions/338.html) | high |
| ELIXIR001 | Elixir: выполнение динамического кода | elixir | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | critical |
| ELIXIR002 | Elixir: динамическая команда оболочки | elixir | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | critical |
| ELIXIR003 | Elixir: интерполяция SQL в Ecto | elixir | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | critical |
| ELIXIR004 | Elixir: десериализация Erlang-термов | elixir | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | high |
| ELIXIR005 | Elixir: динамическое создание атомов | elixir | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | high |
| LUA001 | Lua: динамическая команда оболочки | lua | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | critical |
| LUA002 | Lua: динамическая команда io.popen | lua | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | critical |
| LUA003 | Lua: загрузка динамического кода | lua | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | critical |
| LUA004 | Lua: SQL собирается конкатенацией | lua | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | critical |
| LUA005 | Lua: HTML из параметров OpenResty | lua | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | high |
| PS001 | PowerShell: выполнение строки как кода | powershell | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | critical |
| PS002 | PowerShell: отключена проверка TLS | powershell | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | high |
| PS003 | PowerShell: пароль в открытом строковом литерале | powershell | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | critical |
| PS004 | PowerShell: безусловный callback сертификата | powershell | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | high |
| PS005 | PowerShell: интерполяция в SQL-команде | powershell | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | critical |
| NEWSEC001 | Секрет в исходном коде | c, cpp, dart, elixir, lua, powershell | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | critical |
| NEWSEC002 | Приватный ключ в исходном коде | c, cpp, dart, elixir, lua, powershell | [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | critical |
| NEWSEC003 | AWS access key в исходном коде | c, cpp, dart, elixir, lua, powershell | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | critical |
| NEWSEC004 | GitHub token в исходном коде | c, cpp, dart, elixir, lua, powershell | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | critical |
| NEWSEC005 | GitLab token в исходном коде | c, cpp, dart, elixir, lua, powershell | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | critical |
| NEWSEC006 | Пароль в URI базы данных | c, cpp, dart, elixir, lua, powershell | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | critical |

Опасные и безопасные примеры всех новых правил: tests/fixtures/coverage-rules.json.
Проверки общего движка, CRLF, языков, ZIP, JSON API и неизменности прежнего каталога:
tests/coverage-rules.test.ts. Новые определения добавлены после прежних 150000;
миграция 0011_coverage_20_languages переносит связи родительского снимка в SQL и
импортирует только новые определения. Предыдущие снимки сохраняются.

Первичные источники:
- [CERT C: строки и границы буферов](https://wiki.sei.cmu.edu/confluence/display/c/STR31-C.+Guarantee+that+storage+for+strings+has+sufficient+space+for+character+data+and+the+null+terminator)
- [CERT C: строки формата](https://wiki.sei.cmu.edu/confluence/display/c/FIO30-C.+Exclude+user+input+from+format+strings)
- [Dart: проверка TLS](https://api.dart.dev/dart-io/HttpClient/badCertificateCallback.html)
- [Dart: процессы и shell](https://api.dart.dev/dart-io/Process/run.html)
- [Phoenix: SQL, динамический код и Erlang-термы](https://phoenix.hexdocs.pm/security.html)
- [Lua: стандартные функции](https://www.lua.org/manual/5.4/manual.html)
- [PowerShell: предотвращение script injection](https://learn.microsoft.com/en-us/powershell/scripting/security/preventing-script-injection)

Обновление каталога: npm run rules:catalog.
