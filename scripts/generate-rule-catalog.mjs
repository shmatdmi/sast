import { mkdirSync, writeFileSync } from "node:fs";
import { createExpansionRules } from "../app/lib/sast-rules-expansion.ts";
import { createAdditionalRules } from "../app/lib/sast-rules-additional.ts";
import { createAdvancedRules } from "../app/lib/sast-rules-advanced.ts";
import { createCoverageRules } from "../app/lib/sast-rules-coverage.ts";
import { createHttpCatalogMarkdown } from "./lib/http-rule-catalog.mjs";
import { createFrameworkCatalogMarkdown } from "./lib/framework-rule-catalog.mjs";
import { ruleCount } from "../app/lib/sast-engine.ts";

const rules = createExpansionRules(["все поддерживаемые языки"]);
const groups = Map.groupBy(rules, (rule) => rule.id.replace(/\d+$/, ""));
let markdown = `# Набор из ${rules.length} дополнительных SAST-правил

Общая база содержит ${ruleCount} статических правил. Этот каталог описывает
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
`;
for (const [group, items] of groups) markdown += `| ${group} | ${items.length} |\n`;
for (const [group, items] of groups) {
  markdown += `\n## ${group}\n\n| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |\n|---|---|---|---|---|\n`;
  for (const rule of items) {
    const escape = (value) => value.replaceAll("|", "\\|").replaceAll("\n", " ");
    markdown += `| ${rule.id} | ${escape(rule.title)} | [${rule.cwe}](${rule.references[0]}) / ${rule.owasp} | ${rule.severity} / ${rule.confidence} | ${escape(rule.recommendation)} |\n`;
  }
}
markdown += `
## Проверки

tests/rules-expansion.test.ts содержит независимые опасные/безопасные примеры
для всех ${rules.length} правил. Проверяются ID, метаданные, ограничение по языку,
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
`;
mkdirSync(new URL("../docs/", import.meta.url), { recursive: true });
writeFileSync(new URL("../docs/security-rules-expansion.md", import.meta.url), markdown);
console.log(`Generated ${rules.length} rules; total ${ruleCount}.`);

function generateSupplement(name, startId, additional) {
  const additionalGroups = Map.groupBy(additional, (rule) => rule.id.replace(/\d+$/, ""));
  const cell = (value) => value.replaceAll("&", "&amp;").replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;").replaceAll("|", "\\|").replaceAll("\n", " ");
  let additionalMarkdown = `# Ещё ${additional.length} SAST-правил

Общая база: **${ruleCount} статических правил** и 6 отдельных source-to-sink проверок.
Этот набор находится в app/lib/sast-rules-${name}.ts, ID начинаются с ${startId}.
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
`;
  for (const [family, items] of additionalGroups) additionalMarkdown += `| ${family} | ${items.length} |\n`;
  for (const [family, items] of additionalGroups) {
    additionalMarkdown += `\n## ${family}\n\n| ID | Проверка | CWE / OWASP | Риск / уверенность | Рекомендация |\n|---|---|---|---|---|\n`;
    for (const rule of items) {
      additionalMarkdown += `| ${rule.id} | ${cell(rule.title)} | [${rule.cwe}](${rule.references[0]}) / ${rule.owasp} | ${rule.severity} / ${rule.confidence} | ${cell(rule.recommendation)} |\n`;
    }
  }
  additionalMarkdown += `
## Проверки

Для всех ${additional.length} правил в tests/fixtures/${name}-rules.json есть опасный пример
и безопасная альтернатива. tests/${name}-rules.test.ts проверяет находки через общий движок,
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
`;
  writeFileSync(new URL(`../docs/security-rules-${name}.md`, import.meta.url), additionalMarkdown);
  console.log(`Generated ${additional.length} ${name} rules; total ${ruleCount}.`);
}

generateSupplement("additional", 200, createAdditionalRules());
generateSupplement("advanced", 300, createAdvancedRules());
const coverage = createCoverageRules();
writeFileSync(new URL("../docs/security-rules-coverage.md", import.meta.url), `# Охват 20 языков и форматов

Общий каталог: **${ruleCount} статических правил**. Добавлены C, C++, Dart, Elixir,
Lua и PowerShell: по 5 отдельных проверок для каждого языка и 6 общих проверок
секретов для всех шести языков, всего ${coverage.length} новых определений.

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
${coverage.map((rule) => `| ${rule.id} | ${rule.title} | ${rule.languages.join(", ")} | [${rule.cwe}](${rule.references[0]}) | ${rule.severity} |`).join("\n")}

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
`);
writeFileSync(new URL("../docs/security-rules-http.md", import.meta.url), createHttpCatalogMarkdown());
writeFileSync(new URL("../docs/security-rules-framework.md", import.meta.url), createFrameworkCatalogMarkdown());

writeFileSync(new URL("../docs/security-rules-composed.md", import.meta.url), `# Составные строки с HTTP-вводом

Общая база: **${ruleCount} определений**. Набор добавляет 50000 эвристических определений: 19000 конкатенаций с префиксом, 19000 с суффиксом, 6000 JavaScript template literals и 6000 Python f-strings. Это варианты существующих API и источников, а не новые классы уязвимостей.

Исходник: app/lib/sast-rules-composed.ts. Прежние 20000 определений и ID сохраняются. Снимок БД: 0009_composed_rule_catalog_70000.

Поддержаны прямой первый аргумент, строковые литералы и цепочки обращений к свойствам/индексам и методы источника без аргументов или с одним строковым аргументом. Вложенные вызовы, экранированные литералы, многострочные строки и aliases не покрываются. Комментарии и примеры в строках могут совпасть; типы, импорты и валидация требуют ручной проверки. Конкатенация с префиксом и суффиксом одновременно может дать две находки.

Метаданные CWE, риск и рекомендации унаследованы от исходных проверок. Уверенность medium. Сканер браузера и API использует индекс обязательных имён API.

Проверки: tests/composed-rules.test.ts. Обновление документации: npm run rules:catalog.
`);

writeFileSync(new URL("../docs/security-rules-expressions.md", import.meta.url), `# Формы выражений с HTTP-вводом

Общая база: **${ruleCount} статических определений** и 6 алгоритмических проверок потоков данных. Набор добавляет 80000 определений: по 19000 для ввода в скобках, конкатенации с префиксом/суффиксом вокруг ввода в скобках и ввода со значением по умолчанию; ещё 4000 — интерполяция исходных HTTP-источников. Это варианты 400 существующих записей API, а не новые классы уязвимостей.

Источники: app/lib/sast-rules-expressions.ts. ID EXPR_*. Прежние 70000 определений, их ID, порядок и метаданные сохранены. Снимок БД: 0010_expression_rule_catalog_150000.

Проверяется прямой первый аргумент. Методы источников допускают ноль аргументов либо один строковый литерал; поддержаны свойства и индексы. Значение по умолчанию: JavaScript/Ruby ||, Python or, PHP ??. Интерполяция: JavaScript template literal, Python f-string, PHP complex curly syntax, Ruby #{...}. Тип исходного значения не устанавливается: коллекции и объекты требуют проверки вручную. Ruby и PHP поддерживают только двойные кавычки для интерполяции.

Нет разрешения импортов, aliases, AST или межфайлового анализа. Вложенные вызовы, экранированные и многострочные литералы не покрываются. Комментарии и примеры могут совпасть. Уверенность medium, метаданные CWE и рекомендации унаследованы. Существующие более общие проверки могут дать дополнительные находки.

Все определения проверяются опасными и отрицательными примерами в отдельных процессах по языкам, чтобы ограничить память компилятора RegExp. Интеграционные проверки: tests/expression-rules.test.ts. Общий тестовый набор ограничен двумя одновременными файлами. Сканер сохраняет индекс обязательного имени API.

Обновление: npm run rules:catalog.
`);
