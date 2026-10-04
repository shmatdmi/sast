import { mkdirSync, writeFileSync } from "node:fs";
import { createExpansionRules } from "../app/lib/sast-rules-expansion.ts";
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
