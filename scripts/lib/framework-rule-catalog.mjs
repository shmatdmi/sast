import { createFrameworkRules } from '../../app/lib/sast-rules-framework.ts';
import { createRuleSnapshot } from './sast-rule-seed.mjs';

export function createFrameworkCatalogMarkdown() {
  const snapshot = createRuleSnapshot();
  return `# Расширенное покрытие HTTP-фреймворков

Общая база: **${snapshot.entries.length} определений правил** и 6 алгоритмических проверок.
Этот набор добавляет 15000 определений к прежним 5000:

| Семейство | API | Новых способов доступа к HTTP-вводу | Определений |
|---|---:|---:|---:|
| JavaScript / TypeScript | 150 | 40 | 6000 |
| Python | 150 | 40 | 6000 |
| PHP | 50 | 30 | 1500 |
| Ruby | 50 | 30 | 1500 |

Прежние HTTP-правила сохраняют свои ID и определения. Все 19000 HTTP/framework
определений используют 400 записей API; увеличение числа определений отражает
дополнительные способы чтения ввода, а не новые классы уязвимостей или 19000 API.

Проверяется прямой первый аргумент: свойства, методы чтения HTTP-ввода и прямой await
для body readers. Объекты, коллекции, загруженные файлы, уже приведённые к числу значения
и данные из подписанных cookies остаются сигналами для ручного рассмотрения:
пригодность значения для конкретного API и достаточность защиты не устанавливаются.
Некоторые API и аксессоры относятся к старым версиям фреймворков.
Имена объектов не разрешаются по импортам. Уверенность всех новых правил — medium.
Вызовы Ruby без скобок, aliases, межфайловые потоки, другие аргументы и wrappers
не распознаются. Пересечения с более общими прежними проверками возможны.
Первый аргумент validate(source) не считается прямым потоком; это ограничение
эвристики, а не подтверждение безопасности произвольной функции validate.

Для скорости каталог индексируется по языку и обязательному литералу API.
Пропускаются только группы API, отсутствующих в тексте файла; исходный порядок
находок сохраняется. Метаданные и снимки БД не зависят от этого индекса.

Миграция 0008_framework_rule_catalog_20000 сохраняет новый снимок в sast_rules,
не заменяя наборы на 1000, 2000 и 5000 правил. Сканер использует встроенный набор.
Набор: ${snapshot.name}. SHA-256: ${snapshot.contentHash}.

Исходник: app/lib/sast-rules-framework.ts. Проверка: tests/framework-rules.test.ts.
Обновление: npm run rules:catalog.

Источники: [Tornado](https://www.tornadoweb.org/en/stable/web.html),
[Symfony HttpFoundation](https://symfony.com/doc/current/components/http_foundation.html),
[Rails Action Controller](https://guides.rubyonrails.org/action_controller_overview.html),
[Hono request](https://hono.dev/docs/api/request),
[NextRequest](https://nextjs.org/docs/app/api-reference/functions/next-request),
[Laravel requests](https://laravel.com/docs/requests).

| ID | API и способ доступа | CWE |
|---|---|---|
` + createFrameworkRules().map(r => `| ${r.id} | ${r.title} | ${r.cwe} |`).join('\n') + '\n';
}
