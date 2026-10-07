import { createHttpRules } from '../../app/lib/sast-rules-http.ts';
import { createRuleSnapshot } from './sast-rule-seed.mjs';

export function createHttpCatalogMarkdown() {
  const snapshot = createRuleSnapshot();
  return `# HTTP-ввод в опасных API

База содержит ${snapshot.entries.length} статических правил и 6 алгоритмических проверок потока данных.
Новый набор содержит **4000 сочетаний: 400 API × 10 каналов HTTP-ввода**.
Это 400 API, а не 4000 новых классов уязвимостей. По 1500 правил для JavaScript/TypeScript
и Python, по 500 для PHP и Ruby. Дополнительно остаются прежние 1000 статических правил.

Правила распознают только прямую передачу HTTP-ввода первым аргументом.
Они не отслеживают переменные, aliases импортов, middleware и межфайловые потоки.
Вызовы Ruby без скобок не распознаются. Для PHP распознаются superglobals и Symfony
ParameterBag, для Ruby — Rails/Rack params, cookies и HTTP-часть request.env.
Имя объекта и API не разрешается по импортам: это эвристика с уверенностью medium.
Проверенные wrappers не считаются прямым вводом. Уверенность medium: находка требует
проверки контекста и применённых защит. В API запуска процессов без shell проверяется
выбор недоверенного executable; фиксированный executable с массивом аргументов допустим.
SQL с фиксированным текстом и отдельными параметрами не соответствует этим правилам.
Набор не проверяет другие аргументы, HTTP options-объекты и присваивания DOM.
Возможны пересечения с прежними более общими правилами; число определений
не равно числу уникальных типов ошибок.

Исходник: app/lib/sast-rules-http.ts. Миграции 0006 и 0007 сохраняют снимки на
2000 и 5000 правил в sast_rules, не изменяя исходный набор и его версии.
Текущий общий набор: ${snapshot.name}. SHA-256: ${snapshot.contentHash}.
Дополнительные способы доступа к вводу описаны в security-rules-framework.md.

Обновление: npm run rules:catalog. Проверка: tests/http-rules.test.ts.

Источники: [Node child_process](https://nodejs.org/api/child_process.html),
[Python subprocess](https://docs.python.org/3/library/subprocess.html),
[Express request](https://expressjs.com/en/4x/api/),
[Django request](https://docs.djangoproject.com/en/stable/ref/request-response/).

| ID | API и источник | CWE |
|---|---|---|
` + createHttpRules().map(r => `| ${r.id} | ${r.title} | ${r.cwe} |`).join('\n') + '\n';
}
