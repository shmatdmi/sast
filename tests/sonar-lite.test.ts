import assert from "node:assert/strict";
import test from "node:test";
import { scanCodeQuality } from "../app/lib/sonar-lite.ts";

test("calculates quality metrics and fails the gate for serious issues", () => {
  const result = scanCodeQuality([{ name: "api.js", code: [
    "// TODO remove temporary code",
    "const password = 'hardcoded-secret';",
    "function run(input) {",
    "  if (input == 'admin') eval(input);",
    "  console.log(input);",
    "}",
  ].join("\n") }]);
  assert.equal(result.gate, "failed");
  assert.ok(result.counts.vulnerability >= 2);
  assert.ok(result.counts.bug >= 1);
  assert.ok(result.counts.code_smell >= 2);
  assert.ok(result.metrics.complexity >= 1);
  assert.ok(result.metrics.debtMinutes > 0);
});

test("passes concise code and detects repeated lines", () => {
  const clean = scanCodeQuality([{ name: "math.ts", code: "export const add = (a: number, b: number) => a + b;" }]);
  assert.equal(clean.gate, "passed");
  assert.equal(clean.rating, "A");
  assert.equal(clean.issues.length, 0);
  const duplicated = scanCodeQuality([{ name: "copy.ts", code: "const repeatedValue = calculateValue();\nconst repeatedValue = calculateValue();" }]);
  assert.equal(duplicated.metrics.duplicatedLines, 1);
  assert.equal(duplicated.metrics.duplicationPercent, 50);
});

test("empty input returns finite zero metrics and a passing quality gate", () => {
  assert.deepEqual(scanCodeQuality([]), {
    gate: "passed", rating: "A", issues: [],
    metrics: { files: 0, lines: 0, codeLines: 0, commentLines: 0, complexity: 0, duplicatedLines: 0, duplicationPercent: 0, debtMinutes: 0 },
    counts: { bug: 0, vulnerability: 0, code_smell: 0 },
  });
});

test("CRLF, blank lines and comment styles contribute to the correct metrics", () => {
  const result = scanCodeQuality([{ name: "app.ts", code: "// comment\r\n# comment\r\n/* comment */\r\n* comment\r\n\r\nconst ok = true;" }]);
  assert.equal(result.metrics.lines, 6);
  assert.equal(result.metrics.commentLines, 4);
  assert.equal(result.metrics.codeLines, 1);
  assert.equal(result.metrics.duplicatedLines, 0);
  assert.equal(result.gate, "passed");
});

const qualityRules = [
  ["SL1001", "eval(input);", "JSON.parse(input);", "vulnerability", "blocker", 30],
  ["SL1002", "const password = 'secret-value';", "const password = process.env.PASSWORD;", "vulnerability", "critical", 20],
  ["SL2001", "try { work(); } catch (error) {}", "try { work(); } catch (error) { throw error; }", "bug", "major", 10],
  ["SL2002", "a == b;", "a === b;", "bug", "major", 5],
  ["SL3001", "// TODO implement this", "// completed", "code_smell", "minor", 5],
  ["SL3002", "console.debug(value);", "logger.info(value);", "code_smell", "minor", 5],
  ["SL3003", "x".repeat(161), "x".repeat(160), "code_smell", "minor", 2],
] as const;
for (const [rule, unsafe, safe, type, severity, effort] of qualityRules) {
  test(`${rule}: detection, safe alternative, location and debt`, () => {
    const result = scanCodeQuality([{ name: "src/app.js", code: `\n${unsafe}` }]);
    const issue = result.issues.find(issue => issue.rule === rule);
    assert.ok(issue);
    assert.equal(issue.file, "src/app.js");
    assert.equal(issue.line, 2);
    assert.equal(issue.id, `src/app.js:2:${rule}`);
    assert.equal(issue.type, type);
    assert.equal(issue.severity, severity);
    assert.equal(issue.effortMinutes, effort);
    assert.ok(result.metrics.debtMinutes >= effort);
    assert.ok(!scanCodeQuality([{ name: "safe.js", code: safe }]).issues.some(issue => issue.rule === rule));
  });
}

test("duplicated code is tracked across files but repeated comments and short lines are ignored", () => {
  const result = scanCodeQuality([
    { name: "a.ts", code: "const repeated = compute();\n// repeated comment\nx();" },
    { name: "b.ts", code: "  const repeated = compute();\n// repeated comment\nx();" },
    { name: "c.ts", code: "const repeated = compute();" },
  ]);
  assert.equal(result.metrics.files, 3);
  assert.equal(result.metrics.duplicatedLines, 2);
  assert.equal(result.metrics.codeLines, 5);
  assert.equal(result.metrics.duplicationPercent, 40);
  assert.equal(result.gate, "failed");
});

test("quality ratings cover A through E with predictable issue penalties", () => {
  const cases = [
    ["const ok = true;", "A"],
    ["a == b;\nc != d;", "B"],
    ["a == b;\nc != d;\ne == f;", "C"],
    ["eval(input);\na == b;", "D"],
    ["eval(input);\nconst password = 'secret-value';", "E"],
  ] as const;
  for (const [code, rating] of cases) assert.equal(scanCodeQuality([{ name: "app.js", code }]).rating, rating);
});

test("quality gate distinguishes complexity and duplication boundary values", () => {
  const atBoundary = ["if (ok) work();", ...Array.from({ length: 19 }, (_, i) => `const value${i} = ${i};`)];
  const clean = scanCodeQuality([{ name: "app.js", code: atBoundary.join("\n") }]);
  assert.equal(clean.gate, "passed");
  assert.equal(scanCodeQuality([{ name: "complex.js", code: "if (ok) work();" }]).gate, "failed");
  const tenLines = Array.from({ length: 9 }, (_, i) => `const value${i} = ${i};`);
  assert.equal(scanCodeQuality([{ name: "boundary.js", code: [...tenLines, tenLines[0]].join("\n") }]).metrics.duplicationPercent, 10);
  assert.equal(scanCodeQuality([{ name: "boundary.js", code: [...tenLines, tenLines[0]].join("\n") }]).gate, "passed");
  assert.equal(scanCodeQuality([{ name: "over.js", code: [...tenLines, tenLines[0], tenLines[0]].join("\n") }]).gate, "failed");
});
