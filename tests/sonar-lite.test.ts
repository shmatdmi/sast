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
