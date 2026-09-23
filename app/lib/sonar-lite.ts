export type SonarIssueType = "bug" | "vulnerability" | "code_smell";
export type SonarIssueSeverity = "blocker" | "critical" | "major" | "minor";
export type SonarIssue = { id: string; type: SonarIssueType; severity: SonarIssueSeverity; file: string; line: number; message: string; rule: string; effortMinutes: number };
export type SonarSource = { name: string; code: string };
export type SonarResult = {
  gate: "passed" | "failed"; rating: "A" | "B" | "C" | "D" | "E"; issues: SonarIssue[];
  metrics: { files: number; lines: number; codeLines: number; commentLines: number; complexity: number; duplicatedLines: number; duplicationPercent: number; debtMinutes: number };
  counts: Record<SonarIssueType, number>;
};

type Rule = { rule: string; pattern: RegExp; type: SonarIssueType; severity: SonarIssueSeverity; message: string; effortMinutes: number };
const rules: Rule[] = [
  { rule: "SL1001", pattern: /\b(eval|exec)\s*\(/, type: "vulnerability", severity: "blocker", message: "Не выполняйте динамически сформированный код.", effortMinutes: 30 },
  { rule: "SL1002", pattern: /(?:password|passwd|secret|api[_-]?key)\s*[:=]\s*["'][^"']{4,}["']/i, type: "vulnerability", severity: "critical", message: "Секрет не должен храниться непосредственно в исходном коде.", effortMinutes: 20 },
  { rule: "SL2001", pattern: /catch\s*\([^)]*\)\s*\{\s*\}/, type: "bug", severity: "major", message: "Пустой catch скрывает ошибку и затрудняет диагностику.", effortMinutes: 10 },
  { rule: "SL2002", pattern: /(^|[^=!])==([^=]|$)|(^|[^!])!=([^=]|$)/, type: "bug", severity: "major", message: "Используйте строгое сравнение, чтобы избежать неявного преобразования типов.", effortMinutes: 5 },
  { rule: "SL3001", pattern: /\b(TODO|FIXME|HACK)\b/i, type: "code_smell", severity: "minor", message: "Незавершённая работа увеличивает технический долг.", effortMinutes: 5 },
  { rule: "SL3002", pattern: /\b(console\.(log|debug)|print\s*\()/, type: "code_smell", severity: "minor", message: "Отладочный вывод следует заменить штатным логированием или удалить.", effortMinutes: 5 },
  { rule: "SL3003", pattern: /.{161,}/, type: "code_smell", severity: "minor", message: "Слишком длинная строка ухудшает читаемость кода.", effortMinutes: 2 },
];

function isComment(line: string) { const value = line.trim(); return value.startsWith("//") || value.startsWith("#") || value.startsWith("/*") || value.startsWith("*"); }
export function scanCodeQuality(sources: SonarSource[]): SonarResult {
  const issues: SonarIssue[] = []; let lines = 0; let codeLines = 0; let commentLines = 0; let complexity = 0; let duplicatedLines = 0;
  const occurrences = new Map<string, number>();
  for (const source of sources) {
    source.code.split(/\r?\n/).forEach((line, index) => {
      lines += 1; const trimmed = line.trim(); if (!trimmed) return;
      if (isComment(line)) commentLines += 1; else codeLines += 1;
      complexity += (line.match(/\b(if|else if|for|while|case|catch)\b|&&|\|\||\?/g) ?? []).length;
      if (!isComment(line) && trimmed.length >= 12) occurrences.set(trimmed, (occurrences.get(trimmed) ?? 0) + 1);
      for (const rule of rules) if (rule.pattern.test(line)) issues.push({ id: `${source.name}:${index + 1}:${rule.rule}`, type: rule.type, severity: rule.severity, file: source.name, line: index + 1, message: rule.message, rule: rule.rule, effortMinutes: rule.effortMinutes });
    });
  }
  for (const count of occurrences.values()) if (count > 1) duplicatedLines += count - 1;
  const duplicationPercent = codeLines ? Math.round((duplicatedLines / codeLines) * 1000) / 10 : 0;
  const debtMinutes = issues.reduce((sum, issue) => sum + issue.effortMinutes, 0);
  const blockers = issues.filter((issue) => issue.severity === "blocker").length;
  const criticals = issues.filter((issue) => issue.severity === "critical").length;
  const majors = issues.filter((issue) => issue.severity === "major").length;
  const gate = blockers || criticals || duplicationPercent > 10 || (codeLines > 0 && complexity / codeLines > .35) ? "failed" : "passed";
  const penalty = blockers * 35 + criticals * 20 + majors * 8 + Math.min(20, issues.length) + Math.min(15, duplicationPercent);
  const rating = penalty >= 55 ? "E" : penalty >= 40 ? "D" : penalty >= 25 ? "C" : penalty >= 10 ? "B" : "A";
  return { gate, rating, issues, metrics: { files: sources.length, lines, codeLines, commentLines, complexity, duplicatedLines, duplicationPercent, debtMinutes }, counts: { bug: issues.filter((item) => item.type === "bug").length, vulnerability: issues.filter((item) => item.type === "vulnerability").length, code_smell: issues.filter((item) => item.type === "code_smell").length } };
}
