"use client";
import { useState } from "react";
import { AlertIcon, CheckIcon, CodeIcon } from "./icons";
import type { SonarResult, SonarSource } from "../lib/sonar-lite";

const typeLabels = { bug: "Ошибка", vulnerability: "Уязвимость", code_smell: "Code smell" };
const severityLabels = { blocker: "Blocker", critical: "Critical", major: "Major", minor: "Minor" };
type Props = { sources: SonarSource[]; result: SonarResult | null };

export default function SonarLite({ sources, result }: Props) {
  const [showAll, setShowAll] = useState(false);
  const hasCode = sources.some((source) => source.code.trim());
  const visibleIssues = result?.issues.slice(0, showAll ? undefined : 10) ?? [];
  const hiddenCount = Math.max(0, (result?.issues.length ?? 0) - 10);
  return <section className="sonar-panel" id="sonar"><div className="panel-header"><div><span className="panel-dot sonar-dot" /><div><h2>Sonar Lite</h2><p>Упрощённый локальный анализ качества кода</p></div></div></div>
    {!result ? <div className="sonar-empty"><CodeIcon size={30} /><h3>{hasCode ? "Код готов к проверке" : "Сначала добавьте исходный код"}</h3><p>Сканер рассчитает метрики, технический долг и Quality Gate, а результат сохранится для указанного релиза.</p></div> : <>
      <div className="sonar-summary"><article className={`quality-gate ${result.gate}`}><span>{result.gate === "passed" ? <CheckIcon size={22} /> : <AlertIcon size={22} />}</span><div><small>QUALITY GATE</small><strong>{result.gate === "passed" ? "Пройден" : "Не пройден"}</strong></div></article><article><small>Рейтинг</small><strong className={`rating rating-${result.rating.toLowerCase()}`}>{result.rating}</strong></article><article><small>Ошибки</small><strong>{result.counts.bug}</strong></article><article><small>Уязвимости</small><strong>{result.counts.vulnerability}</strong></article><article><small>Code smells</small><strong>{result.counts.code_smell}</strong></article></div>
      <div className="sonar-metrics"><span><small>Строк кода</small><strong>{result.metrics.codeLines}</strong></span><span><small>Сложность</small><strong>{result.metrics.complexity}</strong></span><span><small>Дублирование</small><strong>{result.metrics.duplicationPercent}%</strong></span><span><small>Технический долг</small><strong>{result.metrics.debtMinutes} мин</strong></span><span><small>Файлов</small><strong>{result.metrics.files}</strong></span></div>
      <div className="sonar-issues">{result.issues.length ? <>{visibleIssues.map((issue) => <article key={issue.id}><span className={`sonar-severity ${issue.severity}`}>{severityLabels[issue.severity]}</span><div><strong>{issue.message}</strong><small>{typeLabels[issue.type]} · {issue.rule} · {issue.file}:{issue.line}</small></div><span>{issue.effortMinutes} мин</span></article>)}{hiddenCount > 0 && <button className="sonar-expand" onClick={() => setShowAll((value) => !value)} aria-expanded={showAll}>{showAll ? "Свернуть" : `Развернуть ещё ${hiddenCount}`}</button>}</> : <div className="sonar-clean"><CheckIcon size={24} /><strong>Проблем качества не найдено</strong></div>}</div>
    </>}
    <div className="sonar-note">Sonar Lite не является SonarQube и не заменяет полноценный анализ SonarSource.</div>
  </section>;
}
