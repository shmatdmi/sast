"use client";
import { useState } from "react";
import { AlertIcon, CheckIcon, CodeIcon, ScanIcon } from "./icons";
import { scanCodeQuality, type SonarResult, type SonarSource } from "../lib/sonar-lite";

const typeLabels = { bug: "Ошибка", vulnerability: "Уязвимость", code_smell: "Code smell" };
const severityLabels = { blocker: "Blocker", critical: "Critical", major: "Major", minor: "Minor" };
export default function SonarLite({ sources }: { sources: SonarSource[] }) {
  const [result, setResult] = useState<SonarResult | null>(null); const hasCode = sources.some((source) => source.code.trim());
  const analyze = () => { if (!hasCode) return; setResult(scanCodeQuality(sources)); };
  return <section className="sonar-panel" id="sonar"><div className="panel-header"><div><span className="panel-dot sonar-dot" /><div><h2>Sonar Lite</h2><p>Упрощённый локальный анализ качества кода</p></div></div><button className="sonar-run" onClick={analyze} disabled={!hasCode}><ScanIcon size={16} />Проверить качество</button></div>
    {!result ? <div className="sonar-empty"><CodeIcon size={30} /><h3>{hasCode ? "Код готов к проверке" : "Сначала добавьте исходный код"}</h3><p>Сканер рассчитает метрики, технический долг и Quality Gate без отправки кода на сервер.</p></div> : <>
      <div className="sonar-summary"><article className={`quality-gate ${result.gate}`}><span>{result.gate === "passed" ? <CheckIcon size={22} /> : <AlertIcon size={22} />}</span><div><small>QUALITY GATE</small><strong>{result.gate === "passed" ? "Пройден" : "Не пройден"}</strong></div></article><article><small>Рейтинг</small><strong className={`rating rating-${result.rating.toLowerCase()}`}>{result.rating}</strong></article><article><small>Ошибки</small><strong>{result.counts.bug}</strong></article><article><small>Уязвимости</small><strong>{result.counts.vulnerability}</strong></article><article><small>Code smells</small><strong>{result.counts.code_smell}</strong></article></div>
      <div className="sonar-metrics"><span><small>Строк кода</small><strong>{result.metrics.codeLines}</strong></span><span><small>Сложность</small><strong>{result.metrics.complexity}</strong></span><span><small>Дублирование</small><strong>{result.metrics.duplicationPercent}%</strong></span><span><small>Технический долг</small><strong>{result.metrics.debtMinutes} мин</strong></span><span><small>Файлов</small><strong>{result.metrics.files}</strong></span></div>
      <div className="sonar-issues">{result.issues.length ? result.issues.map((issue) => <article key={issue.id}><span className={`sonar-severity ${issue.severity}`}>{severityLabels[issue.severity]}</span><div><strong>{issue.message}</strong><small>{typeLabels[issue.type]} · {issue.rule} · {issue.file}:{issue.line}</small></div><span>{issue.effortMinutes} мин</span></article>) : <div className="sonar-clean"><CheckIcon size={24} /><strong>Проблем качества не найдено</strong></div>}</div>
    </>}
    <div className="sonar-note">Sonar Lite не является SonarQube и не заменяет полноценный анализ SonarSource.</div>
  </section>;
}
