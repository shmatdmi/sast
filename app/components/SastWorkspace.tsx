"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertIcon, CheckIcon, ChevronIcon, CloseIcon, CodeIcon, CopyIcon,
  DownloadIcon, FileIcon, LockIcon, ScanIcon, ShieldIcon, UploadIcon,
} from "./icons";
import { languageLabels, ruleCount, scanCode, scanFiles, type Finding, type ScanResult, type Severity } from "../lib/sast-engine";
import { demoCode } from "../lib/demo-code";
import { appVersion } from "../lib/version";
import {
  acceptedSourceExtensions, extractZip, isSupportedSourceFile, MAX_ARCHIVE_BYTES, MAX_SOURCE_FILE_BYTES, type SourceFile,
} from "../lib/archive";

const severities: Array<Severity | "all"> = ["all", "critical", "high", "medium", "low"];
const RELEASE_PATTERN = /^[A-Za-z]{2,4}-(?:[1-9][0-9]{0,3})$/;
type HistoricalScan = {
  id: string; projectName: string; release: string; language: string; scannedLines: number;
  durationMs: number; filesScanned: number; summary: ScanResult["summary"]; createdAt: string;
};
const severityLabels: Record<Severity | "all", string> = {
  all: "Все", critical: "Критические", high: "Высокие", medium: "Средние", low: "Низкие", info: "Инфо",
};

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} Б`;
  return `${(bytes / 1024).toFixed(bytes > 10240 ? 0 : 1)} КБ`;
}

function ScoreRing({ score }: { score: number }) {
  const color = score >= 85 ? "#15936c" : score >= 60 ? "#dd8a24" : "#e24d4d";
  return (
    <div className="score-ring" style={{ "--score": score, "--score-color": color } as React.CSSProperties}>
      <div><strong>{score}</strong><span>/ 100</span></div>
    </div>
  );
}

function FindingCard({ finding, expanded, onToggle }: { finding: Finding; expanded: boolean; onToggle: () => void }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    await navigator.clipboard.writeText(finding.snippet);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  };
  return (
    <article className={`finding-card finding-${finding.severity}`}>
      <button className="finding-summary" onClick={onToggle} aria-expanded={expanded}>
        <span className="severity-marker"><AlertIcon size={16} /></span>
        <span className="finding-main">
          <span className="finding-title-row">
            <strong>{finding.title}</strong>
            <span className={`severity-pill ${finding.severity}`}>{severityLabels[finding.severity]}</span>
          </span>
          <span className="finding-meta">
            <code>{finding.ruleId}</code>{finding.filename && <span className="finding-file">{finding.filename}</span>}<span>{finding.cwe}</span><span>{finding.category}</span><span>строка {finding.line}</span><span>уверенность: {finding.confidence === "high" ? "высокая" : "средняя"}</span>
          </span>
        </span>
        <ChevronIcon className={expanded ? "chevron expanded" : "chevron"} size={18} />
      </button>
      {expanded && (
        <div className="finding-details">
          <p>{finding.description}</p>
          <div className="code-snippet"><span>{finding.line}</span><code>{finding.snippet}</code><button onClick={copy} aria-label="Копировать фрагмент"><CopyIcon size={15} />{copied ? "Скопировано" : "Копировать"}</button></div>
          <div className="recommendation"><CheckIcon size={17} /><div><strong>Как исправить</strong><p>{finding.recommendation}</p></div></div>
          <a href={finding.references[0]} target="_blank" rel="noreferrer">Открыть описание {finding.cwe} ↗</a>
        </div>
      )}
    </article>
  );
}

export default function SastWorkspace() {
  const inputRef = useRef<HTMLInputElement>(null);
  const resultsRef = useRef<HTMLDivElement>(null);
  const [code, setCode] = useState("");
  const [filename, setFilename] = useState("");
  const [fileSize, setFileSize] = useState(0);
  const [language, setLanguage] = useState("auto");
  const [dragging, setDragging] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [filter, setFilter] = useState<Severity | "all">("all");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [notice, setNotice] = useState("");
  const [archiveFiles, setArchiveFiles] = useState<SourceFile[]>([]);
  const [archiveSkipped, setArchiveSkipped] = useState(0);
  const [activeSection, setActiveSection] = useState("overview");
  const [release, setRelease] = useState("");
  const [historyQuery, setHistoryQuery] = useState("");
  const [history, setHistory] = useState<HistoricalScan[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  const navigateToSection = useCallback((section: string) => (event: React.MouseEvent<HTMLAnchorElement>) => {
    event.preventDefault();
    const target = document.getElementById(section);

    if (!target && section === "findings") {
      setNotice("Чтобы открыть находки, сначала загрузите код и запустите проверку.");
      setActiveSection("scanner");
      window.history.pushState(null, "", "#scanner");
      document.getElementById("scanner")?.scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }

    if (!target) return;
    setActiveSection(section);
    window.history.pushState(null, "", `#${section}`);
    target.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  useEffect(() => {
    const sections = ["overview", "history", "scanner", "findings", "how"]
      .map((id) => document.getElementById(id))
      .filter((section): section is HTMLElement => Boolean(section));
    const observer = new IntersectionObserver((entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((left, right) => right.intersectionRatio - left.intersectionRatio)[0];
      if (visible?.target.id) setActiveSection(visible.target.id);
    }, { rootMargin: "-20% 0px -55%", threshold: [0, 0.15, 0.5] });
    sections.forEach((section) => observer.observe(section));
    return () => observer.disconnect();
  }, [result]);

  const loadFile = useCallback(async (file: File) => {
    const isZip = file.name.toLowerCase().endsWith(".zip");
    if (!isZip && !isSupportedSourceFile(file.name)) {
      setNotice("Этот формат пока не поддерживается. Выберите файл с исходным кодом.");
      return;
    }
    if ((!isZip && file.size > MAX_SOURCE_FILE_BYTES) || (isZip && file.size > MAX_ARCHIVE_BYTES)) {
      setNotice(isZip ? "ZIP-архив больше 10 МБ." : "Файл больше 1 МБ. Для быстрого локального анализа выберите файл меньшего размера.");
      return;
    }
    try {
      if (isZip) {
        const extracted = extractZip(new Uint8Array(await file.arrayBuffer()));
        setArchiveFiles(extracted.files); setArchiveSkipped(extracted.skippedFiles);
        setCode(extracted.files[0].code); setLanguage("auto");
      } else {
        setArchiveFiles([]); setArchiveSkipped(0); setCode(await file.text());
      }
      setFilename(file.name); setFileSize(file.size); setResult(null); setNotice("");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Не удалось прочитать файл. Попробуйте выбрать его ещё раз.");
    }
  }, []);

  const analyze = async () => {
    if (!(archiveFiles.length ? archiveFiles.some((file) => file.code.trim()) : code.trim())) { setNotice("Добавьте исходный код или загрузите файл, чтобы начать анализ."); return; }
    if (!RELEASE_PATTERN.test(release)) { setNotice("Укажите релиз: 2–4 английские буквы, дефис и число от 1 до 9999. Например: test-456."); return; }
    setNotice(""); setScanning(true);
    await new Promise((resolve) => window.setTimeout(resolve, 560));
    const next = archiveFiles.length ? scanFiles(archiveFiles) : scanCode(code, filename || "code.txt", language);
    setResult(next); setExpanded(new Set(next.findings.slice(0, 2).map((finding) => finding.id)));
    setFilter("all");
    try {
      const response = await fetch("/api/scans", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          projectName: filename || "code.txt", release, language: next.language,
          scannedLines: next.scannedLines, durationMs: next.durationMs,
          filesScanned: next.filesScanned, summary: next.summary, findings: next.findings,
        }),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
    } catch (error) {
      console.error("Failed to save scan", error);
      setNotice("\u0410\u043d\u0430\u043b\u0438\u0437 \u0437\u0430\u0432\u0435\u0440\u0448\u0451\u043d, \u043d\u043e \u0441\u043e\u0445\u0440\u0430\u043d\u0438\u0442\u044c \u0435\u0433\u043e \u0432 \u0438\u0441\u0442\u043e\u0440\u0438\u0438 \u043d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c. \u041f\u0440\u043e\u0432\u0435\u0440\u044c\u0442\u0435 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0435\u043d\u0438\u0435 \u043a \u0431\u0430\u0437\u0435 \u0434\u0430\u043d\u043d\u044b\u0445.");
    } finally {
      setScanning(false);
      window.setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 50);
    }
  };

  const searchHistory = async () => {
    setHistoryLoading(true); setNotice("");
    try {
      const response = await fetch(`/api/scans?q=${encodeURIComponent(historyQuery.trim())}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      setHistory(await response.json() as HistoricalScan[]);
    } catch (error) {
      console.error("Failed to load scan history", error);
      setNotice("Не удалось загрузить историю сканирований.");
    } finally { setHistoryLoading(false); }
  };

  const openHistoricalScan = async (id: string) => {
    setHistoryLoading(true); setNotice("");
    try {
      const response = await fetch(`/api/scans?id=${encodeURIComponent(id)}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const stored = await response.json() as HistoricalScan & { findings: Finding[] };
      setFilename(stored.projectName); setRelease(stored.release);
      setResult({ language: stored.language, scannedLines: stored.scannedLines, durationMs: stored.durationMs,
        filesScanned: stored.filesScanned, summary: stored.summary, findings: stored.findings });
      setFilter("all"); setExpanded(new Set());
      window.setTimeout(() => document.getElementById("findings")?.scrollIntoView({ behavior: "smooth" }), 50);
    } catch (error) {
      console.error("Failed to load historical scan", error);
      setNotice("Не удалось открыть результат сканирования.");
    } finally { setHistoryLoading(false); }
  };

  const clear = () => {
    setCode(""); setFilename(""); setFileSize(0); setResult(null); setNotice(""); setArchiveFiles([]); setArchiveSkipped(0);
    if (inputRef.current) inputRef.current.value = "";
  };

  const loadDemo = () => {
    setCode(demoCode); setFilename("vulnerable-api.js"); setFileSize(new Blob([demoCode]).size);
    setLanguage("auto"); setResult(null); setNotice(""); setArchiveFiles([]); setArchiveSkipped(0);
  };

  const exportReport = () => {
    if (!result) return;
    const report = { tool: "CodeSentry Local SAST", version: appVersion, release, scannedAt: new Date().toISOString(), file: filename || "code.txt", ...result };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `${(filename || "scan").replace(/\.[^.]+$/, "")}-sast-report.json`;
    link.click(); URL.revokeObjectURL(link.href);
  };

  const exportSarif = () => {
    if (!result) return;
    const uniqueRules = [...new Map(result.findings.map((finding) => [finding.ruleId, finding])).values()];
    const report = {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [{
        tool: { driver: {
          name: "CodeSentry Local SAST",
          version: appVersion,
          informationUri: "https://github.com/shmatdmi/sast",
          properties: { release },
          rules: uniqueRules.map((finding) => ({
            id: finding.ruleId,
            name: finding.title,
            shortDescription: { text: finding.title },
            fullDescription: { text: finding.description },
            helpUri: finding.references[0],
            properties: { tags: [finding.cwe, finding.owasp, finding.category] },
          })),
        } },
        results: result.findings.map((finding) => ({
          ruleId: finding.ruleId,
          level: finding.severity === "critical" || finding.severity === "high" ? "error" : finding.severity === "medium" ? "warning" : "note",
          message: { text: finding.description + " " + finding.recommendation },
          locations: [{ physicalLocation: {
            artifactLocation: { uri: finding.filename || filename || "code.txt" },
            region: { startLine: finding.line, startColumn: finding.column, snippet: { text: finding.snippet } },
          } }],
          properties: { severity: finding.severity, confidence: finding.confidence, cwe: finding.cwe, category: finding.category },
        })),
      }],
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/sarif+json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `${(filename || "scan").replace(/\.[^.]+$/, "")}.sarif`;
    link.click(); URL.revokeObjectURL(link.href);
  };

  const filteredFindings = useMemo(() => {
    if (!result) return [];
    return filter === "all" ? result.findings : result.findings.filter((finding) => finding.severity === filter);
  }, [filter, result]);

  return (
    <main className="app-shell" id="top">
      <aside className="sidebar" aria-label="Основная навигация">
        <a className="brand" href="#top"><span className="brand-mark"><ShieldIcon size={20} /></span><span>CODE<strong>SENTRY</strong></span></a>
        <nav>
          <a className={activeSection === "overview" ? "active" : ""} href="#overview" onClick={navigateToSection("overview")}><ScanIcon size={17} /><span>Обзор</span></a>
          <a className={activeSection === "scanner" ? "active" : ""} href="#scanner" onClick={navigateToSection("scanner")}><CodeIcon size={17} /><span>Сканер</span></a>
          <a className={activeSection === "history" ? "active" : ""} href="#history" onClick={navigateToSection("history")}><FileIcon size={17} /><span>История</span></a>
          <a className={activeSection === "findings" ? "active" : ""} href="#findings" onClick={navigateToSection("findings")}><AlertIcon size={17} /><span>Находки</span>{result && <b>{result.summary.total}</b>}</a>
          <a className={activeSection === "how" ? "active" : ""} href="#how" onClick={navigateToSection("how")}><FileIcon size={17} /><span>Справка</span></a>
        </nav>
        <div className="sidebar-status"><span className="status-dot" /><div><strong>Движок активен</strong><small>Локальный режим</small></div></div>
        <div className="sidebar-version">v{appVersion}</div>
      </aside>
      <div className="app-main">
        <header className="topbar">
          <div className="breadcrumbs"><span>CodeSentry</span><i>/</i><strong>Security overview</strong></div>
          <div className="topbar-actions"><span className="privacy-badge"><LockIcon size={14} />Код не загружается в облако</span><a className="how-link" href="#how" onClick={navigateToSection("how")}>Документация</a></div>
        </header>
        <div className="dashboard-content">
          <section className="overview" id="overview">
            <div className="page-heading"><div><span className="eyebrow">SECURITY CONTROL CENTER</span><h1>Обзор безопасности</h1><p>Запустите локальный SAST-анализ и получите карту рисков исходного кода.</p></div><button className="primary-cta" onClick={() => document.getElementById("scanner")?.scrollIntoView({ behavior: "smooth" })}><ScanIcon size={17} />Новый анализ</button></div>
            <div className="overview-grid">
              <article className="stat-panel accent"><div className="panel-label"><span>Статус защиты</span><span className="live-badge">LIVE</span></div><strong>{result ? (result.summary.score >= 85 ? "Стабильно" : result.summary.score >= 60 ? "Внимание" : "Высокий риск") : "Готов к работе"}</strong><div className="spark-bars" aria-hidden="true">{[34,48,40,65,58,76,69,82,78,91,86,96].map((height, index) => <i key={index} style={{ height: `${height}%` }} />)}</div><small>Анализ выполняется полностью на устройстве</small></article>
              <article className="stat-panel"><div className="panel-label"><span>Правила</span><ShieldIcon size={15} /></div><strong>{ruleCount}</strong><div className="stat-delta positive">● актуальная база</div><small>CWE и OWASP-категории</small></article>
              <article className="stat-panel"><div className="panel-label"><span>Охват</span><CodeIcon size={15} /></div><strong>14</strong><div className="stat-delta">языков и форматов</div><small>Исходники и ZIP-проекты</small></article>
              <article className="stat-panel"><div className="panel-label"><span>Последний скан</span><FileIcon size={15} /></div><strong>{result ? `${result.durationMs} мс` : "—"}</strong><div className="stat-delta">{result ? `${result.scannedLines} строк` : "ожидает запуска"}</div><small>{result ? filename || "code.txt" : "Нет истории отправки данных"}</small></article>
            </div>
          </section>
          <section className="history-panel" id="history">
            <div className="panel-header"><div><span className="panel-dot" /><div><h2>История сканирований</h2><p>Поиск по релизу или имени проекта</p></div></div></div>
            <div className="history-search"><input value={historyQuery} onChange={(event) => setHistoryQuery(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void searchHistory(); }} placeholder="test-456 или project.zip" aria-label="Поиск в истории" /><button onClick={() => void searchHistory()} disabled={historyLoading}>{historyLoading ? "Ищем…" : "Найти"}</button></div>
            {history.length > 0 && <div className="history-list">{history.map((scan) => <button key={scan.id} onClick={() => void openHistoricalScan(scan.id)}><strong>{scan.release}</strong><span>{scan.projectName}</span><span>{scan.summary.total} находок · {new Date(scan.createdAt).toLocaleString("ru-RU")}</span></button>)}</div>}
          </section>
          <section className="workspace-shell" id="scanner" aria-label="Рабочая область анализатора">
            <div className="panel-header"><div><span className="panel-dot" /><div><h2>Новый анализ</h2><p>Источник и конфигурация сканирования</p></div></div><span className="panel-time">LOCAL / READY</span></div>
        <div className="input-grid">
          <div className={`drop-zone ${dragging ? "dragging" : ""} ${filename ? "has-file" : ""}`}
            onDragEnter={(event) => { event.preventDefault(); setDragging(true); }} onDragOver={(event) => event.preventDefault()}
            onDragLeave={(event) => { if (event.currentTarget === event.target) setDragging(false); }}
            onDrop={(event) => { event.preventDefault(); setDragging(false); const file = event.dataTransfer.files[0]; if (file) loadFile(file); }}>
            <input ref={inputRef} type="file" accept={[".zip", ...acceptedSourceExtensions.map((ext) => `.${ext}`)].join(",")} onChange={(event) => { const file = event.target.files?.[0]; if (file) void loadFile(file); }} />
            {filename ? <div className="selected-file"><span className="file-icon"><FileIcon size={26} /></span><div><strong>{filename}</strong><span>{archiveFiles.length ? `${archiveFiles.length} файлов с кодом${archiveSkipped ? ` · пропущено ${archiveSkipped}` : ""}` : `${formatBytes(fileSize)} · готов к анализу`}</span></div><button onClick={(event) => { event.stopPropagation(); clear(); }} aria-label="Удалить файл"><CloseIcon size={17} /></button></div>
              : <button className="drop-action" onClick={() => inputRef.current?.click()}><span className="upload-icon"><UploadIcon size={25} /></span><strong>Перетащите файл или ZIP сюда</strong><span>или <u>выберите на компьютере</u></span><small>исходный код до 1 МБ · ZIP-архив до 10 МБ<br />до 500 файлов, распаковка локально</small></button>}
          </div>
          <div className="code-panel">
            <div className="code-toolbar"><div><CodeIcon size={16} /><span>{archiveFiles.length ? `Предпросмотр: ${archiveFiles[0].name}` : filename || "Вставьте код вручную"}</span></div>{code && <button onClick={clear}>Очистить</button>}</div>
            <div className="editor-wrap"><div className="line-numbers" aria-hidden="true">{code.split("\n").map((_, index) => <span key={index}>{index + 1}</span>)}</div><textarea value={code} readOnly={archiveFiles.length > 0} onChange={(event) => { setCode(event.target.value); setArchiveFiles([]); setArchiveSkipped(0); setResult(null); if (!filename) setFilename("code.txt"); }} spellCheck={false} aria-label="Исходный код" placeholder={"// Вставьте код для проверки\n// или загрузите файл слева"} /></div>
          </div>
        </div>
        {notice && <div className="notice" role="alert"><AlertIcon size={17} />{notice}</div>}
        <div className="action-bar">
          <label>Релиз<input className="release-input" value={release} onChange={(event) => setRelease(event.target.value)} placeholder="test-456" required pattern="[A-Za-z]{2,4}-[1-9][0-9]{0,3}" aria-describedby="release-hint" /></label>
          <small id="release-hint" className="release-hint">2–4 буквы A–Z, дефис, число 1–9999</small>
          <label>Язык анализа<select value={language} disabled={archiveFiles.length > 0} onChange={(event) => setLanguage(event.target.value)}>{Object.entries(languageLabels).filter(([key]) => key !== "unknown" && key !== "multiple").map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
          <button className="demo-button" onClick={loadDemo}><CodeIcon size={16} />Загрузить пример</button>
          <button className="scan-button" onClick={analyze} disabled={scanning}>{scanning ? <><span className="spinner" />Анализируем…</> : <><ScanIcon size={18} />Запустить проверку</>}</button>
        </div>
          </section>

      {result && <section className="results" id="findings" ref={resultsRef} aria-live="polite">
        <div className="results-heading"><div><span className="panel-dot warning" /><div><h2>Результат анализа · {release}</h2><p>{filename || "code.txt"} · {result.filesScanned ? `${result.filesScanned} файлов · ` : ""}{languageLabels[result.language]} · {result.scannedLines} строк</p></div></div><div><button className="export-button" onClick={exportSarif}><DownloadIcon size={16} />SARIF</button><button className="export-button" onClick={exportReport}><DownloadIcon size={16} />JSON</button></div></div>
        <div className="summary-grid">
          <div className="score-card"><ScoreRing score={result.summary.score} /><div><span>Оценка безопасности</span><strong>{result.summary.score >= 85 ? "Хороший результат" : result.summary.score >= 60 ? "Требует внимания" : "Высокий риск"}</strong><p>На основе серьёзности и количества найденных проблем</p></div></div>
          <div className="severity-card critical"><span>Критические</span><strong>{result.summary.critical}</strong><small>Исправить немедленно</small></div>
          <div className="severity-card high"><span>Высокие</span><strong>{result.summary.high}</strong><small>Высокий приоритет</small></div>
          <div className="severity-card medium"><span>Средние</span><strong>{result.summary.medium}</strong><small>Запланировать исправление</small></div>
        </div>
        <div className="findings-panel">
          <div className="findings-toolbar"><div><h3>Найденные проблемы <span>{result.summary.total}</span></h3><p>Анализ завершён за {result.durationMs} мс</p></div><div className="filters" role="group" aria-label="Фильтр по серьёзности">{severities.map((severity) => {
            const count = severity === "all" ? result.summary.total : result.summary[severity];
            return <button key={severity} onClick={() => setFilter(severity)} className={filter === severity ? "active" : ""}>{severityLabels[severity]} <span>{count}</span></button>;
          })}</div></div>
          {filteredFindings.length ? <div className="finding-list">{filteredFindings.map((finding) => <FindingCard key={finding.id} finding={finding} expanded={expanded.has(finding.id)} onToggle={() => setExpanded((current) => { const next = new Set(current); if (next.has(finding.id)) next.delete(finding.id); else next.add(finding.id); return next; })} />)}</div>
            : <div className="empty-findings"><span><CheckIcon size={28} /></span><h3>Проблем этой категории нет</h3><p>Попробуйте выбрать другой фильтр.</p></div>}
        </div>
        <div className="disclaimer"><AlertIcon size={16} /><p><strong>Важно:</strong> автоматический SAST-анализ не заменяет ручной аудит безопасности. Проверяйте контекст находок и дополняйте анализ dependency scanning, DAST и code review.</p></div>
      </section>}

          <section className="how" id="how"><div className="section-kicker">РАБОЧИЙ ПРОЦЕСС</div><h2>От исходника до исправления</h2><div className="how-grid"><article><span>01</span><FileIcon size={22} /><h3>Добавьте источник</h3><p>Файл, ZIP-проект или фрагмент кода остаётся внутри браузера.</p></article><article><span>02</span><ScanIcon size={22} /><h3>Запустите движок</h3><p>Правила безопасной разработки проверят каждую строку локально.</p></article><article><span>03</span><ShieldIcon size={22} /><h3>Устраните риски</h3><p>Используйте CWE, точную строку и рекомендацию для каждой находки.</p></article></div></section>
          <footer><p>CodeSentry Local SAST · v{appVersion}</p><span>Система работает штатно</span><span className="footer-status"><i />LOCAL</span></footer>
        </div>
      </div>
    </main>
  );
}
