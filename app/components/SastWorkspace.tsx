"use client";

import { useCallback, useMemo, useRef, useState } from "react";
import {
  AlertIcon, CheckIcon, ChevronIcon, CloseIcon, CodeIcon, CopyIcon,
  DownloadIcon, FileIcon, LockIcon, ScanIcon, ShieldIcon, UploadIcon,
} from "./icons";
import { languageLabels, ruleCount, scanCode, scanFiles, type Finding, type ScanResult, type Severity } from "../lib/sast-engine";
import {
  acceptedSourceExtensions, extractZip, isSupportedSourceFile, MAX_ARCHIVE_BYTES, MAX_SOURCE_FILE_BYTES, type SourceFile,
} from "../lib/archive";

const demoCode = `const express = require('express');
const { exec } = require('child_process');
const app = express();

const API_KEY = "sk_live_51N8exampleSecretKey";

app.get('/users', async (req, res) => {
  const query = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
  const users = await db.query(query);
  res.json(users);
});

app.get('/diagnostics', (req, res) => {
  exec(\`ping -c 1 \${req.query.host}\`, (error, stdout) => {
    res.send(stdout);
  });
});

app.post('/preview', (req, res) => {
  document.getElementById('preview').innerHTML = req.body.content;
});`;

const severities: Array<Severity | "all"> = ["all", "critical", "high", "medium", "low"];
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

  const analyze = () => {
    if (!(archiveFiles.length ? archiveFiles.some((file) => file.code.trim()) : code.trim())) { setNotice("Добавьте исходный код или загрузите файл, чтобы начать анализ."); return; }
    setNotice(""); setScanning(true);
    window.setTimeout(() => {
      const next = archiveFiles.length ? scanFiles(archiveFiles) : scanCode(code, filename || "code.txt", language);
      setResult(next); setExpanded(new Set(next.findings.slice(0, 2).map((finding) => finding.id)));
      setFilter("all"); setScanning(false);
      window.setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 50);
    }, 560);
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
    const report = { tool: "CodeSentry Local SAST", version: "1.0.0", scannedAt: new Date().toISOString(), file: filename || "code.txt", ...result };
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
          version: "2.0.0",
          informationUri: "https://github.com/shmatdmi/sast",
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
          <a className="active" href="#overview"><ScanIcon size={17} /><span>Обзор</span></a>
          <a href="#scanner"><CodeIcon size={17} /><span>Сканер</span></a>
          <a href="#findings"><AlertIcon size={17} /><span>Находки</span>{result && <b>{result.summary.total}</b>}</a>
          <a href="#how"><FileIcon size={17} /><span>Справка</span></a>
        </nav>
        <div className="sidebar-status"><span className="status-dot" /><div><strong>Движок активен</strong><small>Локальный режим</small></div></div>
        <div className="sidebar-version">v1.0.0</div>
      </aside>
      <div className="app-main">
        <header className="topbar">
          <div className="breadcrumbs"><span>CodeSentry</span><i>/</i><strong>Security overview</strong></div>
          <div className="topbar-actions"><span className="privacy-badge"><LockIcon size={14} />Код не загружается в облако</span><a className="how-link" href="#how">Документация</a></div>
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
          <label>Язык анализа<select value={language} disabled={archiveFiles.length > 0} onChange={(event) => setLanguage(event.target.value)}>{Object.entries(languageLabels).filter(([key]) => key !== "unknown" && key !== "multiple").map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
          <button className="demo-button" onClick={loadDemo}><CodeIcon size={16} />Загрузить пример</button>
          <button className="scan-button" onClick={analyze} disabled={scanning}>{scanning ? <><span className="spinner" />Анализируем…</> : <><ScanIcon size={18} />Запустить проверку</>}</button>
        </div>
          </section>

      {result && <section className="results" id="findings" ref={resultsRef} aria-live="polite">
        <div className="results-heading"><div><span className="panel-dot warning" /><div><h2>Результат анализа</h2><p>{filename || "code.txt"} · {result.filesScanned ? `${result.filesScanned} файлов · ` : ""}{languageLabels[result.language]} · {result.scannedLines} строк</p></div></div><div><button className="export-button" onClick={exportSarif}><DownloadIcon size={16} />SARIF</button><button className="export-button" onClick={exportReport}><DownloadIcon size={16} />JSON</button></div></div>
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
          <footer><p>CodeSentry Local SAST</p><span>Система работает штатно</span><span className="footer-status"><i />LOCAL</span></footer>
        </div>
      </div>
    </main>
  );
}
