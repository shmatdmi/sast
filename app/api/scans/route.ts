import { getDb } from "../../../db";
import { scanRuns } from "../../../db/schema";
import { desc, eq, ilike, or } from "drizzle-orm";
import { scanFindings } from "../../../db/schema";

type ScanPayload = { projectName?: unknown; release?: unknown; language?: unknown; scannedLines?: unknown; durationMs?: unknown; filesScanned?: unknown; summary?: unknown; findings?: unknown };
const summaryFields = ["total", "critical", "high", "medium", "low", "info", "score"] as const;
const isCount = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const RELEASE_PATTERN = /^[A-Za-z]{2,4}-(?:[1-9][0-9]{0,3})$/;

function parsePayload(value: unknown) {
  if (!value || typeof value !== "object") return null;
  const payload = value as ScanPayload;
  if (typeof payload.projectName !== "string" || !payload.projectName.trim() || payload.projectName.length > 512
    || typeof payload.release !== "string" || !RELEASE_PATTERN.test(payload.release)
    || typeof payload.language !== "string" || payload.language.length > 64
    || !isCount(payload.scannedLines) || !isCount(payload.durationMs)
    || (payload.filesScanned !== undefined && !isCount(payload.filesScanned))
    || !payload.summary || typeof payload.summary !== "object"
    || !Array.isArray(payload.findings) || payload.findings.length > 10_000) return null;
  const summary = payload.summary as Record<string, unknown>;
  if (!summaryFields.every((field) => isCount(summary[field])) || (summary.score as number) > 100) return null;
  const validSummary = summary as Record<(typeof summaryFields)[number], number>;
  return {
    projectName: payload.projectName.trim(), release: payload.release, findings: payload.findings,
    summary: { language: payload.language, scannedLines: payload.scannedLines, durationMs: payload.durationMs,
      filesScanned: payload.filesScanned ?? 1, total: validSummary.total, critical: validSummary.critical,
      high: validSummary.high, medium: validSummary.medium, low: validSummary.low, info: validSummary.info, score: validSummary.score },
  };
}

export async function POST(request: Request) {
  try {
    if (Number(request.headers.get("content-length") ?? 0) > 5_242_880)
      return Response.json({ error: "Payload is too large" }, { status: 413 });
    const payload = parsePayload(await request.json());
    if (!payload) return Response.json({ error: "Invalid scan payload" }, { status: 400 });
    const scan = await getDb().transaction(async (tx) => {
      const [created] = await tx.insert(scanRuns).values({
        projectName: payload.projectName, release: payload.release, status: "completed",
        language: payload.summary.language, scannedLines: payload.summary.scannedLines,
        durationMs: payload.summary.durationMs, filesScanned: payload.summary.filesScanned,
        summary: { total: payload.summary.total, critical: payload.summary.critical, high: payload.summary.high,
          medium: payload.summary.medium, low: payload.summary.low, info: payload.summary.info, score: payload.summary.score },
      }).returning({ id: scanRuns.id, createdAt: scanRuns.createdAt });
      if (payload.findings.length) await tx.insert(scanFindings).values(payload.findings.map((item) => {
        const finding = item as Record<string, unknown>;
        return {
          scanRunId: created.id, findingId: String(finding.id ?? ""), ruleId: String(finding.ruleId ?? ""),
          title: String(finding.title ?? ""), description: String(finding.description ?? ""), severity: String(finding.severity ?? ""),
          cwe: String(finding.cwe ?? ""), owasp: String(finding.owasp ?? ""), confidence: String(finding.confidence ?? ""),
          line: Number(finding.line) || 1, column: Number(finding.column) || 1, snippet: String(finding.snippet ?? ""),
          recommendation: String(finding.recommendation ?? ""), references: Array.isArray(finding.references) ? finding.references.map(String) : [],
          category: String(finding.category ?? ""), context: typeof finding.context === "string" ? finding.context : null,
          filename: typeof finding.filename === "string" ? finding.filename : null,
        };
      }));
      return created;
    });
    return Response.json(scan, { status: 201 });
  } catch (error) {
    if (error instanceof SyntaxError) return Response.json({ error: "Invalid JSON" }, { status: 400 });
    console.error("Failed to save scan", error);
    return Response.json({ error: "Failed to save scan" }, { status: 500 });
  }
}

export async function GET(request: Request) {
  const url = new URL(request.url);
  const query = url.searchParams.get("q")?.trim().slice(0, 100) ?? "";
  const id = url.searchParams.get("id");
  const db = getDb();
  if (id) {
    const [scan] = await db.select().from(scanRuns).where(eq(scanRuns.id, id)).limit(1);
    if (!scan) return Response.json({ error: "Scan not found" }, { status: 404 });
    const storedFindings = await db.select().from(scanFindings).where(eq(scanFindings.scanRunId, id));
    return Response.json({ ...scan, findings: storedFindings.map((finding) => ({
      id: finding.findingId, ruleId: finding.ruleId, title: finding.title, description: finding.description,
      severity: finding.severity, cwe: finding.cwe, owasp: finding.owasp, confidence: finding.confidence,
      line: finding.line, column: finding.column, snippet: finding.snippet, recommendation: finding.recommendation,
      references: finding.references, category: finding.category, context: finding.context, filename: finding.filename,
    })) });
  }
  const where = query ? or(ilike(scanRuns.release, `%${query}%`), ilike(scanRuns.projectName, `%${query}%`)) : undefined;
  const scans = await db.select().from(scanRuns).where(where).orderBy(desc(scanRuns.createdAt)).limit(50);
  return Response.json(scans);
}
