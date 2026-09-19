import { getDb } from "../../../db";
import { scanRuns } from "../../../db/schema";

type ScanPayload = { projectName?: unknown; language?: unknown; scannedLines?: unknown; durationMs?: unknown; filesScanned?: unknown; summary?: unknown };
const summaryFields = ["total", "critical", "high", "medium", "low", "info", "score"] as const;
const isCount = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

function parsePayload(value: unknown) {
  if (!value || typeof value !== "object") return null;
  const payload = value as ScanPayload;
  if (typeof payload.projectName !== "string" || !payload.projectName.trim() || payload.projectName.length > 512
    || typeof payload.language !== "string" || payload.language.length > 64
    || !isCount(payload.scannedLines) || !isCount(payload.durationMs)
    || (payload.filesScanned !== undefined && !isCount(payload.filesScanned))
    || !payload.summary || typeof payload.summary !== "object") return null;
  const summary = payload.summary as Record<string, unknown>;
  if (!summaryFields.every((field) => isCount(summary[field])) || (summary.score as number) > 100) return null;
  const validSummary = summary as Record<(typeof summaryFields)[number], number>;
  return {
    projectName: payload.projectName.trim(),
    summary: { language: payload.language, scannedLines: payload.scannedLines, durationMs: payload.durationMs,
      filesScanned: payload.filesScanned ?? 1, total: validSummary.total, critical: validSummary.critical,
      high: validSummary.high, medium: validSummary.medium, low: validSummary.low, info: validSummary.info, score: validSummary.score },
  };
}

export async function POST(request: Request) {
  try {
    if (Number(request.headers.get("content-length") ?? 0) > 16_384)
      return Response.json({ error: "Payload is too large" }, { status: 413 });
    const payload = parsePayload(await request.json());
    if (!payload) return Response.json({ error: "Invalid scan payload" }, { status: 400 });
    const [scan] = await getDb().insert(scanRuns).values({
      projectName: payload.projectName,
      status: "completed",
      language: payload.summary.language,
      scannedLines: payload.summary.scannedLines,
      durationMs: payload.summary.durationMs,
      filesScanned: payload.summary.filesScanned,
      summary: {
        total: payload.summary.total,
        critical: payload.summary.critical,
        high: payload.summary.high,
        medium: payload.summary.medium,
        low: payload.summary.low,
        info: payload.summary.info,
        score: payload.summary.score,
      },
    })
      .returning({ id: scanRuns.id, createdAt: scanRuns.createdAt });
    return Response.json(scan, { status: 201 });
  } catch (error) {
    if (error instanceof SyntaxError) return Response.json({ error: "Invalid JSON" }, { status: 400 });
    console.error("Failed to save scan", error);
    return Response.json({ error: "Failed to save scan" }, { status: 500 });
  }
}
