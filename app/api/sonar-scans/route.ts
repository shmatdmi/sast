import { getDb } from "../../../db";
import { sonarScanIssues, sonarScanRuns } from "../../../db/schema";
import { requireApiUser } from "../../lib/auth";

const RELEASE_PATTERN = /^[A-Za-z]{2,4}-(?:[1-9][0-9]{0,3})$/;
const countFields = ["files", "lines", "codeLines", "commentLines", "complexity", "duplicatedLines", "debtMinutes"] as const;
const issueTypes = new Set(["bug", "vulnerability", "code_smell"]);
const severities = new Set(["blocker", "critical", "major", "minor"]);
const isCount = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

type Payload = { projectName?: unknown; release?: unknown; result?: unknown };

function parsePayload(value: unknown) {
  if (!value || typeof value !== "object") return null;
  const payload = value as Payload;
  if (typeof payload.projectName !== "string" || !payload.projectName.trim() || payload.projectName.length > 512
    || typeof payload.release !== "string" || !RELEASE_PATTERN.test(payload.release)
    || !payload.result || typeof payload.result !== "object") return null;
  const result = payload.result as Record<string, unknown>;
  const metrics = result.metrics as Record<string, unknown> | undefined;
  const counts = result.counts as Record<string, unknown> | undefined;
  const issues = result.issues;
  if ((result.gate !== "passed" && result.gate !== "failed")
    || !["A", "B", "C", "D", "E"].includes(String(result.rating))
    || !metrics || !countFields.every((field) => isCount(metrics[field]))
    || typeof metrics.duplicationPercent !== "number" || !Number.isFinite(metrics.duplicationPercent) || metrics.duplicationPercent < 0
    || !counts || !["bug", "vulnerability", "code_smell"].every((field) => isCount(counts[field]))
    || !Array.isArray(issues) || issues.length > 10_000) return null;
  for (const item of issues) {
    if (!item || typeof item !== "object") return null;
    const issue = item as Record<string, unknown>;
    if (typeof issue.id !== "string" || typeof issue.file !== "string" || typeof issue.message !== "string" || typeof issue.rule !== "string"
      || !issueTypes.has(String(issue.type)) || !severities.has(String(issue.severity)) || !isCount(issue.line) || !isCount(issue.effortMinutes)) return null;
  }
  return { projectName: payload.projectName.trim(), release: payload.release, gate: result.gate, rating: String(result.rating), metrics, counts, issues };
}

export async function POST(request: Request) {
  const auth = await requireApiUser(request);
  if ("response" in auth) return auth.response;
  try {
    if (Number(request.headers.get("content-length") ?? 0) > 5_242_880) return Response.json({ error: "Payload is too large" }, { status: 413 });
    const payload = parsePayload(await request.json());
    if (!payload) return Response.json({ error: "Invalid Sonar scan payload" }, { status: 400 });
    const created = await getDb().transaction(async (tx) => {
      const [run] = await tx.insert(sonarScanRuns).values({
        projectName: payload.projectName, release: payload.release, gate: payload.gate, rating: payload.rating,
        metrics: payload.metrics as never, counts: payload.counts as never,
      }).returning({ id: sonarScanRuns.id, createdAt: sonarScanRuns.createdAt });
      if (payload.issues.length) await tx.insert(sonarScanIssues).values(payload.issues.map((value) => {
        const issue = value as Record<string, unknown>;
        return { sonarScanRunId: run.id, issueId: String(issue.id), type: String(issue.type), severity: String(issue.severity),
          filename: String(issue.file), line: Number(issue.line), message: String(issue.message), rule: String(issue.rule), effortMinutes: Number(issue.effortMinutes) };
      }));
      return run;
    });
    return Response.json(created, { status: 201 });
  } catch (error) {
    if (error instanceof SyntaxError) return Response.json({ error: "Invalid JSON" }, { status: 400 });
    console.error("Failed to save Sonar scan", error);
    return Response.json({ error: "Failed to save Sonar scan" }, { status: 500 });
  }
}
