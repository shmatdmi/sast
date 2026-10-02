import { getDb } from "../../db";
import { scanFindings, scanRuns } from "../../db/schema";
import type { ScanResult } from "./sast-engine";

export async function saveScanResult(projectName: string, release: string, result: ScanResult) {
  return getDb().transaction(async (tx) => {
    const [scan] = await tx.insert(scanRuns).values({
      projectName,
      release,
      status: "completed",
      language: result.language,
      scannedLines: result.scannedLines,
      durationMs: result.durationMs,
      filesScanned: result.filesScanned ?? 1,
      summary: result.summary,
    }).returning({ id: scanRuns.id, createdAt: scanRuns.createdAt });
    if (result.findings.length) {
      await tx.insert(scanFindings).values(result.findings.map((finding) => ({
        scanRunId: scan.id,
        findingId: finding.id,
        ruleId: finding.ruleId,
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
        cwe: finding.cwe,
        owasp: finding.owasp,
        confidence: finding.confidence,
        line: finding.line,
        column: finding.column,
        snippet: finding.snippet,
        recommendation: finding.recommendation,
        references: finding.references,
        category: finding.category,
        context: finding.context ?? null,
        filename: finding.filename ?? null,
      })));
    }
    return scan;
  });
}
