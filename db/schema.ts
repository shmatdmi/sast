import { index, integer, jsonb, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";

export type StoredScanSummary = { total: number; critical: number; high: number; medium: number; low: number; info: number; score: number };

export const scanRuns = pgTable("scan_runs", {
  id: uuid("id").defaultRandom().primaryKey(),
  projectName: text("project_name").notNull(),
  status: text("status").notNull().default("completed"),
  language: text("language").notNull(),
  scannedLines: integer("scanned_lines").notNull(),
  durationMs: integer("duration_ms").notNull(),
  filesScanned: integer("files_scanned").notNull().default(1),
  summary: jsonb("summary").$type<StoredScanSummary>().notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [index("scan_runs_created_at_idx").on(table.createdAt)]);

export const scanFindings = pgTable("scan_findings", {
  id: uuid("id").defaultRandom().primaryKey(),
  scanRunId: uuid("scan_run_id").notNull().references(() => scanRuns.id, { onDelete: "cascade" }),
  findingId: text("finding_id").notNull(), ruleId: text("rule_id").notNull(),
  title: text("title").notNull(), description: text("description").notNull(),
  severity: text("severity").notNull(), cwe: text("cwe").notNull(), owasp: text("owasp").notNull(),
  confidence: text("confidence").notNull(), line: integer("line").notNull(), column: integer("column").notNull(),
  snippet: text("snippet").notNull(), recommendation: text("recommendation").notNull(),
  references: jsonb("references").$type<string[]>().notNull().default([]),
  category: text("category").notNull(), context: text("context"), filename: text("filename"),
}, (table) => [
  index("scan_findings_scan_run_id_idx").on(table.scanRunId),
  index("scan_findings_severity_idx").on(table.severity),
  index("scan_findings_rule_id_idx").on(table.ruleId),
]);
