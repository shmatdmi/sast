import { index, integer, jsonb, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";

import { boolean } from "drizzle-orm/pg-core";

export const users = pgTable("users", {
  id: uuid("id").defaultRandom().primaryKey(),
  username: text("username").notNull().unique(),
  displayName: text("display_name").notNull(),
  passwordHash: text("password_hash").notNull(),
  role: text("role").notNull().default("user"),
  isActive: boolean("is_active").notNull().default(true),
  mustChangePassword: boolean("must_change_password").notNull().default(false),
  lastLoginAt: timestamp("last_login_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [index("users_username_idx").on(table.username)]);

export const userSessions = pgTable("user_sessions", {
  id: uuid("id").defaultRandom().primaryKey(),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  tokenHash: text("token_hash").notNull().unique(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [index("user_sessions_user_id_idx").on(table.userId), index("user_sessions_expires_at_idx").on(table.expiresAt)]);

export const userAuditLog = pgTable("user_audit_log", {
  id: uuid("id").defaultRandom().primaryKey(),
  actorUserId: uuid("actor_user_id").references(() => users.id, { onDelete: "set null" }),
  targetUserId: uuid("target_user_id").references(() => users.id, { onDelete: "set null" }),
  action: text("action").notNull(),
  details: jsonb("details").$type<Record<string, string | boolean>>().notNull().default({}),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [index("user_audit_log_created_at_idx").on(table.createdAt)]);

export type StoredScanSummary = { total: number; critical: number; high: number; medium: number; low: number; info: number; score: number };

export const scanRuns = pgTable("scan_runs", {
  id: uuid("id").defaultRandom().primaryKey(),
  projectName: text("project_name").notNull(),
  release: text("release").notNull(),
  status: text("status").notNull().default("completed"),
  language: text("language").notNull(),
  scannedLines: integer("scanned_lines").notNull(),
  durationMs: integer("duration_ms").notNull(),
  filesScanned: integer("files_scanned").notNull().default(1),
  summary: jsonb("summary").$type<StoredScanSummary>().notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("scan_runs_created_at_idx").on(table.createdAt),
  index("scan_runs_release_idx").on(table.release),
]);

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

export type StoredSonarMetrics = {
  files: number; lines: number; codeLines: number; commentLines: number; complexity: number;
  duplicatedLines: number; duplicationPercent: number; debtMinutes: number;
};
export type StoredSonarCounts = { bug: number; vulnerability: number; code_smell: number };

export const sonarScanRuns = pgTable("sonar_scan_runs", {
  id: uuid("id").defaultRandom().primaryKey(),
  projectName: text("project_name").notNull(),
  release: text("release").notNull(),
  status: text("status").notNull().default("completed"),
  gate: text("gate").notNull(),
  rating: text("rating").notNull(),
  metrics: jsonb("metrics").$type<StoredSonarMetrics>().notNull(),
  counts: jsonb("counts").$type<StoredSonarCounts>().notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("sonar_scan_runs_created_at_idx").on(table.createdAt),
  index("sonar_scan_runs_release_idx").on(table.release),
]);

export const sonarScanIssues = pgTable("sonar_scan_issues", {
  id: uuid("id").defaultRandom().primaryKey(),
  sonarScanRunId: uuid("sonar_scan_run_id").notNull().references(() => sonarScanRuns.id, { onDelete: "cascade" }),
  issueId: text("issue_id").notNull(),
  type: text("type").notNull(),
  severity: text("severity").notNull(),
  filename: text("filename").notNull(),
  line: integer("line").notNull(),
  message: text("message").notNull(),
  rule: text("rule").notNull(),
  effortMinutes: integer("effort_minutes").notNull(),
}, (table) => [
  index("sonar_scan_issues_run_id_idx").on(table.sonarScanRunId),
  index("sonar_scan_issues_severity_idx").on(table.severity),
  index("sonar_scan_issues_rule_idx").on(table.rule),
]);
