import { index, integer, jsonb, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";

import { boolean, check, foreignKey, pgSchema, primaryKey, unique } from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";

export const sastRulesSchema = pgSchema("sast_rules");

export type StoredRuleDefinition = {
  id: string;
  languages: string[];
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cwe: string;
  owasp: string;
  confidence: "high" | "medium";
  pattern: string;
  patternFlags: string;
  exclude: string | null;
  excludeFlags: string | null;
  scope: "line" | "file";
  category: string | null;
  recommendation: string;
  references: string[];
};

export const securityRules = sastRulesSchema.table("rules", {
  id: text("id").primaryKey(),
  title: text("title").notNull(),
  languages: jsonb("languages").$type<string[]>().notNull(),
  category: text("category"),
  cwe: text("cwe").notNull(),
  owasp: text("owasp").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  check("rules_languages_check", sql`jsonb_typeof(${table.languages}) = 'array' AND jsonb_array_length(${table.languages}) > 0`),
  index("rules_cwe_idx").on(table.cwe),
]);

export const securityRuleVersions = sastRulesSchema.table("rule_versions", {
  id: uuid("id").defaultRandom().primaryKey(),
  ruleId: text("rule_id").notNull().references(() => securityRules.id),
  contentHash: text("content_hash").notNull(),
  definition: jsonb("definition").$type<StoredRuleDefinition>().notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  unique("rule_versions_rule_hash_unique").on(table.ruleId, table.contentHash),
  unique("rule_versions_id_rule_unique").on(table.id, table.ruleId),
  check("rule_versions_hash_check", sql`${table.contentHash} ~ '^[0-9a-f]{64}$'`),
  check("rule_versions_definition_check", sql`jsonb_typeof(${table.definition}) = 'object' AND ${table.definition} ?& ARRAY['id', 'languages', 'title', 'description', 'severity', 'cwe', 'owasp', 'confidence', 'pattern', 'patternFlags', 'exclude', 'excludeFlags', 'scope', 'category', 'recommendation', 'references'] AND ${table.definition}->>'id' = ${table.ruleId} AND ${table.definition}->>'severity' IN ('critical', 'high', 'medium', 'low', 'info') AND ${table.definition}->>'confidence' IN ('high', 'medium') AND ${table.definition}->>'scope' IN ('line', 'file')`),
]);

export const securityRulesets = sastRulesSchema.table("rulesets", {
  id: uuid("id").defaultRandom().primaryKey(),
  name: text("name").notNull(),
  source: text("source").notNull().default("builtin"),
  contentHash: text("content_hash").notNull().unique(),
  ruleCount: integer("rule_count").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  check("rulesets_hash_check", sql`${table.contentHash} ~ '^[0-9a-f]{64}$'`),
  check("rulesets_count_check", sql`${table.ruleCount} > 0`),
]);

export const securityRulesetItems = sastRulesSchema.table("ruleset_items", {
  rulesetId: uuid("ruleset_id").notNull().references(() => securityRulesets.id),
  ruleId: text("rule_id").notNull(),
  ruleVersionId: uuid("rule_version_id").notNull(),
  position: integer("position").notNull(),
}, (table) => [
  primaryKey({ columns: [table.rulesetId, table.ruleId] }),
  unique("ruleset_items_position_unique").on(table.rulesetId, table.position),
  foreignKey({ columns: [table.ruleVersionId, table.ruleId], foreignColumns: [securityRuleVersions.id, securityRuleVersions.ruleId], name: "ruleset_items_rule_version_fk" }),
  check("ruleset_items_position_check", sql`${table.position} >= 0`),
]);

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
