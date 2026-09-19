CREATE TABLE "scan_findings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"scan_run_id" uuid NOT NULL,
	"finding_id" text NOT NULL,
	"rule_id" text NOT NULL,
	"title" text NOT NULL,
	"description" text NOT NULL,
	"severity" text NOT NULL,
	"cwe" text NOT NULL,
	"owasp" text NOT NULL,
	"confidence" text NOT NULL,
	"line" integer NOT NULL,
	"column" integer NOT NULL,
	"snippet" text NOT NULL,
	"recommendation" text NOT NULL,
	"references" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"category" text NOT NULL,
	"context" text,
	"filename" text
);
--> statement-breakpoint
ALTER TABLE "scan_runs" ALTER COLUMN "summary" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "scan_runs" ADD COLUMN "language" text DEFAULT 'unknown' NOT NULL;--> statement-breakpoint
ALTER TABLE "scan_runs" ADD COLUMN "scanned_lines" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "scan_runs" ADD COLUMN "duration_ms" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "scan_runs" ADD COLUMN "files_scanned" integer DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "scan_runs" ALTER COLUMN "language" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "scan_runs" ALTER COLUMN "scanned_lines" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "scan_runs" ALTER COLUMN "duration_ms" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "scan_findings" ADD CONSTRAINT "scan_findings_scan_run_id_scan_runs_id_fk" FOREIGN KEY ("scan_run_id") REFERENCES "public"."scan_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "scan_findings_scan_run_id_idx" ON "scan_findings" USING btree ("scan_run_id");--> statement-breakpoint
CREATE INDEX "scan_findings_severity_idx" ON "scan_findings" USING btree ("severity");--> statement-breakpoint
CREATE INDEX "scan_findings_rule_id_idx" ON "scan_findings" USING btree ("rule_id");--> statement-breakpoint
CREATE INDEX "scan_runs_created_at_idx" ON "scan_runs" USING btree ("created_at");
