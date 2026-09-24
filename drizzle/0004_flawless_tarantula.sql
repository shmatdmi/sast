CREATE TABLE "sonar_scan_issues" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"sonar_scan_run_id" uuid NOT NULL,
	"issue_id" text NOT NULL,
	"type" text NOT NULL,
	"severity" text NOT NULL,
	"filename" text NOT NULL,
	"line" integer NOT NULL,
	"message" text NOT NULL,
	"rule" text NOT NULL,
	"effort_minutes" integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sonar_scan_runs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"project_name" text NOT NULL,
	"release" text NOT NULL,
	"status" text DEFAULT 'completed' NOT NULL,
	"gate" text NOT NULL,
	"rating" text NOT NULL,
	"metrics" jsonb NOT NULL,
	"counts" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "sonar_scan_issues" ADD CONSTRAINT "sonar_scan_issues_sonar_scan_run_id_sonar_scan_runs_id_fk" FOREIGN KEY ("sonar_scan_run_id") REFERENCES "public"."sonar_scan_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "sonar_scan_issues_run_id_idx" ON "sonar_scan_issues" USING btree ("sonar_scan_run_id");--> statement-breakpoint
CREATE INDEX "sonar_scan_issues_severity_idx" ON "sonar_scan_issues" USING btree ("severity");--> statement-breakpoint
CREATE INDEX "sonar_scan_issues_rule_idx" ON "sonar_scan_issues" USING btree ("rule");--> statement-breakpoint
CREATE INDEX "sonar_scan_runs_created_at_idx" ON "sonar_scan_runs" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "sonar_scan_runs_release_idx" ON "sonar_scan_runs" USING btree ("release");