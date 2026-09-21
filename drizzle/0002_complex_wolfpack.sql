ALTER TABLE "scan_runs" ADD COLUMN "release" text;--> statement-breakpoint
UPDATE "scan_runs" SET "release" = 'legacy-1' WHERE "release" IS NULL;--> statement-breakpoint
ALTER TABLE "scan_runs" ALTER COLUMN "release" SET NOT NULL;--> statement-breakpoint
CREATE INDEX "scan_runs_release_idx" ON "scan_runs" USING btree ("release");
