import { writeFileSync } from "node:fs";
import postgres from "postgres";
import { createRuleSeedSql, createRuleSnapshot } from "./lib/sast-rule-seed.mjs";

const snapshot = createRuleSnapshot();
const sql = createRuleSeedSql(snapshot);
const args = process.argv.slice(2);

if (args[0] === "--sql" && args.length === 2) {
  writeFileSync(args[1], "BEGIN;\n" + sql + "COMMIT;\n", "utf8");
  console.log(`Exported ${snapshot.entries.length} rules: ${snapshot.name} to ${args[1]}`);
} else if (args.length) {
  throw new Error("Usage: npm run rules:seed [-- --sql <output.sql>]");
} else {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required; run db:migrate before rules:seed");
  const client = postgres(process.env.DATABASE_URL, { max: 1, connect_timeout: 10 });
  try {
    await client.begin(async (transaction) => { await transaction.unsafe(sql); });
    console.log(`Imported ${snapshot.entries.length} rules: ${snapshot.name} (${snapshot.contentHash})`);
  } finally {
    await client.end();
  }
}
