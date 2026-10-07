import { readFileSync, writeFileSync } from "node:fs";
import { getStaticRules } from "../app/lib/sast-engine.ts";
import { createCoverageRules } from "../app/lib/sast-rules-coverage.ts";
import { createRuleSnapshot } from "./lib/sast-rule-seed.mjs";
import { createRuleExtensionSql } from "./lib/sast-rule-extension.mjs";

const tag = "0011_coverage_20_languages";
const rules = getStaticRules();
const base = createRuleSnapshot(rules.slice(0, -createCoverageRules().length));
const snapshot = createRuleSnapshot(rules);
const parentSql = readFileSync(new URL("../drizzle/0010_expression_rule_catalog_150000.sql", import.meta.url), "utf8");
if (!parentSql.startsWith(`-- Built-in catalog: ${base.name};`)) throw new Error("Historical 150000-rule snapshot changed");
writeFileSync(new URL(`../drizzle/${tag}.sql`, import.meta.url), createRuleExtensionSql(base, snapshot));
const journalPath = new URL("../drizzle/meta/_journal.json", import.meta.url);
const journal = JSON.parse(readFileSync(journalPath, "utf8"));
if (!journal.entries.some((entry) => entry.tag === tag)) {
  const previous = journal.entries.at(-1);
  journal.entries.push({ idx: previous.idx + 1, version: "7", when: Math.max(Date.now(), previous.when + 1), tag, breakpoints: true });
  writeFileSync(journalPath, JSON.stringify(journal, null, 2) + "\n");
}
console.log(JSON.stringify({ base: base.name, snapshot: snapshot.name, rules: rules.length, added: createCoverageRules().length, contentHash: snapshot.contentHash }));
