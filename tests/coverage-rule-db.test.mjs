import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import test from "node:test";
import postgres from "postgres";
import { getStaticRules } from "../app/lib/sast-engine.ts";
import { createRuleSnapshot } from "../scripts/lib/sast-rule-seed.mjs";
import { createRuleExtensionSql } from "../scripts/lib/sast-rule-extension.mjs";

test("compact coverage migration reuses 150000 parent rules, is repeatable and rolls back invalid definitions", async () => {
  const url = new URL(process.env.SAST_RULE_TEST_DATABASE_URL ?? "http://missing-test-database");
  assert.ok(["localhost", "127.0.0.1"].includes(url.hostname));
  assert.equal(url.pathname, "/codesentry_rules_test");
  const client = postgres(url.toString(), { max: 1, onnotice: () => {} });
  const source = getStaticRules();
  const snapshot = createRuleSnapshot(source);
  const base = createRuleSnapshot(source.slice(0, 150000));
  const migration = readFileSync("drizzle/0011_coverage_20_languages.sql", "utf8");
  const run = (sql) => client.begin((tx) => tx.unsafe(sql));
  const counts = async () => (await client`SELECT
    (SELECT count(*)::int FROM sast_rules.rules) AS rules,
    (SELECT count(*)::int FROM sast_rules.rule_versions) AS versions,
    (SELECT count(*)::int FROM sast_rules.rulesets) AS sets,
    (SELECT count(*)::int FROM sast_rules.ruleset_items) AS items`)[0];
  try {
    const ddl = readFileSync("drizzle/0005_little_silvermane.sql", "utf8").split("-- Built-in catalog:")[0];
    await client.unsafe(ddl);
    await assert.rejects(run(migration), /Parent SAST catalog/);
    assert.deepEqual(await counts(), { rules: 0, versions: 0, sets: 0, items: 0 });

    await client.begin(async (tx) => {
      await tx`CREATE TEMP TABLE coverage_parent_seed (rule_id text, content_hash text, definition jsonb, position integer) ON COMMIT DROP`;
      const copy = await tx`COPY coverage_parent_seed FROM STDIN WITH (FORMAT csv)`.writable();
      function* rows() {
        for (const [position, entry] of base.entries.entries()) {
          yield `${entry.ruleId},${entry.contentHash},"${JSON.stringify(entry.definition).replaceAll('"', '""')}",${position}\n`;
        }
      }
      await pipeline(Readable.from(rows()), copy);
      await tx`INSERT INTO sast_rules.rules (id, title, languages, category, cwe, owasp)
        SELECT rule_id, definition->>'title', definition->'languages', definition->>'category', definition->>'cwe', definition->>'owasp' FROM coverage_parent_seed`;
      await tx`INSERT INTO sast_rules.rule_versions (rule_id, content_hash, definition)
        SELECT rule_id, content_hash, definition FROM coverage_parent_seed`;
      const [set] = await tx`INSERT INTO sast_rules.rulesets (name, content_hash, rule_count)
        VALUES (${base.name}, ${base.contentHash}, ${base.entries.length}) RETURNING id`;
      await tx`INSERT INTO sast_rules.ruleset_items (ruleset_id, rule_id, rule_version_id, position)
        SELECT ${set.id}, seed.rule_id, version.id, seed.position FROM coverage_parent_seed seed
        JOIN sast_rules.rule_versions version ON version.rule_id = seed.rule_id AND version.content_hash = seed.content_hash`;
    });
    await run(migration);
    const expectedCounts = { rules: 150036, versions: 150036, sets: 2, items: 300036 };
    assert.deepEqual(await counts(), expectedCounts);
    const rows = await client`SELECT item.rule_id, version.content_hash, item.position
      FROM sast_rules.ruleset_items item JOIN sast_rules.rulesets ruleset ON ruleset.id = item.ruleset_id
      JOIN sast_rules.rule_versions version ON version.id = item.rule_version_id
      WHERE ruleset.content_hash = ${snapshot.contentHash} ORDER BY item.position`;
    const hash = createHash("sha256").update(JSON.stringify(rows.map(({ rule_id, content_hash }, position) => {
      assert.equal(rows[position].position, position);
      return { ruleId: rule_id, contentHash: content_hash };
    }))).digest("hex");
    assert.equal(hash, snapshot.contentHash);
    const added = await client`SELECT item.position, version.definition
      FROM sast_rules.ruleset_items item JOIN sast_rules.rulesets ruleset ON ruleset.id = item.ruleset_id
      JOIN sast_rules.rule_versions version ON version.id = item.rule_version_id
      WHERE ruleset.content_hash = ${snapshot.contentHash} AND item.position >= 150000 ORDER BY item.position`;
    assert.equal(added.length, 36);
    for (const row of added) assert.deepEqual(row.definition, snapshot.entries[row.position].definition);

    await run(migration);
    assert.deepEqual(await counts(), expectedCounts);
    const invalid = { ...snapshot, entries: [...snapshot.entries] };
    invalid.entries[150000] = structuredClone(invalid.entries[150000]);
    invalid.entries[150000].definition.title += " tampered";
    await assert.rejects(run(createRuleExtensionSql(base, invalid)), /does not match/);
    assert.deepEqual(await counts(), expectedCounts);
  } finally {
    await client.end();
  }
});
