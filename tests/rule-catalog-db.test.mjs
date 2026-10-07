import assert from "node:assert/strict";
import test from "node:test";
import postgres from "postgres";
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import { getStaticRules } from "../app/lib/sast-engine.ts";
import { createRuleSeedSql, createRuleSnapshot } from "../scripts/lib/sast-rule-seed.mjs";

test("PostgreSQL migration, exact catalog round-trip, repeat import and rollback", async () => {
  const url = new URL(process.env.SAST_RULE_TEST_DATABASE_URL ?? "http://missing-test-database");
  assert.ok(["localhost", "127.0.0.1"].includes(url.hostname), "use a dedicated local PostgreSQL instance");
  assert.equal(url.pathname, "/codesentry_rules_test", "use the dedicated codesentry_rules_test database");
  const client = postgres(url.toString(), { max: 1, connect_timeout: 10, onnotice: () => {} });
  const snapshot = createRuleSnapshot();
  const importSnapshot = (value) => client.begin(async (tx) => { await tx.unsafe(createRuleSeedSql(value)); });
  const readSnapshot = (hash) => client`
    SELECT item.rule_id, item.position, version.id, version.content_hash, version.definition
    FROM sast_rules.ruleset_items item
    JOIN sast_rules.rulesets ruleset ON ruleset.id = item.ruleset_id
    JOIN sast_rules.rule_versions version ON version.id = item.rule_version_id
    WHERE ruleset.content_hash = ${hash} ORDER BY item.position`;
  try {
    await migrate(drizzle(client), { migrationsFolder: "./drizzle" });
    const first = await readSnapshot(snapshot.contentHash);
    assert.equal(first.length, 150036);
    const sourceRules = getStaticRules();
    for (const [position, stored] of first.entries()) {
      const expected = snapshot.entries[position];
      assert.equal(stored.rule_id, expected.ruleId);
      assert.equal(stored.position, position);
      assert.equal(stored.content_hash, expected.contentHash);
      assert.deepEqual(stored.definition, expected.definition, expected.ruleId);
      assert.equal(new RegExp(stored.definition.pattern, stored.definition.patternFlags).toString(), sourceRules[position].pattern.toString());
    }
    await migrate(drizzle(client), { migrationsFolder: "./drizzle" });
    await importSnapshot(snapshot);
    await importSnapshot(snapshot);
    assert.deepEqual(await readSnapshot(snapshot.contentHash), first, "repeat imports preserve version IDs and definitions");
    const [counts] = await client`SELECT
      (SELECT count(*)::int FROM sast_rules.rules) AS rules,
      (SELECT count(*)::int FROM sast_rules.rule_versions) AS versions,
      (SELECT count(*)::int FROM sast_rules.rulesets) AS sets,
      (SELECT count(*)::int FROM sast_rules.ruleset_items) AS items`;
    assert.deepEqual(counts, { rules: 150036, versions: 150036, sets: 7, items: 398036 });
    const [historical] = await client`SELECT rule_count FROM sast_rules.rulesets WHERE name = 'builtin-1000-5837bdc59459'`;
    assert.equal(historical.rule_count, 1000, "original snapshot is preserved");

    const changed = getStaticRules();
    changed[0].title += " Тест O'Reilly";
    changed[0].pattern = /\btest\s*\('value'\)/im;
    await importSnapshot(createRuleSnapshot(changed));
    assert.deepEqual(await readSnapshot(snapshot.contentHash), first, "a new revision preserves previous sets");
    const changedSnapshot = createRuleSnapshot(changed);
    const changedRows = await readSnapshot(changedSnapshot.contentHash);
    assert.deepEqual(changedRows[0].definition, changedSnapshot.entries[0].definition);
    assert.notEqual(changedRows[0].id, first[0].id);
    assert.equal(changedRows[1].id, first[1].id, "unchanged definitions reuse the existing version");

    const invalid = structuredClone(snapshot);
    invalid.entries[0].definition.title = "tampered definition with unchanged hash";
    await assert.rejects(importSnapshot(invalid), /does not match/);
    assert.deepEqual(await readSnapshot(snapshot.contentHash), first, "failed imports roll back atomically");
    await assert.rejects(client.begin(async (tx) => {
      const [set] = await tx`INSERT INTO sast_rules.rulesets (name, content_hash, rule_count)
        VALUES ('invalid-member-test', ${"f".repeat(64)}, 1) RETURNING id`;
      await tx`INSERT INTO sast_rules.ruleset_items (ruleset_id, rule_id, rule_version_id, position)
        VALUES (${set.id}, ${first[0].rule_id}, ${first[1].id}, 0)`;
    }), { code: "23503" });
    const [invalidSets] = await client`SELECT count(*)::int AS count FROM sast_rules.rulesets WHERE name = 'invalid-member-test'`;
    assert.equal(invalidSets.count, 0);
  } finally {
    await client.end();
  }
});
