import { createHash } from "node:crypto";
import { getStaticRules } from "../../app/lib/sast-engine.ts";

const hash = (value) => createHash("sha256").update(JSON.stringify(value), "utf8").digest("hex");
const literal = (value) => "'" + value.replaceAll("'", "''") + "'";

export function createRuleSnapshot(source = getStaticRules()) {
  if (!source.length) throw new Error("Cannot import an empty rule catalog");
  const ids = new Set();
  const entries = source.map((rule) => {
    if (!rule.id || ids.has(rule.id)) throw new Error(`Duplicate or empty rule ID: ${rule.id}`);
    ids.add(rule.id);
    const definition = {
      id: rule.id, languages: [...rule.languages], title: rule.title,
      description: rule.description, severity: rule.severity, cwe: rule.cwe,
      owasp: rule.owasp, confidence: rule.confidence,
      pattern: rule.pattern.source, patternFlags: rule.pattern.flags,
      exclude: rule.exclude?.source ?? null, excludeFlags: rule.exclude?.flags ?? null,
      scope: rule.scope ?? "line", category: rule.category ?? null,
      recommendation: rule.recommendation, references: [...rule.references],
    };
    return { ruleId: rule.id, contentHash: hash(definition), definition };
  });
  const contentHash = hash(entries.map(({ ruleId, contentHash }) => ({ ruleId, contentHash })));
  return { name: `builtin-${entries.length}-${contentHash.slice(0, 12)}`, contentHash, entries };
}

/** Run within one transaction, both in Drizzle migrations and standalone imports. */
export function createRuleSeedSql(snapshot = createRuleSnapshot()) {
  const { entries, name, contentHash } = snapshot;
  const quotedHash = literal(contentHash);
  return `-- Built-in catalog: ${name}; ${entries.length} static rules.
SET LOCAL standard_conforming_strings = on;
SELECT pg_advisory_xact_lock(hashtext('codesentry:sast-rules:seed'));

CREATE TEMP TABLE sast_rule_seed_data ON COMMIT DROP AS
SELECT entry->>'ruleId' AS rule_id,
       entry->>'contentHash' AS content_hash,
       entry->'definition' AS definition,
       (ordinality - 1)::integer AS position
FROM jsonb_array_elements(${literal(JSON.stringify(entries))}::jsonb)
WITH ORDINALITY AS data(entry, ordinality);

INSERT INTO sast_rules.rules (id, title, languages, category, cwe, owasp)
SELECT rule_id, definition->>'title', definition->'languages',
       definition->>'category', definition->>'cwe', definition->>'owasp'
FROM sast_rule_seed_data
ON CONFLICT (id) DO NOTHING;

INSERT INTO sast_rules.rule_versions (rule_id, content_hash, definition)
SELECT rule_id, content_hash, definition FROM sast_rule_seed_data
ON CONFLICT (rule_id, content_hash) DO NOTHING;

INSERT INTO sast_rules.rulesets (name, source, content_hash, rule_count)
VALUES (${literal(name)}, 'builtin', ${quotedHash}, ${entries.length})
ON CONFLICT (content_hash) DO NOTHING;

INSERT INTO sast_rules.ruleset_items (ruleset_id, rule_id, rule_version_id, position)
SELECT ruleset.id, seed.rule_id, version.id, seed.position
FROM sast_rule_seed_data seed
JOIN sast_rules.rule_versions version
  ON version.rule_id = seed.rule_id AND version.content_hash = seed.content_hash
CROSS JOIN sast_rules.rulesets ruleset
WHERE ruleset.content_hash = ${quotedHash}
ON CONFLICT (ruleset_id, rule_id) DO NOTHING;

DO $verify_catalog$
BEGIN
  IF (SELECT count(*) FROM sast_rules.ruleset_items item
      JOIN sast_rules.rulesets ruleset ON ruleset.id = item.ruleset_id
      WHERE ruleset.content_hash = ${quotedHash}) <> ${entries.length}
     OR NOT EXISTS (SELECT 1 FROM sast_rules.rulesets
                    WHERE content_hash = ${quotedHash} AND rule_count = ${entries.length})
     OR EXISTS (
       SELECT 1 FROM sast_rule_seed_data seed
       LEFT JOIN sast_rules.rule_versions version
         ON version.rule_id = seed.rule_id AND version.content_hash = seed.content_hash
       LEFT JOIN sast_rules.ruleset_items item
         ON item.rule_version_id = version.id
         AND item.rule_id = seed.rule_id
         AND item.ruleset_id = (SELECT id FROM sast_rules.rulesets WHERE content_hash = ${quotedHash})
       WHERE version.definition IS DISTINCT FROM seed.definition
          OR item.position IS DISTINCT FROM seed.position
     ) THEN
    RAISE EXCEPTION 'Imported SAST catalog does not match the built-in snapshot';
  END IF;
END
$verify_catalog$;
`;
}
