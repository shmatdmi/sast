const literal = (value) => "'" + value.replaceAll("'", "''") + "'";

/** Compact append-only migration: reuse the persisted parent instead of embedding it. */
export function createRuleExtensionSql(base, snapshot) {
  const parent = snapshot.entries.slice(0, base.entries.length);
  if (parent.length !== base.entries.length || parent.some((entry, index) => JSON.stringify(entry) !== JSON.stringify(base.entries[index]))
      || snapshot.entries.length <= base.entries.length) {
    throw new Error("Rule extensions must preserve all parent definitions and their order");
  }
  const added = snapshot.entries.slice(base.entries.length);
  const baseHash = literal(base.contentHash);
  const nextHash = literal(snapshot.contentHash);
  return `-- Built-in catalog: ${snapshot.name}; ${snapshot.entries.length} static rules.
-- Reuse ${base.name} and import only ${added.length} appended definitions.
SET LOCAL standard_conforming_strings = on;
SELECT pg_advisory_xact_lock(hashtext('codesentry:sast-rules:seed'));

DO $verify_parent$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM sast_rules.rulesets
                 WHERE content_hash = ${baseHash} AND rule_count = ${base.entries.length})
     OR (SELECT count(*) FROM sast_rules.ruleset_items item
         JOIN sast_rules.rulesets ruleset ON ruleset.id = item.ruleset_id
         WHERE ruleset.content_hash = ${baseHash}) <> ${base.entries.length} THEN
    RAISE EXCEPTION 'Parent SAST catalog is missing or incomplete';
  END IF;
END
$verify_parent$;

CREATE TEMP TABLE sast_rule_extension ON COMMIT DROP AS
SELECT entry->>'ruleId' AS rule_id, entry->>'contentHash' AS content_hash,
       entry->'definition' AS definition,
       (${base.entries.length} + ordinality - 1)::integer AS position
FROM jsonb_array_elements(${literal(JSON.stringify(added))}::jsonb)
WITH ORDINALITY AS data(entry, ordinality);

INSERT INTO sast_rules.rules (id, title, languages, category, cwe, owasp)
SELECT rule_id, definition->>'title', definition->'languages',
       definition->>'category', definition->>'cwe', definition->>'owasp'
FROM sast_rule_extension ON CONFLICT (id) DO NOTHING;

INSERT INTO sast_rules.rule_versions (rule_id, content_hash, definition)
SELECT rule_id, content_hash, definition FROM sast_rule_extension
ON CONFLICT (rule_id, content_hash) DO NOTHING;

INSERT INTO sast_rules.rulesets (name, source, content_hash, rule_count)
VALUES (${literal(snapshot.name)}, 'builtin', ${nextHash}, ${snapshot.entries.length})
ON CONFLICT (content_hash) DO NOTHING;

INSERT INTO sast_rules.ruleset_items (ruleset_id, rule_id, rule_version_id, position)
SELECT next.id, item.rule_id, item.rule_version_id, item.position
FROM sast_rules.ruleset_items item
JOIN sast_rules.rulesets parent ON parent.id = item.ruleset_id
CROSS JOIN sast_rules.rulesets next
WHERE parent.content_hash = ${baseHash} AND next.content_hash = ${nextHash}
UNION ALL
SELECT next.id, seed.rule_id, version.id, seed.position
FROM sast_rule_extension seed
JOIN sast_rules.rule_versions version
  ON version.rule_id = seed.rule_id AND version.content_hash = seed.content_hash
CROSS JOIN sast_rules.rulesets next
WHERE next.content_hash = ${nextHash}
ON CONFLICT (ruleset_id, rule_id) DO NOTHING;

DO $verify_extension$
BEGIN
  IF (SELECT count(*) FROM sast_rules.ruleset_items item
      JOIN sast_rules.rulesets ruleset ON ruleset.id = item.ruleset_id
      WHERE ruleset.content_hash = ${nextHash}) <> ${snapshot.entries.length}
     OR NOT EXISTS (SELECT 1 FROM sast_rules.rulesets
                    WHERE content_hash = ${nextHash} AND rule_count = ${snapshot.entries.length})
     OR EXISTS (
       SELECT 1 FROM sast_rules.ruleset_items original
       JOIN sast_rules.rulesets parent ON parent.id = original.ruleset_id
       LEFT JOIN sast_rules.ruleset_items copied
         ON copied.ruleset_id = (SELECT id FROM sast_rules.rulesets WHERE content_hash = ${nextHash})
         AND copied.rule_id = original.rule_id
       WHERE parent.content_hash = ${baseHash}
         AND (copied.rule_version_id IS DISTINCT FROM original.rule_version_id
              OR copied.position IS DISTINCT FROM original.position)
     )
     OR EXISTS (
       SELECT 1 FROM sast_rule_extension seed
       LEFT JOIN sast_rules.rule_versions version
         ON version.rule_id = seed.rule_id AND version.content_hash = seed.content_hash
       LEFT JOIN sast_rules.ruleset_items item
         ON item.rule_version_id = version.id AND item.rule_id = seed.rule_id
         AND item.ruleset_id = (SELECT id FROM sast_rules.rulesets WHERE content_hash = ${nextHash})
       WHERE version.definition IS DISTINCT FROM seed.definition
          OR item.position IS DISTINCT FROM seed.position
     ) THEN
    RAISE EXCEPTION 'Extended SAST catalog does not match the built-in snapshot';
  END IF;
END
$verify_extension$;
`;
}
