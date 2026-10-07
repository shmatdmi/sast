import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { readFile } from "node:fs/promises";
import { randomUUID, createHash } from "node:crypto";
import postgres from "postgres";
import { zipSync, strToU8 } from "fflate";

if (!process.env.API_TEST_DATABASE_URL || process.env.DATABASE_URL !== process.env.API_TEST_DATABASE_URL) {
  throw new Error("Run npm run test:integration to provision the isolated test database");
}
const databaseAddress = new URL(process.env.API_TEST_DATABASE_URL);
assert.equal(databaseAddress.hostname, "127.0.0.1", "Integration tests must use loopback PostgreSQL");
assert.equal(databaseAddress.pathname, "/sast_test", "Integration tests must use their dedicated database");
assert.equal(databaseAddress.username, "sast_test");
const sql = postgres(process.env.API_TEST_DATABASE_URL, { max: 1 });
let worker;
let adminCookie;
let version;
const origin = "https://codesentry.test";
async function api(path, { method = "GET", cookie, json, body, headers = {} } = {}) {
  const response = await worker.fetch(new Request(`${origin}${path}`, {
    method, headers: { ...headers, ...(cookie ? { cookie } : {}), ...(json !== undefined ? { "content-type": "application/json" } : {}) },
    body: json !== undefined ? JSON.stringify(json) : body,
  }), { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } }, { waitUntil() {}, passThroughOnException() {} });
  return response;
}
const cookieOf = response => {
  const cookie = response.headers.get("set-cookie");
  assert.ok(cookie, "Login must set a session cookie");
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
  assert.match(cookie, /Secure/);
  return cookie.split(";")[0];
};
async function login(username, password) {
  const response = await api("/api/auth/login", { method: "POST", json: { username, password } });
  assert.equal(response.status, 200);
  return cookieOf(response);
}
async function account(role = "user") {
  const username = `user-${randomUUID()}`;
  const response = await api("/api/users", { method: "POST", cookie: adminCookie,
    json: { username, displayName: "Test user", password: "1234567", role } });
  assert.equal(response.status, 201);
  return { username, id: (await response.json()).id, cookie: await login(username, "1234567") };
}
const patchUser = (id, action, role) => api("/api/users", { method: "PATCH", cookie: adminCookie, json: { id, action, role } });
const emptySummary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, score: 100 };
const scanPayload = () => ({ projectName: "Saved scan", release: "TEST-1", language: "javascript", scannedLines: 1, durationMs: 0, summary: emptySummary, findings: [] });
const sonarPayload = () => ({ projectName: "Sonar project", release: "TEST-2", result: {
  gate: "passed", rating: "A", metrics: { files: 1, lines: 1, codeLines: 1, commentLines: 0, complexity: 0, duplicatedLines: 0, duplicationPercent: 0, debtMinutes: 0 },
  counts: { bug: 0, vulnerability: 0, code_smell: 0 }, issues: [],
} });

before(async () => {
  // Real application migrations for accounts and scan storage. Rule-catalog
  // migrations have their own database suite and are not needed by the API.
  const journal = JSON.parse(await readFile(new URL("../drizzle/meta/_journal.json", import.meta.url), "utf8"));
  for (const entry of journal.entries.filter(entry => entry.idx <= 4)) {
    const migration = await readFile(new URL(`../drizzle/${entry.tag}.sql`, import.meta.url), "utf8");
    await sql.begin(async tx => {
      for (const statement of migration.split("--> statement-breakpoint").filter(s => s.trim())) await tx.unsafe(statement);
    });
  }
  globalThis.postgresClient = sql;
  ({ default: worker } = await import("../dist/server/index.js"));
  adminCookie = await login("test-admin", "admin-test-password");
  const health = await api("/api/health");
  assert.equal(health.status, 200);
  version = (await health.json()).version;
});
after(async () => {
  await sql.end();
  delete globalThis.postgresClient;
});

test("initial login creates exactly one administrator and stores only a token hash", async () => {
  const cookie = await login(" TEST-ADMIN ", "admin-test-password");
  const [row] = await sql`SELECT count(*)::int AS count FROM users WHERE username = 'test-admin'`;
  assert.equal(row.count, 1);
  const token = cookie.slice(cookie.indexOf("=") + 1);
  const [session] = await sql`SELECT token_hash, expires_at FROM user_sessions WHERE token_hash = ${createHash("sha256").update(token).digest("hex")}`;
  assert.ok(session);
  assert.notEqual(session.token_hash, token);
  assert.ok(new Date(session.expires_at).getTime() > Date.now());
});
test("unknown users and incorrect passwords receive the same error", async () => {
  const bodies = [];
  for (const username of ["test-admin", "does-not-exist"]) {
    const response = await api("/api/auth/login", { method: "POST", json: { username, password: "incorrect" } });
    assert.equal(response.status, 401);
    assert.equal(response.headers.get("set-cookie"), null);
    bodies.push(await response.json());
  }
  assert.deepEqual(bodies[0], bodies[1]);
});
test("malformed login JSON receives 400", async () => {
  const response = await api("/api/auth/login", { method: "POST", body: "{", headers: { "content-type": "application/json" } });
  assert.equal(response.status, 400);
});
test("a corrupted stored password hash never authenticates a user", async () => {
  const user = await account();
  await sql`UPDATE users SET password_hash = 'scrypt:eA==:!!!' WHERE id = ${user.id}`;
  assert.equal((await api("/api/auth/login", { method: "POST", json: { username: user.username, password: "arbitrary-password" } })).status, 401);
});
test("expired, forged and missing sessions cannot access protected APIs", async () => {
  const user = await account();
  await sql`UPDATE user_sessions SET expires_at = now() - interval '1 minute' WHERE user_id = ${user.id}`;
  for (const cookie of [undefined, "codesentry_session=forged", user.cookie]) {
    assert.equal((await api("/api/scans", { cookie })).status, 401);
  }
});
test("logout deletes the session and expires the browser cookie", async () => {
  const user = await account();
  const response = await api("/api/auth/logout", { method: "POST", cookie: user.cookie });
  assert.equal(response.status, 204);
  assert.match(response.headers.get("set-cookie"), /Max-Age=0/);
  assert.equal((await api("/api/scans", { cookie: user.cookie })).status, 401);
  assert.equal((await api("/api/auth/logout", { method: "POST" })).status, 204);
});
test("regular users cannot administer accounts", async () => {
  const user = await account();
  for (const method of ["GET", "POST", "PATCH", "DELETE"]) {
    assert.equal((await api("/api/users", { method, cookie: user.cookie, ...(method === "POST" || method === "PATCH" ? { json: {} } : {}) })).status, 403);
  }
});
test("account creation accepts seven characters, rejects six, normalizes names and prevents duplicates", async () => {
  const username = `boundary-${randomUUID()}`;
  for (const password of ["", "123456", "x".repeat(257)]) {
    assert.equal((await api("/api/users", { method: "POST", cookie: adminCookie,
      json: { username, displayName: "Boundary", password } })).status, 400);
  }
  const response = await api("/api/users", { method: "POST", cookie: adminCookie,
    json: { username: ` ${username.toUpperCase()} `, displayName: " Boundary ", password: "1234567" } });
  assert.equal(response.status, 201);
  const [stored] = await sql`SELECT * FROM users WHERE username = ${username}`;
  assert.equal(stored.display_name, "Boundary");
  assert.equal(stored.must_change_password, true);
  assert.notEqual(stored.password_hash, "1234567");
  assert.match(stored.password_hash, /^scrypt:/);
  assert.equal((await api("/api/users", { method: "POST", cookie: adminCookie,
    json: { username, displayName: "Duplicate", password: "1234567" } })).status, 409);
  const listed = await (await api("/api/users", { cookie: adminCookie })).json();
  assert.ok(listed.some(user => user.id === stored.id));
  assert.ok(listed.every(user => !("passwordHash" in user) && !("password_hash" in user)));
});
test("invalid account identifiers and empty display names are rejected", async () => {
  for (const fields of [{ username: "ab" }, { username: "bad name" }, { displayName: " " }, { displayName: "x".repeat(121) }]) {
    assert.equal((await api("/api/users", { method: "POST", cookie: adminCookie,
      json: { username: `valid-${randomUUID()}`, displayName: "User", password: "1234567", ...fields } })).status, 400);
  }
});
test("password changes reject incorrect current passwords and revoke every old session", async () => {
  const user = await account();
  const secondCookie = await login(user.username, "1234567");
  for (const [currentPassword, newPassword] of [["incorrect", "7654321"], ["1234567", "123456"], ["1234567", "x".repeat(257)]]) {
    assert.equal((await api("/api/auth/password", { method: "PUT", cookie: user.cookie, json: { currentPassword, newPassword } })).status, 400);
  }
  assert.equal((await api("/api/auth/password", { method: "PUT", cookie: user.cookie,
    json: { currentPassword: "1234567", newPassword: "7654321" } })).status, 204);
  for (const cookie of [user.cookie, secondCookie]) assert.equal((await api("/api/scans", { cookie })).status, 401);
  assert.equal((await api("/api/auth/login", { method: "POST", json: { username: user.username, password: "1234567" } })).status, 401);
  await login(user.username, "7654321");
  const [stored] = await sql`SELECT must_change_password FROM users WHERE id = ${user.id}`;
  assert.equal(stored.must_change_password, false);
});
test("administrator cannot block, demote or delete their own account", async () => {
  const [admin] = await sql`SELECT id FROM users WHERE username = 'test-admin'`;
  for (const action of ["block", "role", "delete"]) assert.equal((await patchUser(admin.id, action, "user")).status, 400);
  assert.equal((await api(`/api/users?id=${admin.id}`, { method: "DELETE", cookie: adminCookie })).status, 400);
});
test("blocking revokes sessions, prevents login and unblocking restores access", async () => {
  const user = await account();
  assert.equal((await patchUser(user.id, "block")).status, 200);
  assert.equal((await api("/api/scans", { cookie: user.cookie })).status, 401);
  assert.equal((await api("/api/auth/login", { method: "POST", json: { username: user.username, password: "1234567" } })).status, 401);
  assert.equal((await patchUser(user.id, "unblock")).status, 200);
  await login(user.username, "1234567");
});
test("role changes revoke sessions and new sessions respect the new role", async () => {
  const user = await account();
  assert.equal((await patchUser(user.id, "role", "admin")).status, 200);
  assert.equal((await api("/api/users", { cookie: user.cookie })).status, 401);
  const cookie = await login(user.username, "1234567");
  assert.equal((await api("/api/users", { cookie })).status, 200);
  assert.equal((await patchUser(user.id, "role", "user")).status, 200);
  assert.equal((await api("/api/users", { cookie })).status, 401);
  assert.equal((await api("/api/users", { cookie: await login(user.username, "1234567") })).status, 403);
});
test("reset generates a temporary password, revokes sessions and records an audit event", async () => {
  const user = await account();
  const response = await patchUser(user.id, "reset-password");
  assert.equal(response.status, 200);
  const { temporaryPassword } = await response.json();
  assert.ok(temporaryPassword.length >= 7);
  assert.equal((await api("/api/scans", { cookie: user.cookie })).status, 401);
  await login(user.username, temporaryPassword);
  const [stored] = await sql`SELECT must_change_password FROM users WHERE id = ${user.id}`;
  assert.equal(stored.must_change_password, true);
  const [audit] = await sql`SELECT action, details FROM user_audit_log WHERE target_user_id = ${user.id} AND action = 'user.reset-password'`;
  assert.ok(audit);
  assert.ok(!JSON.stringify(audit.details).includes(temporaryPassword));
});
test("deleting an account removes its sessions and keeps the audit record", async () => {
  const user = await account();
  assert.equal((await api(`/api/users?id=${user.id}`, { method: "DELETE", cookie: adminCookie })).status, 204);
  assert.equal((await api("/api/scans", { cookie: user.cookie })).status, 401);
  const [counts] = await sql`SELECT (SELECT count(*)::int FROM users WHERE id = ${user.id}) AS users,
    (SELECT count(*)::int FROM user_sessions WHERE user_id = ${user.id}) AS sessions`;
  assert.deepEqual(counts, { users: 0, sessions: 0 });
  const [audit] = await sql`SELECT action FROM user_audit_log WHERE action = 'user.delete' ORDER BY created_at DESC LIMIT 1`;
  assert.ok(audit);
});
test("missing accounts and unsupported actions do not mutate users", async () => {
  assert.equal((await patchUser(randomUUID(), "block")).status, 404);
  assert.equal((await api(`/api/users?id=${randomUUID()}`, { method: "DELETE", cookie: adminCookie })).status, 404);
  const user = await account();
  assert.equal((await patchUser(user.id, "unsupported")).status, 400);
  assert.equal((await api("/api/scans", { cookie: user.cookie })).status, 200);
});
test("authenticated dashboard renders coverage, password minimum and the release version", async () => {
  const response = await api("/", { cookie: adminCookie });
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.ok(html.includes(version));
  assert.match(html, /<strong>20<\/strong>/);
  assert.match(html, /minlength="7"/i);
  assert.doesNotMatch(html, /minlength="10"/i);
});
test("health returns the database state and the same release version as scans", async () => {
  const response = await api("/api/health");
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: "ok", database: "connected", version });
});
test("JSON scan runs analysis and persists its findings atomically", async () => {
  const response = await api("/api/scans/json", { method: "POST", cookie: adminCookie,
    json: { projectName: " JSON project ", release: " TEST-3 ", files: [{ name: "src/api.js", code: "eval(input);" }, { name: "src/main.py", code: "print('hello')" }] } });
  assert.equal(response.status, 201);
  const result = await response.json();
  assert.equal(result.version, version);
  assert.equal(result.projectName, "JSON project");
  assert.equal(result.filesScanned, 2);
  assert.equal(result.language, "multiple");
  assert.ok(result.findings.some(finding => finding.ruleId === "JS001" && finding.filename === "src/api.js"));
  const detail = await api(`/api/scans?id=${result.scanId}`, { cookie: adminCookie });
  assert.equal(detail.status, 200);
  const stored = await detail.json();
  assert.equal(stored.findings.length, result.findings.length);
  assert.deepEqual(stored.summary, result.summary);
  for (const finding of result.findings) assert.ok(stored.findings.some(item => item.id === finding.id && item.filename === finding.filename && item.ruleId === finding.ruleId));
});
test("invalid JSON scans are rejected without creating database rows", async () => {
  const [before] = await sql`SELECT count(*)::int AS count FROM scan_runs`;
  for (const [json, status] of [[{}, 400], [{ projectName: "x", release: "TEST-0", files: [] }, 400],
    [{ projectName: "x", release: "TEST-1", files: [{ name: "../outside.js", code: "" }] }, 400]]) {
    assert.equal((await api("/api/scans/json", { method: "POST", cookie: adminCookie, json })).status, status);
  }
  assert.equal((await api("/api/scans/json", { method: "POST", cookie: adminCookie, body: "{}", headers: { "content-type": "text/plain" } })).status, 415);
  assert.equal((await api("/api/scans/json", { method: "POST", cookie: adminCookie, body: "{", headers: { "content-type": "application/json" } })).status, 400);
  const [after] = await sql`SELECT count(*)::int AS count FROM scan_runs`;
  assert.equal(after.count, before.count);
});
test("stored scan API saves empty reports, searches by project and release, and returns 404", async () => {
  const payload = scanPayload();
  payload.projectName = `Search ${randomUUID()}`;
  payload.release = "FIND-9999";
  const response = await api("/api/scans", { method: "POST", cookie: adminCookie, json: payload });
  assert.equal(response.status, 201);
  const { id } = await response.json();
  const detail = await (await api(`/api/scans?id=${id}`, { cookie: adminCookie })).json();
  assert.deepEqual(detail.findings, []);
  assert.equal(detail.filesScanned, 1);
  for (const q of [payload.projectName.toLowerCase(), payload.release.toLowerCase()]) {
    const results = await (await api(`/api/scans?q=${encodeURIComponent(q)}`, { cookie: adminCookie })).json();
    assert.ok(results.some(scan => scan.id === id));
  }
  assert.deepEqual(await (await api("/api/scans?q=nonexistent-search-query", { cookie: adminCookie })).json(), []);
  assert.equal((await api(`/api/scans?id=${randomUUID()}`, { cookie: adminCookie })).status, 404);
});
test("stored scan API rejects malformed payloads and size declarations", async () => {
  for (const change of [{ projectName: "" }, { release: "TEST-0" }, { scannedLines: -1 }, { durationMs: 1.5 },
    { findings: {} }, { findings: Array(10001).fill({}) }, { summary: { ...emptySummary, score: 101 } }]) {
    assert.equal((await api("/api/scans", { method: "POST", cookie: adminCookie, json: { ...scanPayload(), ...change } })).status, 400);
  }
  assert.equal((await api("/api/scans", { method: "POST", cookie: adminCookie, body: "{", headers: { "content-type": "application/json" } })).status, 400);
  assert.equal((await api("/api/scans", { method: "POST", cookie: adminCookie, json: scanPayload(), headers: { "content-length": "5242881" } })).status, 413);
});
test("failed finding insertion rolls back its scan run", async () => {
  const [before] = await sql`SELECT count(*)::int AS count FROM scan_runs`;
  const response = await api("/api/scans", { method: "POST", cookie: adminCookie, json: { ...scanPayload(), findings: [null] } });
  assert.equal(response.status, 500);
  const [after] = await sql`SELECT count(*)::int AS count FROM scan_runs`;
  assert.equal(after.count, before.count);
});
function archiveForm({ name = "project.zip", bytes = zipSync({ "src/app.js": strToU8("eval(input);"), "README.md": strToU8("docs") }), release = "TEST-4", projectName } = {}) {
  const form = new FormData();
  form.set("archive", new File([bytes], name));
  form.set("release", release);
  if (projectName !== undefined) form.set("projectName", projectName);
  return form;
}
test("JSON API scans all six added languages and retains their filenames", async () => {
  const cases = [
    ["src/main.c", "gets(buffer);", "C001"],
    ["src/main.cpp", "std::strcpy(buffer, input);", "CPP001"],
    ["src/main.dart", "client.badCertificateCallback = (cert, host, port) => true;", "DART001"],
    ["src/main.ex", 'Code.eval_string(params["code"])', "ELIXIR001"],
    ["src/main.lua", "os.execute(command)", "LUA001"],
    ["src/main.ps1", "Invoke-Expression -Command $userInput", "PS001"],
  ];
  const response = await api("/api/scans/json", { method: "POST", cookie: adminCookie,
    json: { projectName: "Coverage 20", release: "TEST-20", files: cases.map(([name, code]) => ({ name, code })) } });
  assert.equal(response.status, 201);
  const result = await response.json();
  assert.equal(result.filesScanned, 6);
  assert.equal(result.version, version);
  for (const [filename, , ruleId] of cases) assert.ok(result.findings.some(finding => finding.ruleId === ruleId && finding.filename === filename));
});
test("ZIP scan uses the archive name, skips unsupported files and persists real findings", async () => {
  const response = await api("/api/scans/archive", { method: "POST", cookie: adminCookie, body: archiveForm() });
  assert.equal(response.status, 201);
  const result = await response.json();
  assert.equal(result.projectName, "project");
  assert.equal(result.skippedFiles, 1);
  assert.equal(result.filesScanned, 1);
  assert.ok(result.findings.some(finding => finding.ruleId === "JS001"));
  const detail = await (await api(`/api/scans?id=${result.scanId}`, { cookie: adminCookie })).json();
  assert.equal(detail.findings.length, result.findings.length);
});
test("ZIP API rejects wrong media types, empty archives, corrupt data and traversal", async () => {
  assert.equal((await api("/api/scans/archive", { method: "POST", cookie: adminCookie, json: {} })).status, 415);
  for (const form of [archiveForm({ name: "project.txt" }), archiveForm({ bytes: new Uint8Array() }),
    archiveForm({ bytes: strToU8("not ZIP") }), archiveForm({ bytes: zipSync({ "../outside.js": strToU8("eval(input)") }) }),
    archiveForm({ release: "BAD-0" }), archiveForm({ projectName: "x".repeat(513) }), new FormData()]) {
    assert.equal((await api("/api/scans/archive", { method: "POST", cookie: adminCookie, body: form })).status, 400);
  }
});
test("Sonar API persists metrics and issue details and accepts empty reports", async () => {
  for (const issue of [undefined, { id: "issue-1", file: "src/app.js", line: 1, type: "bug", severity: "major", message: "Empty catch", rule: "SL2001", effortMinutes: 10 }]) {
    const payload = sonarPayload();
    if (issue) { payload.result.issues.push(issue); payload.result.counts.bug = 1; }
    const response = await api("/api/sonar-scans", { method: "POST", cookie: adminCookie, json: payload });
    assert.equal(response.status, 201);
    const { id } = await response.json();
    const [stored] = await sql`SELECT * FROM sonar_scan_runs WHERE id = ${id}`;
    assert.deepEqual(stored.metrics, payload.result.metrics);
    assert.deepEqual(stored.counts, payload.result.counts);
    const issues = await sql`SELECT * FROM sonar_scan_issues WHERE sonar_scan_run_id = ${id}`;
    assert.equal(issues.length, issue ? 1 : 0);
    if (issue) { assert.equal(issues[0].issue_id, issue.id); assert.equal(issues[0].filename, issue.file); }
  }
});
test("Sonar API rejects invalid issue categories, metrics and JSON", async () => {
  for (const result of [{ gate: "unknown" }, { rating: "Z" }, { metrics: {} }, { counts: {} },
    { issues: [null] }, { issues: Array(10001).fill({}) }, { issues: [{ id: "i", file: "x", message: "m", rule: "r", type: "other", severity: "major", line: 1, effortMinutes: 0 }] }]) {
    const payload = sonarPayload();
    Object.assign(payload.result, result);
    assert.equal((await api("/api/sonar-scans", { method: "POST", cookie: adminCookie, json: payload })).status, 400);
  }
  assert.equal((await api("/api/sonar-scans", { method: "POST", cookie: adminCookie, body: "{", headers: { "content-type": "application/json" } })).status, 400);
  assert.equal((await api("/api/sonar-scans", { method: "POST", cookie: adminCookie, json: sonarPayload(), headers: { "content-length": "5242881" } })).status, 413);
});
test("health reports 503 if the database cannot connect", async () => {
  const originalUrl = process.env.DATABASE_URL;
  const originalClient = globalThis.postgresClient;
  process.env.DATABASE_URL = "postgres://sast_test:test@127.0.0.1:1/sast_test";
  globalThis.postgresClient = postgres(process.env.DATABASE_URL, { max: 1, connect_timeout: 1 });
  try {
    const response = await api("/api/health");
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { status: "error", database: "unavailable", version });
  } finally {
    await globalThis.postgresClient?.end();
    globalThis.postgresClient = originalClient;
    process.env.DATABASE_URL = originalUrl;
  }
});
