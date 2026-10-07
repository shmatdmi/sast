import assert from "node:assert/strict";
import test from "node:test";

const workerPromise = import("../dist/server/index.js");

async function render(request = new Request("https://codesentry.example/", { headers: { accept: "text/html" } })) {
  const { default: worker } = await workerPromise;
  return worker.fetch(
    request,
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("server-renders the protected CodeSentry login page", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);
  const html = await response.text();
  assert.match(html, /<html lang="ru">/i);
  assert.match(html, /CodeSentry/i);
  assert.match(html, /Вход в систему/i);
  assert.match(html, /Логин/i);
  assert.match(html, /Пароль/i);
  assert.doesNotMatch(html, /Запустить проверку/i);
  assert.match(html, /og\.png/i);
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape|Building your site/i);
});

test("JSON scan API requires authentication before processing sources", async () => {
  const response = await render(new Request("https://codesentry.example/api/scans/json", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ projectName: "Example", release: "TEST-1", files: [{ name: "app.js", code: "eval(input)" }] }),
  }));
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: "Требуется авторизация" });
});

for (const [path, methods] of [
  ["/api/users", ["GET", "POST", "PATCH", "DELETE"]],
  ["/api/scans", ["GET", "POST"]],
  ["/api/sonar-scans", ["POST"]],
  ["/api/auth/password", ["PUT"]],
]) {
  for (const method of methods) {
    test(`${method} ${path} rejects unauthenticated requests before touching the database`, async () => {
      const response = await render(new Request(`https://codesentry.example${path}`, {
        method, ...(method === "POST" || method === "PATCH" || method === "PUT" ? { body: "invalid JSON" } : {}),
      }));
      assert.equal(response.status, 401);
      assert.equal(typeof (await response.json()).error, "string");
    });
  }
}

test("ZIP uploads up to 10 MiB reach API authentication", async () => {
  for (const size of [3250586, 10 * 1024 * 1024]) {
    const form = new FormData();
    form.set("archive", new Blob([new Uint8Array(size)]), "project.zip");
    form.set("release", "TEST-1");
    const response = await render(new Request("https://codesentry.example/api/scans/archive", {
      method: "POST", body: form,
    }));
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: "Требуется авторизация" });
  }
});

test("multipart uploads declared above the framework limit are rejected", async () => {
  const form = new FormData();
  form.set("archive", new Blob([new Uint8Array(11 * 1024 * 1024)]), "project.zip");
  const response = await render(new Request("https://codesentry.example/api/scans/archive", {
    method: "POST", body: form,
    headers: { "content-length": String(11 * 1024 * 1024 + 1024) },
  }));
  assert.equal(response.status, 413);
});
