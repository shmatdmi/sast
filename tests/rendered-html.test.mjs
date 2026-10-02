import assert from "node:assert/strict";
import test from "node:test";

async function render(request = new Request("https://codesentry.example/", { headers: { accept: "text/html" } })) {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);
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
