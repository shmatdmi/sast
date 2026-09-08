const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync(require('node:path').join(__dirname, 'weather-api.js'), 'utf8');

function createStorage(seed = {}) {
  const values = new Map(Object.entries(seed));
  return {
    getItem(key) { return values.has(key) ? values.get(key) : null; },
    setItem(key, value) { values.set(key, value); },
    snapshot() { return Object.fromEntries(values); }
  };
}

function loadWeather(fetch, localStorage) {
  const window = {};
  vm.runInNewContext(source, { window, fetch, localStorage, Intl, Date, URL, encodeURIComponent, Map, Object, Number, Error });
  return window.Weather;
}

(async () => {
  const payload = { weather: [{ id: 800, description: 'ясно' }], main: { temp: 21 }, wind: { speed: 2 } };
  const storage = createStorage();
  const online = loadWeather(async () => ({ ok: true, json: async () => payload }), storage);
  const fresh = await online.fetchWeather(online.cities[0]);
  assert.equal(fresh.main.temp, 21);
  assert.equal(fresh.__weatherMeta.fromCache, false);

  const offlineAfterReload = loadWeather(async () => { throw new Error('network down'); }, createStorage(storage.snapshot()));
  const cached = await offlineAfterReload.fetchWeather(offlineAfterReload.cities[0]);
  assert.equal(cached.main.temp, 21);
  assert.equal(cached.__weatherMeta.fromCache, true);
  assert.equal(cached.__weatherMeta.error, 'network down');

  const emptyOffline = loadWeather(async () => ({ ok: false, status: 503 }), createStorage());
  await assert.rejects(() => emptyOffline.fetchWeather(emptyOffline.cities[0]), /503/);

  console.log('Cache fallback tests passed');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
