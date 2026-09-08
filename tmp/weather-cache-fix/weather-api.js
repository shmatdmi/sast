(function () {
  'use strict';

  const TOKEN = 'ba23e3e7888484e7a26b57b215d65200';
  const CACHE_PREFIX = 'moscow-weather:last-success:v1:';
  const memoryCache = new Map();

  const cities = [
    { slug: 'moscow', name: 'Москва', query: 'Moscow,RU', country: 'Россия', about: 'Столица России и крупнейший культурный, деловой и транспортный центр страны. Москва сочетает древние кварталы, монументальную архитектуру и быстрый ритм современного мегаполиса.', facts: ['Москва-река', 'Красная площадь', 'Крупный транспортный узел'] },
    { slug: 'tula', name: 'Тула', query: 'Tula,RU', country: 'Россия', about: 'Старинный город к югу от Москвы, известный ремесленными традициями, оружейным производством, пряниками и самоварами. Историческое сердце города — каменный Тульский кремль.', facts: ['Тульский кремль', 'Пряники и самовары', 'Город мастеров'] },
    { slug: 'sochi', name: 'Сочи', query: 'Sochi,RU', country: 'Россия', about: 'Черноморский курорт у подножия Кавказских гор. В пределах одного города здесь соседствуют морское побережье, субтропическая растительность и горнолыжные склоны.', facts: ['Чёрное море', 'Кавказские горы', 'Субтропический климат'] },
    { slug: 'minsk', name: 'Минск', query: 'Minsk,BY', country: 'Беларусь', about: 'Столица Беларуси, расположенная на реке Свислочь. Город узнаваем по широким проспектам, большим зелёным пространствам и цельному ансамблю послевоенной архитектуры.', facts: ['Река Свислочь', 'Широкие проспекты', 'Зелёный город'] },
    { slug: 'london', name: 'Лондон', query: 'London,GB', country: 'Великобритания', about: 'Столица Великобритании и один из главных мировых культурных и финансовых центров. Многослойная история Лондона читается от Тауэра и Вестминстера до современных кварталов на Темзе.', facts: ['Река Темза', 'Вестминстер', 'Мировой культурный центр'] },
    { slug: 'madrid', name: 'Мадрид', query: 'Madrid,ES', country: 'Испания', about: 'Столица Испании в самом сердце Пиренейского полуострова. Мадрид славится художественными музеями, оживлёнными площадями, просторными парками и поздним ритмом городской жизни.', facts: ['Музей Прадо', 'Парк Ретиро', 'Сердце Испании'] }
  ];

  function cacheKey(city) {
    return `${CACHE_PREFIX}${city.slug}`;
  }

  function readCached(city) {
    const key = cacheKey(city);
    if (memoryCache.has(key)) return memoryCache.get(key);

    try {
      const cached = JSON.parse(localStorage.getItem(key));
      if (cached && Number.isFinite(cached.savedAt) && cached.data && typeof cached.data === 'object') {
        memoryCache.set(key, cached);
        return cached;
      }
    } catch (_) {
      // localStorage may be unavailable or contain a damaged entry.
    }

    return null;
  }

  function writeCached(city, data) {
    const cached = { savedAt: Date.now(), data };
    const key = cacheKey(city);
    memoryCache.set(key, cached);

    try {
      localStorage.setItem(key, JSON.stringify(cached));
    } catch (_) {
      // The in-memory copy still protects refresh attempts in this tab.
    }

    return cached;
  }

  function withMeta(data, fromCache, savedAt, error) {
    Object.defineProperty(data, '__weatherMeta', {
      configurable: true,
      enumerable: false,
      value: { fromCache, savedAt, error: error || '' }
    });
    return data;
  }

  async function fetchWeather(city) {
    const url = `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(city.query)}&appid=${TOKEN}&units=metric&lang=ru`;

    try {
      const response = await fetch(url, { cache: 'no-store' });
      if (!response.ok) throw new Error(`сервис ответил с кодом ${response.status}`);

      const data = await response.json();
      const cached = writeCached(city, data);
      return withMeta(data, false, cached.savedAt);
    } catch (error) {
      const cached = readCached(city);
      if (cached) return withMeta(cached.data, true, cached.savedAt, error.message);
      throw error;
    }
  }

  function number(value, digits = 1) {
    return Number.isFinite(value) ? new Intl.NumberFormat('ru-RU', { maximumFractionDigits: digits }).format(value) : '—';
  }

  function capitalize(value) {
    return value ? value[0].toUpperCase() + value.slice(1) : 'Нет описания';
  }

  function localDate(unix, timezone, options) {
    return Number.isFinite(unix) ? new Intl.DateTimeFormat('ru-RU', { timeZone: 'UTC', ...options }).format(new Date((unix + timezone) * 1000)) : '—';
  }

  function windDirection(degrees) {
    if (!Number.isFinite(degrees)) return '—';
    const directions = ['С', 'СВ', 'В', 'ЮВ', 'Ю', 'ЮЗ', 'З', 'СЗ'];
    return `${directions[Math.round(degrees / 45) % 8]} · ${degrees}°`;
  }

  function symbol(id) {
    if (id >= 200 && id < 300) return 'ϟ';
    if (id >= 300 && id < 600) return '☂';
    if (id >= 600 && id < 700) return '❄';
    if (id === 800) return '☀';
    if (id > 800) return '☁';
    return '≈';
  }

  window.Weather = { cities, fetchWeather, number, capitalize, localDate, windDirection, symbol };
})();
