(function () {
  'use strict';

  const W = window.Weather;
  const grid = document.getElementById('weatherGrid');
  const template = document.getElementById('weatherCardTemplate');
  const error = document.getElementById('globalError');
  const cards = new Map();

  W.cities.forEach((city) => {
    const card = template.content.firstElementChild.cloneNode(true);
    card.href = `weather.html?city=${encodeURIComponent(city.slug)}`;
    card.setAttribute('aria-label', `Подробная погода: ${city.name}`);
    card.querySelector('.city').textContent = city.name;
    card.querySelector('.country').textContent = city.country;
    grid.append(card);
    cards.set(city.slug, card);
  });

  function cacheTime(savedAt) {
    return new Intl.DateTimeFormat('ru-RU', {
      day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'
    }).format(new Date(savedAt));
  }

  async function loadCity(city) {
    const card = cards.get(city.slug);
    const data = await W.fetchWeather(city);
    const meta = data.__weatherMeta;

    card.querySelector('.description').textContent = W.capitalize(data.weather?.[0]?.description);
    card.querySelector('.temperature-value').textContent = W.number(data.main?.temp);
    card.querySelector('.wind').textContent = W.number(data.wind?.speed);
    card.querySelector('.feels').textContent = W.number(data.main?.feels_like);
    card.querySelector('.weather-icon').textContent = W.symbol(data.weather?.[0]?.id);

    if (meta?.fromCache) {
      card.classList.add('offline');
      card.querySelector('.updated').textContent = `Данные от ${cacheTime(meta.savedAt)}`;
      return true;
    }

    card.classList.remove('offline');
    card.querySelector('.updated').textContent = new Intl.DateTimeFormat('ru-RU', {
      hour: '2-digit', minute: '2-digit'
    }).format(new Date());
    return false;
  }

  async function load() {
    error.classList.remove('visible');
    const results = await Promise.allSettled(W.cities.map(loadCity));
    const unavailable = results.filter((result) => result.status === 'rejected').length;
    const cached = results.filter((result) => result.status === 'fulfilled' && result.value).length;

    if (unavailable || cached) {
      const messages = [];
      if (cached) messages.push(`Для ${cached} город(а) показаны последние сохранённые данные.`);
      if (unavailable) messages.push(`Для ${unavailable} город(а) данных пока нет.`);
      messages.push('Следующая попытка через минуту.');
      error.textContent = messages.join(' ');
      error.classList.add('visible');
    }
  }

  load();
  setInterval(load, 60000);
})();
