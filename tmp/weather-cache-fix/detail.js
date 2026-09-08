(function () {
  'use strict';

  const W = window.Weather;
  const params = new URLSearchParams(location.search);
  const city = W.cities.find((item) => item.slug === params.get('city'));
  const error = document.getElementById('detailError');
  const content = document.getElementById('detailContent');
  const json = document.getElementById('jsonPanel');
  const button = document.getElementById('refreshButton');

  if (!city) {
    document.getElementById('detailCity').textContent = 'Город не найден';
    error.textContent = 'Откройте один из городов с главной страницы.';
    error.classList.add('visible');
    return;
  }

  document.title = `Погода в городе ${city.name}`;
  document.getElementById('detailCity').textContent = city.name;
  document.getElementById('detailCountry').textContent = city.country;
  document.getElementById('aboutTitle').textContent = `${city.name} — характер города`;
  document.getElementById('aboutText').textContent = city.about;
  document.getElementById('factList').innerHTML = city.facts.map((fact, index) => `<span><b>${String(index + 1).padStart(2, '0')}</b>${fact}</span>`).join('');

  const metric = (label, value, note = '') => `<article class="detail-metric"><span>${label}</span><strong>${value}</strong>${note ? `<small>${note}</small>` : ''}</article>`;

  function duration(seconds) {
    if (!Number.isFinite(seconds)) return '—';
    return `${Math.floor(seconds / 3600)} ч ${Math.round(seconds % 3600 / 60)} мин`;
  }

  function cacheTime(savedAt) {
    return new Intl.DateTimeFormat('ru-RU', {
      day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit'
    }).format(new Date(savedAt));
  }

  function render(data) {
    const timezone = data.timezone || 0;
    document.getElementById('detailDescription').textContent = W.capitalize(data.weather?.[0]?.description);
    document.getElementById('detailTemp').textContent = W.number(data.main?.temp);
    document.getElementById('observedAt').textContent = `Наблюдение: ${W.localDate(data.dt, timezone, { day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit' })}`;
    document.getElementById('metricGrid').innerHTML = [
      metric('Ощущается', `${W.number(data.main?.feels_like)} °C`, `минимум ${W.number(data.main?.temp_min)}° · максимум ${W.number(data.main?.temp_max)}°`),
      metric('Влажность', `${W.number(data.main?.humidity, 0)}%`, 'относительная влажность'),
      metric('Давление', `${W.number(data.main?.pressure, 0)} гПа`, `${W.number(data.main?.pressure * .750062, 0)} мм рт. ст.`),
      metric('Ветер', `${W.number(data.wind?.speed)} м/с`, `${W.windDirection(data.wind?.deg)}${Number.isFinite(data.wind?.gust) ? ` · порывы ${W.number(data.wind.gust)} м/с` : ''}`),
      metric('Видимость', `${W.number(data.visibility / 1000)} км`, 'горизонтальная'),
      metric('Облачность', `${W.number(data.clouds?.all, 0)}%`, W.capitalize(data.weather?.[0]?.description))
    ].join('');
    document.getElementById('sunrise').textContent = W.localDate(data.sys?.sunrise, timezone, { hour: '2-digit', minute: '2-digit' });
    document.getElementById('sunset').textContent = W.localDate(data.sys?.sunset, timezone, { hour: '2-digit', minute: '2-digit' });
    document.getElementById('dayLength').textContent = duration(data.sys?.sunset - data.sys?.sunrise);
    document.getElementById('coordinates').textContent = `${W.number(data.coord?.lat, 4)}°, ${W.number(data.coord?.lon, 4)}°`;
    document.getElementById('rawJson').textContent = JSON.stringify(data, null, 2);
    content.hidden = false;
    json.hidden = false;
  }

  async function load() {
    button.disabled = true;
    button.textContent = 'Обновляем…';
    error.classList.remove('visible');

    try {
      const data = await W.fetchWeather(city);
      render(data);
      if (data.__weatherMeta?.fromCache) {
        error.textContent = `Сервис погоды временно недоступен. Показаны последние данные, сохранённые ${cacheTime(data.__weatherMeta.savedAt)}.`;
        error.classList.add('visible');
      }
    } catch (loadError) {
      error.textContent = `Не удалось получить погоду: ${loadError.message}. Сохранённых данных для этого города пока нет.`;
      error.classList.add('visible');
    } finally {
      button.disabled = false;
      button.textContent = 'Обновить';
    }
  }

  button.addEventListener('click', load);
  load();
})();
