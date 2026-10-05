(() => {
  const STORAGE_KEY = 'belyjspisok.analyticsConsent';
  const METRIKA_ID = 110893097;

  function readConsent() {
    try {
      return window.localStorage.getItem(STORAGE_KEY);
    } catch (error) {
      return null;
    }
  }

  function saveConsent(value) {
    try {
      window.localStorage.setItem(STORAGE_KEY, value);
    } catch (error) {
      // Если localStorage недоступен, согласие действует только до перезагрузки.
    }
  }

  function loadMetrika() {
    if (window.__belyjspisokMetrikaLoaded) return;
    window.__belyjspisokMetrikaLoaded = true;

    window.ym = window.ym || function () {
      (window.ym.a = window.ym.a || []).push(arguments);
    };
    window.ym.l = 1 * new Date();

    const script = document.createElement('script');
    script.async = true;
    script.src = `https://mc.yandex.ru/metrika/tag.js?id=${METRIKA_ID}`;
    document.head.appendChild(script);

    window.ym(METRIKA_ID, 'init', {
      ssr: true,
      webvisor: true,
      clickmap: true,
      ecommerce: 'dataLayer',
      referrer: document.referrer,
      url: location.href,
      accurateTrackBounce: true,
      trackLinks: true
    });

    sendTheme();
    watchTheme();
  }

  /* Тема оформления посетителя. Переключателя на сайте нет — сайт следует
     системной настройке, поэтому читаем prefers-color-scheme. Значение
     уходит параметром визита, а смену темы в течение визита отслеживаем. */
  function currentTheme() {
    try {
      return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    } catch (error) {
      return 'unknown';
    }
  }

  function sendTheme() {
    if (typeof window.ym !== 'function') return;
    window.ym(METRIKA_ID, 'params', { theme: currentTheme() });
  }

  function watchTheme() {
    try {
      const query = window.matchMedia('(prefers-color-scheme: dark)');
      const handler = () => sendTheme();
      if (typeof query.addEventListener === 'function') {
        query.addEventListener('change', handler);
      } else if (typeof query.addListener === 'function') {
        query.addListener(handler);
      }
    } catch (error) {
      // Старые браузеры без matchMedia — просто не отслеживаем смену.
    }
  }

  function removeBanner() {
    document.getElementById('analytics-consent')?.remove();
  }

  function showBanner() {
    if (document.getElementById('analytics-consent')) return;

    const banner = document.createElement('section');
    banner.id = 'analytics-consent';
    banner.className = 'consent-banner';
    banner.setAttribute('role', 'region');
    banner.setAttribute('aria-label', 'Согласие на веб-аналитику');

    banner.innerHTML = `
      <div class="consent-banner__inner">
        <p>
          Мы используем cookie и Яндекс Метрику для анализа работы сайта.
          Аналитика включится только после вашего согласия.
        </p>
        <div class="consent-banner__actions">
          <a class="consent-banner__details" href="/privacy/">Подробнее</a>
          <button class="consent-banner__accept" type="button">Принять</button>
        </div>
      </div>
    `;

    banner.querySelector('.consent-banner__accept').addEventListener('click', () => {
      saveConsent('accepted');
      removeBanner();
      loadMetrika();
    });

    document.body.appendChild(banner);
  }

  function initConsent() {
    if (readConsent() === 'accepted') {
      loadMetrika();
    } else {
      showBanner();
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initConsent, { once: true });
  } else {
    initConsent();
  }
})();
