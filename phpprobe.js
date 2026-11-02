/*
 * Tech Detector Pro - individuazione della versione PHP
 * Autore: Umberto Meglio - Supporto alla creazione: Claude di Anthropic
 *
 * Quasi tutti i siti in produzione hanno expose_php=Off, oppure un proxy/CDN che
 * toglie X-Powered-By dalla pagina principale. Per questo la versione si cerca
 * in più modi, dal più affidabile al più indiretto:
 *
 *  1. header delle risposte che PHP genera direttamente (script .php inesistenti,
 *     endpoint noti del CMS, URL con cache-buster per saltare la cache del CDN)
 *  2. [approfondita] pagine phpinfo() dimenticate, composer.lock/installed.json esposti,
 *     README dei CMS, easter egg dei PHP < 5.5
 *  3. stima dal pacchetto della distribuzione Linux (Apache/nginx + Ubuntu/Debian)
 *  4. limite minimo imposto dalla versione del CMS/framework rilevato
 *
 * Ogni risultato riporta fonte e grado di affidabilità (certa / probabile / stima / minimo).
 */
'use strict';

const PHP_VER_RE = /PHP\/(\d+\.\d+(?:\.\d+)?)/i;

/* Versione di Apache/nginx pacchettizzata -> versione PHP di default della distribuzione */
const DISTRO_PHP = [
  { os: /ubuntu/i, server: 'Apache HTTP Server', ver: '2.4.29', php: '7.2', distro: 'Ubuntu 18.04' },
  { os: /ubuntu/i, server: 'Apache HTTP Server', ver: '2.4.41', php: '7.4', distro: 'Ubuntu 20.04' },
  { os: /ubuntu/i, server: 'Apache HTTP Server', ver: '2.4.52', php: '8.1', distro: 'Ubuntu 22.04' },
  { os: /ubuntu/i, server: 'Apache HTTP Server', ver: '2.4.58', php: '8.3', distro: 'Ubuntu 24.04' },
  { os: /ubuntu/i, server: 'Apache HTTP Server', ver: '2.4.64', php: '8.4', distro: 'Ubuntu 25.10' },
  { os: /ubuntu/i, server: 'nginx', ver: '1.14.0', php: '7.2', distro: 'Ubuntu 18.04' },
  { os: /ubuntu/i, server: 'nginx', ver: '1.24.0', php: '8.3', distro: 'Ubuntu 24.04' },
  { os: /debian/i, server: 'Apache HTTP Server', ver: '2.4.25', php: '7.0', distro: 'Debian 9' },
  { os: /debian/i, server: 'Apache HTTP Server', ver: '2.4.38', php: '7.3', distro: 'Debian 10' },
  { os: /debian/i, server: 'nginx', ver: '1.14.2', php: '7.3', distro: 'Debian 10' },
  { os: /debian/i, server: 'nginx', ver: '1.22.1', php: '8.2', distro: 'Debian 12' },
  { os: /debian/i, server: 'nginx', ver: '1.26.3', php: '8.4', distro: 'Debian 13' },
  { os: /centos|red hat|rhel|alma|rocky/i, server: 'Apache HTTP Server', ver: '2.4.6', php: '5.4', distro: 'CentOS/RHEL 7' },
  { os: /centos|red hat|rhel|alma|rocky/i, server: 'Apache HTTP Server', ver: '2.4.37', php: '7.2–8.2 (AppStream)', distro: 'RHEL 8' },
  { os: /centos|red hat|rhel|alma|rocky/i, server: 'Apache HTTP Server', ver: '2.4.57', php: '8.0–8.3 (AppStream)', distro: 'RHEL 9' }
];

/* Versione minima di PHP richiesta da CMS/framework */
const MIN_PHP = [
  { tech: 'Laravel', rules: [['12', '8.2'], ['11', '8.2'], ['10', '8.1'], ['9', '8.0'], ['8', '7.3']] },
  { tech: 'Symfony', rules: [['7', '8.2'], ['6.4', '8.1'], ['6', '8.0'], ['5', '7.2']] },
  { tech: 'Drupal', rules: [['11', '8.3'], ['10', '8.1'], ['9', '7.3'], ['8', '7.0']] },
  { tech: 'Joomla', rules: [['6', '8.3'], ['5', '8.1'], ['4', '7.2.5']] },
  { tech: 'Magento', rules: [['2.4.8', '8.3'], ['2.4.7', '8.2'], ['2.4.4', '7.4']] },
  { tech: 'PrestaShop', rules: [['9', '8.1'], ['8', '7.2.5']] },
  { tech: 'Typo3', rules: [['13', '8.2'], ['12', '8.1']] },
  { tech: 'WordPress', rules: [['6.6', '7.2.24'], ['6.0', '5.6.20']] }
];

/* Tecnologie che indicano un backend diverso da PHP */
const NON_PHP_BACKENDS = [
  // backend: nome del backend; static: sito statico generato con...; note: chiave di traduzione del motivo
  { tech: 'Next.js', backend: 'Node.js (Next.js)', note: 'bn.node' },
  { tech: 'Nuxt', backend: 'Node.js (Nuxt)', note: 'bn.node' },
  { tech: 'Nuxt.js', backend: 'Node.js (Nuxt)', note: 'bn.node' },
  { tech: 'Gatsby', static: 'Gatsby', note: 'bn.static' },
  { tech: 'Express', backend: 'Node.js (Express)', note: 'bn.express' },
  { tech: 'ASP.NET', backend: 'ASP.NET (.NET)', note: 'bn.aspnet' },
  { tech: 'Java Servlet', backend: 'Java', note: 'bn.jsession' },
  { tech: 'Apache Tomcat', backend: 'Java (Tomcat)', note: 'bn.banner' },
  { tech: 'Django', backend: 'Python (Django)', note: 'bn.django' },
  { tech: 'Ruby on Rails', backend: 'Ruby (Rails)', note: 'bn.rails' },
  { tech: 'Ruby on Rails / Rack', backend: 'Ruby (Rack)', note: 'bn.rack' },
  { tech: 'Hugo', static: 'Hugo', note: 'bn.static' },
  { tech: 'Jekyll', static: 'Jekyll', note: 'bn.static' },
  { tech: 'GitHub Pages', static: 'GitHub Pages', note: 'bn.hosting' }
];

const sameOrigin = (u) => new URL(u).origin;
const rnd = () => Math.random().toString(36).slice(2, 10);

async function probe(url, opts = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeout || 6000);
  try {
    const r = await fetch(url, { method: opts.method || 'GET', credentials: 'omit', cache: 'no-store', redirect: 'manual', signal: ctrl.signal });
    const headers = {};
    r.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    let body = '';
    if (opts.body && r.status === 200) {
      const reader = r.body.getReader();
      let size = 0;
      const dec = new TextDecoder();
      // legge al massimo 256 KB
      while (size < 262144) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        body += dec.decode(value, { stream: true });
      }
      try { reader.cancel(); } catch (e) { /* ignora */ }
    } else {
      try { r.body && r.body.cancel(); } catch (e) { /* ignora */ }
    }
    return { url, status: r.status, headers, body, type: r.headers.get('content-type') || '' };
  } catch (e) {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function versionFromHeaders(h) {
  for (const k of ['x-powered-by', 'server', 'x-php-version', 'x-generator']) {
    const v = h && h[k];
    if (!v) continue;
    if (k === 'x-php-version' && /^\d+\.\d+/.test(v)) return { version: v.trim(), header: k };
    const m = v.match(PHP_VER_RE);
    if (m) return { version: m[1], header: k };
  }
  return null;
}

/**
 * Cerca la versione PHP.
 * @param {object} ctx { url, techs, capture, deep }
 * @returns {Promise<{version, confidence, source, evidence:string[], isPhp:boolean}>}
 */
async function detectPhpVersion(ctx) {
  const origin = sameOrigin(ctx.url);
  const evidence = [];
  const has = (n) => ctx.techs.find((t) => t.name.toLowerCase() === n.toLowerCase());
  const cms = ['WordPress', 'Drupal', 'Joomla', 'Magento', 'PrestaShop', 'Laravel', 'Symfony', 'Typo3', 'CodeIgniter', 'phpBB', 'MediaWiki', 'Moodle', 'Nextcloud'].filter(has);
  let isPhp = !!has('PHP') || cms.length > 0 || /\.php(\?|$)/i.test(ctx.url);

  // backend chiaramente non PHP: inutile (e fuorviante) cercare una versione
  if (!isPhp) {
    const other = NON_PHP_BACKENDS.find((b) => has(b.tech));
    if (other) {
      evidence.push(t('ev.notPhp', other.tech, t(other.note)));
      return { version: null, confidence: null, source: null, evidence, isPhp: false, notPhp: other.static ? t('b.static', other.static) : other.backend };
    }
  }
  const found = (version, confidence, source) => ({ version, confidence, source, evidence, isPhp: true });

  // 0. già presente negli header della pagina?
  const direct = versionFromHeaders(headerMap((ctx.capture && ctx.capture.headers) || []));
  if (direct) return found(direct.version, 'certa', t('psrc.pageHeader', direct.header));

  // 1. risposte generate da PHP
  const light = [
    `${ctx.url}${ctx.url.includes('?') ? '&' : '?'}_tdp=${rnd()}`, // salta la cache del CDN
    `${origin}/index.php`,
    `${origin}/${rnd()}.php`                                       // nginx+php-fpm: "File not found." generato da PHP
  ];
  if (has('WordPress')) light.push(`${origin}/wp-login.php`, `${origin}/xmlrpc.php`, `${origin}/wp-cron.php`, `${origin}/wp-json/`);
  if (has('Drupal')) light.push(`${origin}/user/login`, `${origin}/core/install.php`);
  if (has('Joomla')) light.push(`${origin}/administrator/index.php`);
  if (has('Magento')) light.push(`${origin}/customer/account/login/`);
  if (has('PrestaShop')) light.push(`${origin}/index.php?controller=authentication`);

  // richiesta di controllo: un percorso inesistente SENZA .php. Se risponde 200 il sito ha un
  // "catch-all" (SPA, router applicativo) e lo stato delle risposte .php non prova nulla.
  const [control, ...results] = await Promise.all([probe(`${origin}/${rnd()}-${rnd()}`), ...light.map((u) => probe(u))]);
  const catchAll = !!control && control.status === 200;
  if (catchAll) evidence.push(t('ev.catchAll'));
  for (const r of results) {
    if (!r) continue;
    const v = versionFromHeaders(r.headers);
    if (v) { evidence.push(`${r.url} → ${r.headers[v.header]}`); return found(v.version, 'certa', t('psrc.headerOf', v.header, new URL(r.url).pathname)); }
    if (/PHPSESSID|laravel_session|ci_session/.test(r.headers['set-cookie'] || '') || /^PHP\b/i.test(r.headers['x-powered-by'] || '')) isPhp = true;
    if (!catchAll && r.status === 200 && /\/index\.php$/.test(r.url) && /text\/html/.test(r.type)) isPhp = true;
  }
  evidence.push(t('ev.noXPB'));

  // 2. ricerca approfondita
  if (ctx.deep) {
    const deep = await deepSearch(origin, has, evidence);
    if (deep) return found(deep.version, deep.confidence, deep.source);
  }

  // 3. stima dalla distribuzione
  const est = estimateFromDistro(ctx.capture);
  if (est && isPhp) {
    evidence.push(t('ev.distro', est.server, est.ver, est.distro, est.php));
    return found(est.php, 'stima', t('psrc.distro', est.distro));
  }

  // 4. minimo richiesto dal CMS
  const min = minimumFromCms(ctx.techs);
  if (min) {
    evidence.push(t('ev.min', min.tech, min.techVersion, min.php));
    return found('≥ ' + min.php, 'minimo', t('psrc.min', min.tech, min.techVersion));
  }

  return { version: null, confidence: null, source: null, evidence, isPhp };
}

async function deepSearch(origin, has, evidence) {
  // pagine phpinfo() dimenticate
  const infoPaths = ['phpinfo.php', 'info.php', 'php_info.php', 'test.php', 'i.php', 'pi.php', 'php.php', 'infophp.php', 'phpversion.php', 'version.php', 'status.php'];
  const infos = await Promise.all(infoPaths.map((p) => probe(`${origin}/${p}`, { body: true })));
  for (const r of infos) {
    if (!r || r.status !== 200) continue;
    const m = r.body.match(/<h1 class="p">PHP Version ([\d.]+)/i) || r.body.match(/PHP Version\s*<\/td><td class="v">\s*([\d.]+)/i) ||
      r.body.match(/\bPHP Version:?\s*([\d.]+\d)/i);
    if (m) {
      evidence.push(t('ev.phpinfo', r.url));
      return { version: m[1], confidence: 'certa', source: t('psrc.phpinfo', new URL(r.url).pathname) };
    }
    const v = versionFromHeaders(r.headers);
    if (v) return { version: v.version, confidence: 'certa', source: t('psrc.headerOf', v.header, new URL(r.url).pathname) };
  }

  // file di Composer esposti
  const comp = await Promise.all(['composer.lock', 'composer.json', 'vendor/composer/installed.json', 'vendor/composer/platform_check.php']
    .map((p) => probe(`${origin}/${p}`, { body: true })));
  for (const r of comp) {
    if (!r || r.status !== 200 || /text\/html/.test(r.type)) continue;
    const name = new URL(r.url).pathname;
    let m = r.body.match(/PHP_VERSION_ID\s*>=\s*(\d)(\d{2})(\d{2})/);
    if (m) {
      evidence.push(t('ev.exposed', name));
      return { version: `≥ ${m[1]}.${+m[2]}.${+m[3]}`, confidence: 'minimo', source: t('psrc.composerCheck', name) };
    }
    m = r.body.match(/"platform-overrides"\s*:\s*\{[^}]*"php"\s*:\s*"([\d.]+)"/) || r.body.match(/"platform"\s*:\s*\{[^}]*"php"\s*:\s*"([\d.]+)"/);
    if (m) { evidence.push(t('ev.exposed', name)); return { version: m[1], confidence: 'probabile', source: t('psrc.composerPlatform', name) }; }
    m = r.body.match(/"require"\s*:\s*\{[^}]*"php"\s*:\s*"([^"]+)"/);
    if (m) { evidence.push(t('ev.exposed', name)); return { version: m[1], confidence: 'minimo', source: t('psrc.composerReq', name) }; }
  }

  // easter egg (solo PHP < 5.5): risponde con un'immagine
  const egg = await probe(`${origin}/?=PHPE9568F34-D428-11d2-A769-00AA001ACF42`);
  if (egg && egg.status === 200 && /^image\//.test(egg.type)) {
    evidence.push(t('ev.egg'));
    return { version: '< 5.5', confidence: 'probabile', source: t('psrc.egg') };
  }

  // README del CMS per avere almeno il requisito minimo
  if (has('WordPress')) {
    const r = await probe(`${origin}/readme.html`, { body: true });
    const m = r && r.status === 200 && r.body.match(/PHP<\/a>\s*version\s*<strong>([\d.]+)<\/strong>/i);
    if (m) evidence.push(t('ev.wpReadme', m[1]));
  }
  evidence.push(t('ev.noDeep'));
  return null;
}

function estimateFromDistro(capture) {
  if (!capture) return null;
  const h = headerMap(capture.headers || []);
  const products = parseProducts(h['server'] || '');
  if (!products.os) return null;
  for (const p of products) {
    const name = canonical(p.name);
    const hit = DISTRO_PHP.find((d) => d.server === name && d.os.test(products.os) && p.version === d.ver);
    if (hit) return hit;
  }
  return null;
}

function minimumFromCms(techs) {
  for (const entry of MIN_PHP) {
    const t = techs.find((x) => x.name.toLowerCase() === entry.tech.toLowerCase() && x.version && /^\d/.test(x.version));
    if (!t) continue;
    const rule = entry.rules.find(([v]) => cmpVersion(t.version, v) >= 0);
    if (rule) return { tech: entry.tech, techVersion: t.version, php: rule[1] };
  }
  return null;
}

if (typeof module !== 'undefined') module.exports = { detectPhpVersion, estimateFromDistro, minimumFromCms, versionFromHeaders };
