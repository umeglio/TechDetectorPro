/*
 * Tech Detector Pro - analisi header HTTP, audit di sicurezza e controllo versioni/CVE
 * Autore: Umberto Meglio - Supporto alla creazione: Claude di Anthropic
 *
 * Tutto il codice gira nel popup: nessun dato viene inviato a servizi esterni.
 */
'use strict';

/* ---------- utilità versioni ---------- */
function cmpVersion(a, b) {
  const pa = String(a).split(/[.\-+]/).map((x) => parseInt(x, 10) || 0);
  const pb = String(b).split(/[.\-+]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}
const lt = (a, b) => cmpVersion(a, b) < 0;
const branch = (v, n = 2) => String(v).split('.').slice(0, n).join('.');

/* ---------- parsing header ---------- */
function headerMap(list) {
  const m = {};
  (list || []).forEach((h) => {
    const k = h.name.toLowerCase();
    m[k] = m[k] ? m[k] + '\n' + h.value : h.value;
  });
  return m;
}

/**
 * Estrae i prodotti dal valore di Server / X-Powered-By, es.
 * "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f PHP/7.4.3" -> [{name:'Apache',version:'2.4.41'},...]
 */
function parseProducts(value) {
  const out = [];
  if (!value) return out;
  const re = /([A-Za-z][\w.\-]*?)\/(\d[\w.\-]*)/g;
  let m;
  while ((m = re.exec(value))) out.push({ name: m[1], version: m[2].replace(/[^\d.].*$/, '') });
  if (!out.length) out.push({ name: value.split(/[\s(;,]/)[0], version: null });
  const os = value.match(/\((Ubuntu|Debian|CentOS|Red Hat|Red Hat Enterprise Linux|RHEL|Fedora|AlmaLinux|Rocky|Amazon|Unix|Win32|Win64|FreeBSD)[^)]*\)/i);
  if (os) out.os = os[1];
  return out;
}

const PRODUCT_ALIASES = {
  apache: 'Apache HTTP Server', httpd: 'Apache HTTP Server', nginx: 'nginx', openresty: 'OpenResty',
  'microsoft-iis': 'Microsoft IIS', litespeed: 'LiteSpeed', openlitespeed: 'OpenLiteSpeed',
  caddy: 'Caddy', 'apache-coyote': 'Apache Tomcat', tomcat: 'Apache Tomcat', jetty: 'Jetty',
  gunicorn: 'Gunicorn', uvicorn: 'Uvicorn', werkzeug: 'Werkzeug', kestrel: 'Kestrel',
  cloudflare: 'Cloudflare', 'akamaighost': 'Akamai', gws: 'Google Web Server', envoy: 'Envoy',
  php: 'PHP', openssl: 'OpenSSL', 'mod_ssl': 'mod_ssl', 'mod_perl': 'mod_perl', perl: 'Perl',
  python: 'Python', 'mod_wsgi': 'mod_wsgi', 'mod_fcgid': 'mod_fcgid', phusion_passenger: 'Phusion Passenger',
  'asp.net': 'ASP.NET', express: 'Express', 'next.js': 'Next.js', servlet: 'Java Servlet', jsp: 'JSP',
  plesklin: 'Plesk', pleskwin: 'Plesk', 'w3 total cache': 'W3 Total Cache', 'wp engine': 'WP Engine',
  'amazons3': 'Amazon S3', 'awselb': 'AWS ELB', 'varnish': 'Varnish', 'squid': 'Squid', 'tengine': 'Tengine'
};
const canonical = (n) => PRODUCT_ALIASES[String(n).toLowerCase()] || n;

const CATEGORY_OF = {
  'Apache HTTP Server': 'Web Server', nginx: 'Web Server', OpenResty: 'Web Server', 'Microsoft IIS': 'Web Server',
  LiteSpeed: 'Web Server', OpenLiteSpeed: 'Web Server', Caddy: 'Web Server', 'Apache Tomcat': 'Web Server',
  Jetty: 'Web Server', Gunicorn: 'Web Server', Uvicorn: 'Web Server', Werkzeug: 'Web Server', Kestrel: 'Web Server',
  'Google Web Server': 'Web Server', Envoy: 'Proxy', Tengine: 'Web Server', Varnish: 'Cache Tool', Squid: 'Proxy',
  PHP: 'Linguaggio di programmazione', Perl: 'Linguaggio di programmazione', Python: 'Linguaggio di programmazione',
  'ASP.NET': 'Framework Backend', Express: 'Framework Backend', 'Next.js': 'JavaScript Framework',
  OpenSSL: 'Libreria TLS', 'mod_ssl': 'Modulo Apache', 'mod_perl': 'Modulo Apache', 'mod_wsgi': 'Modulo Apache',
  'mod_fcgid': 'Modulo Apache', Cloudflare: 'CDN', Akamai: 'CDN', 'Amazon S3': 'PaaS', 'AWS ELB': 'Proxy',
  Plesk: 'Pannello di hosting', 'Phusion Passenger': 'Application Server'
};

/**
 * Analizza gli header e restituisce:
 *  - server: righe chiave/valore per la scheda "Server"
 *  - techs: tecnologie con versione (unite poi a quelle del DOM)
 *  - security: audit degli header di sicurezza
 */
function analyzeHeaders(capture, page) {
  const h = headerMap(capture && capture.headers);
  const server = [];
  const techs = [];
  const add = (name, version, source) => {
    name = canonical(name);
    if (!name) return;
    const ex = techs.find((t) => t.name === name);
    if (ex) { if (!ex.version && version) ex.version = version; return; }
    techs.push({ name, version: version || null, type: source, category: CATEGORY_OF[name] || 'Server', fromHeaders: true });
  };

  const row = (label, value, hint) => { if (value !== null && value !== undefined && value !== '') server.push({ label, value: String(value), hint }); };

  if (capture) {
    row('URL finale', capture.url);
    row('Indirizzo IP', capture.ip);
    row('Stato HTTP', capture.statusLine || capture.statusCode);
  }
  if (page) {
    const proto = { 'h3': 'HTTP/3 (QUIC)', 'h2': 'HTTP/2', 'http/1.1': 'HTTP/1.1', 'http/1.0': 'HTTP/1.0' }[page.protocol] || page.protocol;
    row('Protocollo', proto);
    row('Cifratura', /^https:/.test(page.url) ? 'HTTPS' : 'nessuna (HTTP in chiaro)');
  }

  // Server / X-Powered-By & co.
  const serverProducts = parseProducts(h['server']);
  if (h['server']) row('Server', h['server']);
  if (serverProducts.os) row('Sistema operativo (da banner)', serverProducts.os);
  serverProducts.forEach((p) => add(p.name, p.version, 'header Server'));

  // distribuzione dedotta dalla versione del pacchetto Apache/nginx
  if (serverProducts.os) {
    const d = guessDistro(serverProducts);
    if (d) {
      row('Distribuzione stimata', `${d.name} ${d.version}`, d.note);
      techs.push({ name: d.name, version: d.version, type: 'dedotto dal banner ' + d.from, category: 'Sistema operativo', fromHeaders: true });
    }
  }
  if (page && /Apache2 (Ubuntu|Debian) Default Page|Welcome to nginx!|IIS Windows Server|Test Page for the (Apache|Nginx) HTTP Server/i.test(page.title || '')) {
    row('Pagina di default', page.title, 'il server mostra la pagina predefinita del pacchetto: host probabilmente dimenticato');
  }

  if (h['x-powered-by']) {
    row('X-Powered-By', h['x-powered-by']);
    h['x-powered-by'].split(/[\n,]/).forEach((part) => parseProducts(part.trim()).forEach((p) => add(p.name, p.version, 'header X-Powered-By')));
  }
  if (h['x-aspnet-version']) { row('X-AspNet-Version', h['x-aspnet-version']); add('ASP.NET', h['x-aspnet-version'], 'header X-AspNet-Version'); }
  if (h['x-aspnetmvc-version']) { row('ASP.NET MVC', h['x-aspnetmvc-version']); add('ASP.NET MVC', h['x-aspnetmvc-version'], 'header'); }
  if (h['x-generator']) { row('X-Generator', h['x-generator']); parseProducts(h['x-generator']).forEach((p) => add(p.name, p.version, 'header X-Generator')); }
  if (h['x-drupal-cache'] || h['x-drupal-dynamic-cache']) add('Drupal', null, 'header X-Drupal-Cache');
  if (h['x-pingback'] || /wp-json/.test(h['link'] || '')) add('WordPress', null, 'header Link/X-Pingback');
  if (h['x-shopify-stage'] || h['x-shopid']) add('Shopify', null, 'header');
  if (h['x-magento-cache-debug'] || h['x-magento-tags']) add('Magento', null, 'header');
  if (h['x-litespeed-cache']) add('LiteSpeed Cache', null, 'header');
  if (h['x-varnish']) add('Varnish', null, 'header X-Varnish');
  if (h['x-turbo-charged-by']) add(h['x-turbo-charged-by'], null, 'header');
  if (h['x-runtime']) add('Ruby on Rails / Rack', null, 'header X-Runtime');
  if (h['x-nextjs-cache'] || h['x-nextjs-prerender'] || h['x-nextjs-stale-time']) add('Next.js', null, 'header');
  if (h['x-vercel-id'] || h['x-vercel-cache']) add('Vercel', null, 'header');
  if (h['x-nf-request-id']) add('Netlify', null, 'header');
  if (h['x-github-request-id']) add('GitHub Pages', null, 'header');
  if (h['x-amz-cf-id'] || /cloudfront/i.test(h['via'] || '')) add('Amazon CloudFront', null, 'header');
  if (h['cf-ray']) add('Cloudflare', null, 'header CF-Ray');
  if (h['x-served-by'] && /cache-/.test(h['x-served-by'])) add('Fastly', null, 'header X-Served-By');
  if (h['x-azure-ref']) add('Azure Front Door', null, 'header');
  if (h['x-goog-generation'] || h['x-guploader-uploadid']) add('Google Cloud Storage', null, 'header');
  if (h['x-envoy-upstream-service-time']) add('Envoy', null, 'header');
  if (h['x-kong-proxy-latency'] || h['via'] && /kong/i.test(h['via'])) add('Kong', null, 'header');
  if (h['x-sucuri-id']) add('Sucuri WAF', null, 'header');
  if (h['x-iinfo'] || h['x-cdn'] === 'Imperva') add('Imperva', null, 'header');

  const cats = { 'Cloudflare': 'CDN', 'Amazon CloudFront': 'CDN', 'Fastly': 'CDN', 'Azure Front Door': 'CDN', 'Vercel': 'PaaS',
    'Netlify': 'PaaS', 'GitHub Pages': 'PaaS', 'Google Cloud Storage': 'PaaS', 'Kong': 'Proxy', 'Sucuri WAF': 'Security',
    'Imperva': 'Security', 'Drupal': 'CMS', 'WordPress': 'CMS', 'Shopify': 'E-commerce', 'Magento': 'E-commerce',
    'LiteSpeed Cache': 'Cache Tool', 'Ruby on Rails / Rack': 'Framework Backend', 'ASP.NET MVC': 'Framework Backend' };
  techs.forEach((t) => { if (cats[t.name]) t.category = cats[t.name]; });

  if (h['via']) row('Via (proxy)', h['via']);
  if (h['content-type']) row('Content-Type', h['content-type']);
  if (h['content-encoding']) row('Compressione', h['content-encoding']);
  if (h['cache-control']) row('Cache-Control', h['cache-control']);
  if (h['age']) row('Age (cache)', h['age'] + ' s');
  ['x-cache', 'cf-cache-status', 'x-cache-status', 'x-proxy-cache', 'x-vercel-cache', 'x-litespeed-cache'].forEach((k) => {
    if (h[k]) row('Cache: ' + k, h[k]);
  });
  if (h['alt-svc']) row('Alt-Svc', h['alt-svc'], /h3/.test(h['alt-svc']) ? 'HTTP/3 annunciato' : '');
  if (h['last-modified']) row('Last-Modified', h['last-modified']);
  if (h['etag']) row('ETag', h['etag']);
  if (page) {
    if (page.ttfb !== null) row('TTFB', page.ttfb + ' ms');
    if (page.loadTime) row('Caricamento pagina', page.loadTime + ' ms');
    if (page.transferSize) row('Dimensione trasferita', (page.transferSize / 1024).toFixed(1) + ' KB');
    row('Nodi DOM', page.domNodes);
    row('Charset', page.charset);
    row('Doctype / modalità', page.doctype + ' / ' + page.renderMode);
    row('Lingua', page.lang);
    row('Meta generator', page.generator);
    row('Script (esterni / cross-origin)', `${page.scripts} (${page.externalScripts} / ${page.crossOriginScripts})`);
    row('Service Worker attivo', page.serviceWorker ? 'sì' : 'no');
  }

  // cookie di sessione rivelatori del backend
  const setCookie = h['set-cookie'] || '';
  const cookieNames = new Set((page && page.cookieNames) || []);
  setCookie.split('\n').forEach((c) => { const n = c.split('=')[0].trim(); if (n) cookieNames.add(n); });
  const COOKIE_TECH = { PHPSESSID: 'PHP', JSESSIONID: 'Java Servlet', 'ASP.NET_SessionId': 'ASP.NET', ASPSESSIONID: 'ASP classico',
    laravel_session: 'Laravel', ci_session: 'CodeIgniter', 'XSRF-TOKEN': null, csrftoken: 'Django', sessionid: null,
    _rails_session: 'Ruby on Rails', 'connect.sid': 'Express', CFID: 'ColdFusion', CFTOKEN: 'ColdFusion', __cf_bm: 'Cloudflare Bot Management',
    'wordpress_test_cookie': 'WordPress', 'PrestaShop': 'PrestaShop', 'frontend': null, 'Drupal.visitor': 'Drupal', '_shopify_y': 'Shopify' };
  cookieNames.forEach((n) => {
    const key = Object.keys(COOKIE_TECH).find((k) => n === k || n.startsWith(k));
    if (key && COOKIE_TECH[key]) add(COOKIE_TECH[key], null, 'cookie ' + n);
  });
  if (cookieNames.size) {
    const names = Array.from(cookieNames);
    const short = names.slice(0, 12).map((n) => (n.length > 28 ? n.slice(0, 26) + '…' : n));
    row('Cookie rilevati', `${names.length}: ${short.join(', ')}${names.length > 12 ? ` (+${names.length - 12})` : ''}`);
  }

  return { server, techs, security: auditSecurity(h, capture, page, setCookie), headers: capture ? capture.headers : [] };
}

/* Versione del pacchetto -> release della distribuzione */
const DISTRO_BY_PACKAGE = {
  Ubuntu: { 'Apache HTTP Server': { '2.4.7': '14.04', '2.4.12': '15.04', '2.4.18': '16.04', '2.4.29': '18.04', '2.4.41': '20.04', '2.4.52': '22.04', '2.4.58': '24.04' },
    nginx: { '1.4.6': '14.04', '1.10.3': '16.04', '1.14.0': '18.04', '1.24.0': '24.04' } },
  Debian: { 'Apache HTTP Server': { '2.4.10': '8', '2.4.25': '9', '2.4.38': '10' },
    nginx: { '1.6.2': '8', '1.10.3': '9', '1.14.2': '10', '1.22.1': '12', '1.26.3': '13' } }
};
function guessDistro(products) {
  const os = /ubuntu/i.test(products.os) ? 'Ubuntu' : /debian/i.test(products.os) ? 'Debian' : null;
  if (!os) return null;
  for (const p of products) {
    const name = canonical(p.name);
    const v = DISTRO_BY_PACKAGE[os][name] && DISTRO_BY_PACKAGE[os][name][p.version];
    if (v) return { name: os, version: v, from: `${p.name}/${p.version}`, note: `${name} ${p.version} è il pacchetto di ${os} ${v}` };
  }
  return null;
}

/* ---------- audit header di sicurezza ---------- */
function auditSecurity(h, capture, page, setCookie) {
  const checks = [];
  const https = /^https:/.test((capture && capture.url) || (page && page.url) || '');
  const c = (name, ok, detail, weight = 1) => checks.push({ name, ok, detail, weight });

  c('HTTPS', !!https, https ? 'connessione cifrata' : 'il sito non usa HTTPS', 3);
  const hsts = h['strict-transport-security'];
  const maxAge = hsts ? parseInt((hsts.match(/max-age=(\d+)/) || [])[1] || '0', 10) : 0;
  c('Strict-Transport-Security', !!hsts && maxAge >= 15552000, hsts ? `${hsts}${maxAge < 15552000 ? ' (max-age < 180 giorni)' : ''}` : 'assente', 2);
  const csp = h['content-security-policy'];
  const cspIssues = [];
  if (csp) {
    const scriptSrc = (csp.match(/(?:^|;)\s*script-src\s+([^;]*)/i) || csp.match(/(?:^|;)\s*default-src\s+([^;]*)/i) || [])[1];
    if (!scriptSrc) cspIssues.push('nessuna direttiva script-src/default-src (non limita gli script)');
    else {
      const strict = /'strict-dynamic'|'nonce-|'sha(256|384|512)-/.test(scriptSrc);
      if (/'unsafe-inline'/.test(scriptSrc) && !strict) cspIssues.push("script-src con 'unsafe-inline'");
      if (/'unsafe-eval'/.test(scriptSrc)) cspIssues.push("script-src con 'unsafe-eval'");
      if (/(^|\s)(\*|https?:|data:)(\s|$)/.test(scriptSrc)) cspIssues.push('script-src con sorgenti jolly (*, https:, data:)');
    }
  }
  c('Content-Security-Policy', !!csp && !cspIssues.length,
    csp ? (cspIssues.length ? 'presente ma debole: ' + cspIssues.join('; ') : 'presente e restrittiva sugli script') :
      (h['content-security-policy-report-only'] ? 'solo report-only (non applicata)' : 'assente'), 2);
  c('X-Content-Type-Options', /nosniff/i.test(h['x-content-type-options'] || ''), h['x-content-type-options'] || 'assente');
  c('Protezione clickjacking', !!h['x-frame-options'] || /frame-ancestors/.test(csp || ''),
    h['x-frame-options'] || (/frame-ancestors/.test(csp || '') ? 'CSP frame-ancestors' : 'assente'));
  c('Referrer-Policy', !!h['referrer-policy'], h['referrer-policy'] || 'assente');
  c('Permissions-Policy', !!h['permissions-policy'], h['permissions-policy'] ? 'presente' : 'assente');
  c('Cross-Origin-Opener-Policy', !!h['cross-origin-opener-policy'], h['cross-origin-opener-policy'] || 'assente');
  if (h['access-control-allow-origin'] === '*' && /true/i.test(h['access-control-allow-credentials'] || ''))
    c('CORS', false, 'Allow-Origin * con credenziali', 2);
  else if (h['access-control-allow-origin']) c('CORS', h['access-control-allow-origin'] !== '*', 'Allow-Origin: ' + h['access-control-allow-origin']);

  const versionLeak = /\d+\.\d+/.test(h['server'] || '') || !!h['x-powered-by'] || !!h['x-aspnet-version'] || !!h['x-aspnetmvc-version'];
  c('Nessuna esposizione di versione', !versionLeak,
    versionLeak ? 'gli header rivelano software e versione (Server/X-Powered-By): utile a un attaccante' : 'banner non verboso', 2);

  if (setCookie) {
    const cookies = setCookie.split('\n').filter(Boolean);
    const weak = cookies.filter((ck) => (https && !/;\s*secure/i.test(ck)) || !/;\s*httponly/i.test(ck) || !/;\s*samesite/i.test(ck));
    c('Flag dei cookie (Secure/HttpOnly/SameSite)', weak.length === 0,
      weak.length ? `${weak.length} cookie su ${cookies.length} senza tutti i flag: ${weak.map((w) => w.split('=')[0]).slice(0, 5).join(', ')}` : 'ok');
  }
  if (page) {
    if (https) c('Contenuti misti', page.mixedContent === 0, page.mixedContent ? `${page.mixedContent} risorse caricate via http://` : 'nessuno');
    c('Subresource Integrity', page.crossOriginWithoutSRI === 0,
      page.crossOriginWithoutSRI ? `${page.crossOriginWithoutSRI} script cross-origin senza attributo integrity` : 'ok');
  }

  const total = checks.reduce((s, x) => s + x.weight, 0);
  const got = checks.reduce((s, x) => s + (x.ok ? x.weight : 0), 0);
  const score = total ? Math.round((got / total) * 100) : 0;
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  return { checks, score, grade };
}

/* ---------- base dati versioni obsolete / CVE note (aggiornata a fine 2026) ----------
 * severity: critical | high | medium | low | info
 * Ogni regola: test(version) -> true se vulnerabile/obsoleto.
 * Le regole sono indicative: verificare sempre con il bollettino del vendor,
 * perché le distribuzioni Linux applicano backport senza cambiare il numero di versione.
 */
const VULN_RULES = [
  // PHP
  { tech: 'PHP', test: (v) => lt(v, '8.2'), severity: 'critical',
    msg: 'Ramo PHP fuori supporto (EOL): nessuna patch di sicurezza. Rami supportati: 8.2 (solo sicurezza, fino a fine 2026), 8.3, 8.4, 8.5.',
    cves: ['CVE-2024-4577 (argument injection CGI, <8.1.29)', 'CVE-2024-8926', 'CVE-2024-11236'] },
  { tech: 'PHP', test: (v) => cmpVersion(branch(v), '8.2') === 0, severity: 'medium',
    msg: 'PHP 8.2 riceve solo patch di sicurezza e raggiunge l\'EOL il 31/12/2026: pianificare la migrazione a 8.4/8.5.' },
  { tech: 'PHP', test: (v) => [['8.2', '8.2.35'], ['8.3', '8.3.36'], ['8.4', '8.4.27'], ['8.5', '8.5.12']].some(([b, fix]) => branch(v) === b && lt(v, fix)),
    severity: 'critical',
    msg: 'PHP2Shell: use-after-free nella gestione di sessioni/upload multipart, RCE non autenticata con PoC pubblici (avviso ACN AL07/261021/CSIRT-ITA). Corrette in 8.2.35, 8.3.36, 8.4.27, 8.5.12. Le distribuzioni possono aver applicato backport senza cambiare versione: verificare sul server con tools/php-vuln-check.sh.',
    cves: ['CVE-2026-109618', 'CVE-2026-109619'] },
  { tech: 'PHP', test: (v) => lt(v, '8.2'), severity: 'critical',
    msg: 'PHP2Shell su ramo fuori supporto: esistono solo backport minimi in sorgente per 7.4/8.0/8.1.', cves: ['CVE-2026-109618', 'CVE-2026-109619'] },
  { tech: 'PHP', test: () => true, severity: 'high',
    msg: 'CVE-2026-115560 (sessioni, upload progress) non è ancora corretta da alcuna release: impostare session.upload_progress.enabled = 0 in php.ini o nel pool FPM e riavviare i worker. Esporre la versione (X-Powered-By) facilita la ricerca dei bersagli: expose_php = Off.',
    cves: ['CVE-2026-115560'] },

  // Apache httpd
  { tech: 'Apache HTTP Server', test: (v) => lt(v, '2.4'), severity: 'critical', msg: 'Apache 2.2 o precedente: fuori supporto dal 2017.' },
  { tech: 'Apache HTTP Server', test: (v) => !lt(v, '2.4') && lt(v, '2.4.62'), severity: 'critical',
    msg: 'Apache httpd < 2.4.62: vulnerabilità gravi in mod_rewrite, mod_proxy e handler (SSRF, esecuzione/disclosure di codice sorgente).',
    cves: ['CVE-2024-38476', 'CVE-2024-38474', 'CVE-2024-38475', 'CVE-2024-40725', 'CVE-2024-40898'] },
  { tech: 'Apache HTTP Server', test: (v) => !lt(v, '2.4.62') && lt(v, '2.4.65'), severity: 'high',
    msg: 'Apache httpd < 2.4.65: CVE corrette a luglio 2025 (mod_ssl, mod_proxy_http2, HTTP response splitting).',
    cves: ['CVE-2025-23048', 'CVE-2025-49812', 'CVE-2025-53020', 'CVE-2024-42516', 'CVE-2025-54090'] },

  // nginx
  { tech: 'nginx', test: (v) => lt(v, '1.26.3') || (branch(v) === '1.27' && lt(v, '1.27.4')), severity: 'high',
    msg: 'nginx con CVE note (riuso sessioni TLS su virtual host, worker crash in mp4/HTTP/3).',
    cves: ['CVE-2025-23419', 'CVE-2024-7347', 'CVE-2024-32760'] },
  { tech: 'nginx', test: (v) => lt(v, '1.28.1') && !lt(v, '1.26.3') && !(branch(v) === '1.27' && lt(v, '1.27.4')), severity: 'medium',
    msg: 'nginx precedente al rilascio di agosto 2025 (ngx_mail_smtp_module).', cves: ['CVE-2025-53859'] },

  // OpenSSL
  { tech: 'OpenSSL', test: (v) => lt(v, '3.0'), severity: 'critical', msg: 'OpenSSL 1.x è fuori supporto (EOL settembre 2023).' },
  { tech: 'OpenSSL', test: (v) => ['3.1', '3.2'].includes(branch(v)), severity: 'high', msg: 'Ramo OpenSSL 3.1/3.2 fuori supporto: usare 3.0 LTS, 3.5 LTS o successivi.' },
  { tech: 'OpenSSL', test: (v) => (branch(v) === '3.0' && lt(v, '3.0.18')) || (branch(v) === '3.5' && lt(v, '3.5.4')), severity: 'medium',
    msg: 'OpenSSL con patch level datato.', cves: ['CVE-2025-9230', 'CVE-2025-9231', 'CVE-2025-9232'] },

  // IIS / ASP.NET
  { tech: 'Microsoft IIS', test: (v) => lt(v, '10.0'), severity: 'critical', msg: 'IIS < 10 implica Windows Server 2012 R2 o precedenti, fuori supporto.' },
  { tech: 'ASP.NET', test: (v) => /^[12]\./.test(v), severity: 'high', msg: 'ASP.NET 1.x/2.0 (CLR 2): runtime legacy non più aggiornato.' },

  // sistemi operativi (stimati dal banner)
  { tech: 'Ubuntu', test: (v) => !['20.04', '22.04', '24.04', '25.10', '26.04'].includes(v), severity: 'critical',
    msg: 'Release di Ubuntu fuori supporto: il sistema operativo non riceve più patch di sicurezza (versione stimata dal banner del server).' },
  { tech: 'Ubuntu', test: (v) => v === '20.04', severity: 'high', msg: 'Ubuntu 20.04: supporto standard terminato a maggio 2025, patch solo con Ubuntu Pro/ESM.' },
  { tech: 'Debian', test: (v) => cmpVersion(v, '12') < 0, severity: 'critical', msg: 'Release di Debian fuori supporto (Debian 11 LTS terminato ad agosto 2026).' },

  // Tomcat
  { tech: 'Apache Tomcat', test: (v) => lt(v, '9.0'), severity: 'critical', msg: 'Tomcat < 9 fuori supporto.' },
  { tech: 'Apache Tomcat', test: (v) => (branch(v, 1) === '9' && lt(v, '9.0.99')) || (branch(v, 1) === '10' && lt(v, '10.1.35')) || (branch(v, 1) === '11' && lt(v, '11.0.3')),
    severity: 'critical', msg: 'Tomcat vulnerabile a RCE tramite partial PUT.', cves: ['CVE-2025-24813'] },

  // CMS
  { tech: 'WordPress', test: (v) => lt(v, '6.4'), severity: 'high', msg: 'WordPress molto datato: aggiornare all\'ultima release 6.x (le patch di sicurezza sono garantite solo sull\'ultimo ramo).' },
  { tech: 'WordPress', test: (v) => !lt(v, '6.4') && lt(v, '6.8'), severity: 'medium', msg: 'WordPress non all\'ultimo ramo: aggiornare.' },
  { tech: 'Drupal', test: (v) => lt(v, '10'), severity: 'high', msg: 'Drupal 7/9 fuori supporto (Drupal 7 EOL gennaio 2025).' },
  { tech: 'Joomla', test: (v) => lt(v, '5'), severity: 'high', msg: 'Joomla 3/4 fuori supporto.', cves: ['CVE-2023-23752 (Joomla 4.0-4.2.7)'] },

  // librerie front-end
  { tech: 'jQuery', test: (v) => lt(v, '3.5.0'), severity: 'medium', msg: 'jQuery < 3.5.0: XSS in htmlPrefilter / manipolazione HTML.', cves: ['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2019-11358'] },
  { tech: 'jQuery UI', test: (v) => lt(v, '1.13.2'), severity: 'medium', msg: 'jQuery UI < 1.13.2: XSS.', cves: ['CVE-2022-31160', 'CVE-2021-41182', 'CVE-2021-41184'] },
  { tech: 'AngularJS', test: () => true, severity: 'high', msg: 'AngularJS 1.x è EOL da gennaio 2022: CVE ReDoS/XSS non più corrette.', cves: ['CVE-2022-25869', 'CVE-2023-26116', 'CVE-2024-21490'] },
  { tech: 'Bootstrap', test: (v) => lt(v, '3.4.1') || (branch(v, 1) === '4' && lt(v, '4.3.1')), severity: 'medium', msg: 'Bootstrap con XSS nei componenti data-*.', cves: ['CVE-2019-8331', 'CVE-2018-14042'] },
  { tech: 'Bootstrap', test: (v) => lt(v, '5'), severity: 'low', msg: 'Bootstrap 3/4 non più mantenuto (EOL): migrare a 5.x.' },
  { tech: 'Lodash', test: (v) => lt(v, '4.17.21'), severity: 'high', msg: 'Lodash < 4.17.21: command injection / prototype pollution.', cves: ['CVE-2021-23337', 'CVE-2020-8203'] },
  { tech: 'Underscore.js', test: (v) => lt(v, '1.13.6'), severity: 'medium', msg: 'Underscore < 1.13.6: code injection in _.template.', cves: ['CVE-2021-23358'] },
  { tech: 'Moment.js', test: (v) => lt(v, '2.29.4'), severity: 'medium', msg: 'Moment.js < 2.29.4: ReDoS / path traversal.', cves: ['CVE-2022-31129', 'CVE-2022-24785'] },
  { tech: 'Moment.js', test: (v) => !lt(v, '2.29.4'), severity: 'info', msg: 'Moment.js è in modalità manutenzione: valutare Day.js, Luxon o Temporal.' },
  { tech: 'Handlebars', test: (v) => lt(v, '4.7.7'), severity: 'high', msg: 'Handlebars < 4.7.7: RCE/prototype pollution nei template.', cves: ['CVE-2021-23369', 'CVE-2021-23383'] },
  { tech: 'Vue.js', test: (v) => lt(v, '3'), severity: 'medium', msg: 'Vue 2 è EOL da dicembre 2023.', cves: ['CVE-2024-6783'] },
  { tech: 'React', test: (v) => ['19.0.0', '19.1.0', '19.1.1', '19.2.0'].includes(v), severity: 'critical',
    msg: 'React 19 con Server Components vulnerabili a RCE non autenticata ("React2Shell").', cves: ['CVE-2025-55182'] },
  { tech: 'Next.js', test: (v) => (branch(v, 1) === '15' && lt(v, '15.2.3')) || (branch(v, 1) === '14' && lt(v, '14.2.25')) || (branch(v, 1) === '13' && lt(v, '13.5.9')) || lt(v, '12.3.5'),
    severity: 'critical', msg: 'Next.js: bypass dell\'autorizzazione nel middleware.', cves: ['CVE-2025-29927'] },
  { tech: 'Next.js', test: (v) => [['15.0', '15.0.5'], ['15.1', '15.1.9'], ['15.2', '15.2.6'], ['15.3', '15.3.6'], ['15.4', '15.4.8'], ['15.5', '15.5.7'], ['16.0', '16.0.7']]
      .some(([b, fix]) => branch(v) === b && lt(v, fix)),
    severity: 'critical', msg: 'Next.js App Router con React Server Components vulnerabili a RCE non autenticata ("React2Shell").', cves: ['CVE-2025-55182', 'CVE-2025-66478'] },
  { tech: 'DOMPurify', test: (v) => lt(v, '3.2.4'), severity: 'medium', msg: 'DOMPurify < 3.2.4: bypass mXSS.', cves: ['CVE-2024-45801', 'CVE-2025-26791'] },
  { tech: 'Axios', test: (v) => lt(v, '1.8.2'), severity: 'medium', msg: 'Axios < 1.8.2: SSRF / leak credenziali con URL assoluti.', cves: ['CVE-2025-27152', 'CVE-2023-45857'] },
  { tech: 'Prototype', test: () => true, severity: 'medium', msg: 'Prototype.js non è più mantenuto.' },
  { tech: 'MooTools', test: () => true, severity: 'medium', msg: 'MooTools non è più mantenuto.' },
  { tech: 'TinyMCE', test: (v) => lt(v, '7.0'), severity: 'medium', msg: 'TinyMCE < 7: diverse XSS corrette nel 2024.', cves: ['CVE-2024-29881', 'CVE-2024-38356'] },
  { tech: 'CKEditor', test: (v) => lt(v, '4.24') || branch(v, 1) === '4', severity: 'medium', msg: 'CKEditor 4 è EOL (giugno 2023) per la versione open source.', cves: ['CVE-2024-24815'] }
];

function checkVulnerabilities(techs) {
  const findings = [];
  techs.forEach((t) => {
    if (!t.version || !/^\d/.test(t.version)) return;
    VULN_RULES.filter((r) => r.tech === t.name).forEach((r) => {
      let hit = false;
      try { hit = r.test(t.version); } catch (e) { hit = false; }
      if (hit) findings.push({ tech: t.name, version: t.version, severity: r.severity, msg: r.msg, cves: r.cves || [] });
    });
  });
  // AngularJS/Prototype/MooTools anche senza versione
  techs.forEach((t) => {
    if (!t.version && ['AngularJS', 'Prototype', 'MooTools'].includes(t.name)) {
      const r = VULN_RULES.find((x) => x.tech === t.name);
      findings.push({ tech: t.name, version: null, severity: r.severity, msg: r.msg, cves: r.cves || [] });
    }
  });
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return findings.sort((a, b) => order[a.severity] - order[b.severity]);
}

if (typeof module !== 'undefined') module.exports = { cmpVersion, parseProducts, analyzeHeaders, checkVulnerabilities, headerMap };
