/*
 * Tech Detector Pro - logica del popup
 * Autore: Umberto Meglio - Supporto alla creazione: Claude di Anthropic
 *
 * Flusso:
 *  1. rilevamento DOM (detectTechnologies) + info pagina (collectPageInfo) nella scheda attiva
 *  2. header HTTP catturati dal service worker; se mancanti, richiesta di fallback dal popup
 *  3. fusione dei risultati, audit di sicurezza e controllo versioni/CVE
 */
'use strict';

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = text;
  return e;
};

const CATEGORY_ORDER = [
  ['Web Server', '🖥️'], ['Server', '🖥️'], ['Application Server', '⚙️'], ['Proxy', '🔀'], ['Cache Tool', '⚡'], ['CDN', '🌐'],
  ['PaaS', '☁️'], ['Pannello di hosting', '🧰'], ['Linguaggio di programmazione', '🔤'], ['PHP', '🐘'],
  ['Framework Backend', '🏗️'], ['Libreria TLS', '🔐'], ['Sistema operativo', '🐧'], ['Modulo Apache', '🧩'], ['Database', '🗄️'], ['CMS', '📝'],
  ['E-commerce', '🛒'], ['JavaScript Framework', '⚛️'], ['JavaScript Library', '📚'], ['CSS Framework', '🎨'],
  ['Analytics', '📊'], ['Tag Manager', '🏷️'], ['Marketing', '📣'], ['Network Pubblicitario', '💰'], ['Security', '🛡️'],
  ['Static Site Generator', '📄'], ['Strumenti di Sviluppo', '🛠️'], ['PWA', '📱'], ['Font', '🔠'], ['RUM', '⏱️'],
  ['Personalisation', '🎯'], ['Segmentation', '🎯'], ['Customer data platform', '👥'], ['Miscellanea', '🧩'], ['Altro', '❔']
];
const ICON = Object.fromEntries(CATEGORY_ORDER);
const ORDER = CATEGORY_ORDER.map((c) => c[0]);

// nomi delle librerie lette da pageinfo -> nome usato dal detector
const LIB_NAME = { 'Vue.js': 'Vue.js', React: 'React', jQuery: 'jQuery', Lodash: 'Lodash', 'Moment.js': 'Moment.js' };
const LIB_CATEGORY = {
  'Angular': 'JavaScript Framework', 'AngularJS': 'JavaScript Framework', 'React': 'JavaScript Framework', 'Vue.js': 'JavaScript Framework',
  'Next.js': 'JavaScript Framework', 'Nuxt': 'JavaScript Framework', 'Svelte': 'JavaScript Framework', 'Ember.js': 'JavaScript Framework',
  'Backbone.js': 'JavaScript Framework', 'Knockout': 'JavaScript Framework', 'Alpine.js': 'JavaScript Framework', 'Dojo': 'JavaScript Framework',
  'Bootstrap': 'CSS Framework', 'WordPress': 'CMS', 'TinyMCE': 'Strumenti di Sviluppo', 'CKEditor': 'Strumenti di Sviluppo'
};

let REPORT = null;

document.addEventListener('DOMContentLoaded', init);

/** Lingua: preferenza salvata, altrimenti quella del browser. Cambiarla ricarica il popup. */
async function initLang() {
  let pref = null;
  try { pref = (await chrome.storage.local.get('lang')).lang; } catch (e) { /* storage non disponibile */ }
  I18N.set(I18N.pick(pref, chrome.i18n.getUILanguage()));
  applyStaticI18n();
  const sel = $('#lang');
  I18N.LANGS.forEach(([code, name]) => {
    const o = document.createElement('option');
    o.value = code; o.textContent = name; o.selected = code === I18N.lang;
    sel.appendChild(o);
  });
  sel.addEventListener('change', async () => {
    try { await chrome.storage.local.set({ lang: sel.value }); } catch (e) { /* ignora */ }
    location.reload();
  });
}

async function init() {
  await initLang();
  $('#ver').textContent = chrome.runtime.getManifest().version;
  document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => switchTab(t.dataset.tab)));
  $('#btn-export').addEventListener('click', exportJSON);
  $('#btn-copy').addEventListener('click', copyReport);

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !/^https?:/.test(tab.url || '')) {
    $('#loading').style.display = 'none';
    $('#tab-tech').appendChild(el('div', 'empty', t('ui.openSite')));
    return;
  }
  $('#host').textContent = new URL(tab.url).host;

  const [domTechs, page, capture] = await Promise.all([
    runInPage(tab.id, detectTechnologies, 'ISOLATED'),
    runInPage(tab.id, collectPageInfo, 'MAIN'),
    getHeaders(tab)
  ]);

  const analysis = analyzeHeaders(capture, page);
  const techs = mergeTechs(domTechs || [], analysis.techs, (page && page.libs) || {});
  const discarded = techs.discarded || [];
  REPORT = {
    generatedAt: new Date().toISOString(), url: tab.url, ip: capture && capture.ip,
    technologies: techs, server: analysis.server, security: analysis.security,
    vulnerabilities: [], headers: analysis.headers, headerSource: capture && capture.source, php: null,
    discardedTextOnly: discarded
  };
  CTX = { url: tab.url, capture };

  REPORT.php = await detectPhpVersion({ url: tab.url, techs, capture, deep: false });
  applyPhp();
  $('#loading').style.display = 'none';
  renderAll();
}

let CTX = null;

/** Inserisce la versione PHP trovata tra le tecnologie e ricalcola le vulnerabilità. */
function applyPhp() {
  const php = REPORT.php;
  const techs = REPORT.technologies;
  if (php && (php.version || php.isPhp)) {
    let tp = techs.find((x) => x.name === 'PHP');
    if (!tp) { tp = { name: 'PHP', version: null, type: '', category: 'Linguaggio di programmazione', fromHeaders: true }; techs.push(tp); }
    if (php.version && (!tp.version || php.confidence === 'certa')) {
      tp.version = php.version;
      tp.type = `${t('conf.' + php.confidence)} · ${php.source}`;
    } else if (!tp.version) tp.type = t('php.hidden');
  }
  // le stime e i minimi non generano avvisi CVE come se fossero certi
  const forVulns = techs.map((t) => (t.name === 'PHP' && php && php.confidence && !['certa', 'probabile'].includes(php.confidence))
    ? Object.assign({}, t, { version: null }) : t);
  REPORT.vulnerabilities = checkVulnerabilities(forVulns);
  if (php && php.version && php.confidence === 'stima') {
    const est = checkVulnerabilities([{ name: 'PHP', version: php.version.replace(/[^\d.].*$/, '') }]);
    est.forEach((v) => { v.msg = t('php.estPrefix') + v.msg; if (v.severity === 'critical') v.severity = 'high'; });
    REPORT.vulnerabilities = REPORT.vulnerabilities.concat(est);
  }
}

function renderAll() {
  ['tech', 'server', 'security', 'headers'].forEach((n) => { $('#tab-' + n).textContent = ''; });
  renderTech(REPORT.technologies, REPORT.vulnerabilities);
  renderServer(REPORT.server, CTX.capture);
  renderSecurity(REPORT.security, REPORT.vulnerabilities);
  renderHeaders(REPORT.headers, CTX.capture);
}

async function deepPhpSearch(btn) {
  btn.disabled = true;
  btn.textContent = t('php.searching');
  REPORT.php = await detectPhpVersion({ url: CTX.url, techs: REPORT.technologies, capture: CTX.capture, deep: true });
  REPORT.php.deepDone = true;
  applyPhp();
  renderAll();
  switchTab('server');
}

function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.panel').forEach((p) => p.classList.toggle('active', p.id === 'tab-' + name));
}

async function runInPage(tabId, func, world) {
  try {
    const res = await chrome.scripting.executeScript({ target: { tabId }, func, world });
    return res && res[0] ? res[0].result : null;
  } catch (e) {
    console.warn('executeScript', e);
    return null;
  }
}

/** Header dal service worker; se assenti (pagina aperta prima dell'installazione) li richiede di nuovo. */
async function getHeaders(tab) {
  const key = 'tab_' + tab.id;
  try {
    const data = (await chrome.storage.session.get(key))[key];
    if (data && sameDoc(data.url, tab.url)) return Object.assign(data, { source: 'nav' });
  } catch (e) { /* storage non disponibile */ }
  try {
    const r = await fetch(tab.url, { method: 'GET', credentials: 'include', cache: 'no-store', redirect: 'follow' });
    const headers = [];
    r.headers.forEach((value, name) => headers.push({ name: name.toLowerCase(), value }));
    try { r.body && r.body.cancel(); } catch (e) { /* ignora */ }
    return { url: r.url, ip: null, statusCode: r.status, statusLine: `${r.status} ${r.statusText}`, headers, source: 'probe' };
  } catch (e) {
    return null;
  }
}
const sameDoc = (a, b) => { try { const x = new URL(a), y = new URL(b); return x.origin + x.pathname === y.origin + y.pathname; } catch (e) { return false; } };

const cleanVersion = (v) => (v ? String(v).trim().replace(/^v/i, '').replace(/[^\w]+$/, '') || null : null);

function mergeTechs(dom, fromHeaders, libs) {
  const out = [];
  const find = (n) => out.find((t) => t.name.toLowerCase() === n.toLowerCase());
  const push = (t) => {
    t = Object.assign({}, t, { name: typeof canonical === 'function' ? canonical(t.name) : t.name });
    const ex = find(t.name);
    if (ex) { if (!ex.version && t.version) ex.version = cleanVersion(t.version); if (t.fromHeaders) ex.fromHeaders = true; return; }
    out.push({ name: t.name, version: cleanVersion(t.version), type: t.type || '', category: t.category || 'Altro', fromHeaders: !!t.fromHeaders, deduced: !!t.deduced });
  };
  fromHeaders.forEach(push);
  dom.forEach(push);
  Object.entries(libs).forEach(([name, version]) => {
    const n = LIB_NAME[name] || name;
    // il detector chiama "Angular" anche AngularJS: distinguiamo
    if (name === 'AngularJS') { const a = find('Angular'); if (a && !a.version) { a.name = 'AngularJS'; } }
    push({ name: n, version, type: t('type.global'), category: LIB_CATEGORY[n] || 'JavaScript Library' });
  });
  const node = out.find((t) => ['Next.js', 'Nuxt', 'Nuxt.js', 'Express'].includes(t.name));
  if (node && !find('Node.js')) out.push({ name: 'Node.js', version: null, type: t('type.deduced', node.name), category: 'Linguaggio di programmazione', fromHeaders: false, deduced: true });

  // Il browser non vede database, cache, linguaggio o web server: se una di queste tecnologie
  // arriva solo da una parola trovata nel testo della pagina (e non da header/cookie) NON è un
  // rilevamento. Esempio reale: un'applicazione di monitoraggio che elenca "Redis" tra i servizi
  // veniva marcata come "usa Redis". Queste voci vengono scartate.
  const confirmed = out.filter((t) => !(SERVER_SIDE.has(t.category) && !t.fromHeaders && !STRONG_DOM.has(t.name) && !t.deduced));
  confirmed.discarded = out.filter((t) => !confirmed.includes(t)).map((t) => t.name);
  return confirmed;
}

const SERVER_SIDE = new Set(['Web Server', 'Server', 'Proxy', 'Cache Tool', 'Database', 'Linguaggio di programmazione', 'PHP', 'Framework Backend']);
// tecnologie con regole lato pagina affidabili (script, oggetti globali o marcatori specifici)
const STRONG_DOM = new Set(['Next.js', 'Nuxt', 'Nuxt.js', 'PHP', 'Firebase', 'Node.js']);

/* ---------- rendering ---------- */
function renderTech(techs, vulns) {
  const root = $('#tab-tech');
  $('#cnt-tech').textContent = techs.length;
  if (!techs.length) { root.appendChild(el('div', 'empty', t('ui.noTech'))); return; }
  const vulnTech = new Set(vulns.filter((v) => v.severity !== 'info').map((v) => v.tech));
  const groups = {};
  techs.forEach((t) => { (groups[t.category] = groups[t.category] || []).push(t); });
  const cats = Object.keys(groups).sort((a, b) => (ORDER.indexOf(a) + 1 || 99) - (ORDER.indexOf(b) + 1 || 99));
  cats.forEach((cat) => {
    const h = el('div', 'category');
    h.append(el('span', 'ico', ICON[cat] || '🔹'), el('span', null, catLabel(cat)), el('span', 'pill', groups[cat].length));
    root.appendChild(h);
    groups[cat].sort((a, b) => a.name.localeCompare(b.name)).forEach((tc) => {
      const it = el('div', 'item');
      it.appendChild(el('span', 'name', tc.name));
      if (tc.version) it.appendChild(el('span', 'badge ver', tc.version));
      if (vulnTech.has(tc.name)) {
        const w = el('span', 'badge warn', t('ui.toUpdate'));
        w.style.cursor = 'pointer';
        w.addEventListener('click', () => switchTab('security'));
        it.appendChild(w);
      }
      it.appendChild(el('span', 'type', tc.fromHeaders ? (tc.type || t('ui.httpHeader')) : (tc.type || '')));
      root.appendChild(it);
    });
  });
}

function renderServer(rows, capture) {
  const root = $('#tab-server');
  if (!rows.length) { root.appendChild(el('div', 'empty', t('ui.noServer'))); return; }
  const kv = el('div', 'kv');
  rows.forEach((r) => {
    kv.appendChild(el('div', 'k', r.label));
    const v = el('div', 'v', r.value);
    if (r.hint) v.appendChild(el('div', 'hint', r.hint));
    kv.appendChild(v);
  });
  root.appendChild(kv);
  renderPhpBox(root);
  if (capture && capture.source !== 'nav') root.appendChild(el('div', 'note', t('ui.headersProbe')));
  if (!capture) root.appendChild(el('div', 'note', t('ui.headersNone')));
}

function renderPhpBox(root) {
  const php = REPORT.php;
  if (!php) return;
  if (php.notPhp) {
    root.appendChild(el('div', 'category', '🐘 Versione PHP'));
    const box = el('div', 'php-box');
    const head = el('div', 'php-head');
    head.append(el('span', 'php-ver', t('php.notUsed')), el('span', 'conf ok', t('php.backend', php.notPhp)));
    box.appendChild(head);
    const ul = el('ul', 'evidence');
    php.evidence.forEach((e) => ul.appendChild(el('li', null, e)));
    box.appendChild(ul);
    root.appendChild(box);
    return;
  }
  if (!php.isPhp && !php.version) return;
  root.appendChild(el('div', 'category', '🐘 Versione PHP'));
  const box = el('div', 'php-box');
  const conf = { certa: 'ok', probabile: 'ok', stima: 'warn', minimo: 'warn' }[php.confidence] || 'ko';
  const head = el('div', 'php-head');
  head.append(el('span', 'php-ver', php.version || t('php.notFound')));
  if (php.confidence) head.append(el('span', 'conf ' + conf, t('conf.' + php.confidence)));
  box.appendChild(head);
  if (php.source) box.appendChild(el('div', 'd', t('ui.source', php.source)));
  if (php.evidence.length) {
    const ul = el('ul', 'evidence');
    php.evidence.forEach((e) => ul.appendChild(el('li', null, e)));
    box.appendChild(ul);
  }
  if (php.confidence !== 'certa' && !php.deepDone) {
    const b = el('button', 'btn', t('php.deep'));
    b.title = t('php.deepTitle');
    b.addEventListener('click', () => deepPhpSearch(b));
    box.appendChild(b);
    box.appendChild(el('div', 'note', t('php.deepNote')));
  }
  root.appendChild(box);
}

function renderSecurity(sec, vulns) {
  const root = $('#tab-security');
  const serious = vulns.filter((v) => ['critical', 'high', 'medium'].includes(v.severity)).length;
  const pill = $('#cnt-sec');
  pill.textContent = serious || sec.grade;
  if (serious) pill.classList.add('bad');

  root.appendChild(el('div', 'category', t('sec.components')));
  if (!vulns.length) {
    root.appendChild(el('div', 'note', t('sec.noVulns')));
  }
  vulns.forEach((v) => {
    const box = el('div', 'vuln ' + v.severity);
    const sevLabel = t('sev.' + v.severity);
    box.append(el('div', 'sev', `${sevLabel} · ${v.tech}${v.version ? ' ' + v.version : ''}`), el('div', null, v.msg));
    if (v.cves.length) {
      const c = el('div', 'cves');
      v.cves.forEach((id, i) => {
        const m = id.match(/CVE-\d{4}-\d+/);
        if (m) {
          const a = el('a', null, id);
          a.href = 'https://nvd.nist.gov/vuln/detail/' + m[0];
          a.target = '_blank'; a.rel = 'noopener noreferrer';
          c.appendChild(a);
        } else c.appendChild(document.createTextNode(id));
        if (i < v.cves.length - 1) c.appendChild(document.createTextNode(' · '));
      });
      box.appendChild(c);
    }
    root.appendChild(box);
  });

  root.appendChild(el('div', 'category', t('sec.headers')));
  const sc = el('div', 'score');
  sc.append(el('div', 'grade ' + sec.grade, sec.grade), el('div', null, t('sec.score', sec.score, sec.checks.filter((c) => c.ok).length, sec.checks.length)));
  root.appendChild(sc);
  sec.checks.forEach((c) => {
    const row = el('div', 'check ' + (c.ok ? 'ok' : 'ko'));
    const body = el('div');
    body.append(el('div', null, c.name), el('div', 'd', c.detail));
    row.append(el('span', 'st', c.ok ? '✓' : '✗'), body);
    root.appendChild(row);
  });
  root.appendChild(el('div', 'note', t('sec.note')));
}

function renderHeaders(headers, capture) {
  const root = $('#tab-headers');
  if (!headers || !headers.length) { root.appendChild(el('div', 'empty', t('ui.noHeaders'))); return; }
  if (capture) root.appendChild(el('div', 'note', t('ui.source', `${t('src.' + capture.source)} · ${capture.statusLine || capture.statusCode}`)));
  headers.slice().sort((a, b) => a.name.localeCompare(b.name)).forEach((h) => {
    const d = el('div', 'hdr');
    d.append(el('b', null, h.name), document.createTextNode(': ' + h.value));
    root.appendChild(d);
  });
}

/* ---------- export ---------- */
function exportJSON() {
  if (!REPORT) return;
  const blob = new Blob([JSON.stringify(REPORT, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `techdetector-${new URL(REPORT.url).host}-${Date.now()}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

async function copyReport() {
  if (!REPORT) return;
  const lines = [`Tech Detector Pro - ${REPORT.url}`, `IP: ${REPORT.ip || '-'}`, '', `== ${t('rep.tech')} ==`];
  REPORT.technologies.forEach((x) => lines.push(`- [${catLabel(x.category)}] ${x.name}${x.version ? ' ' + x.version : ''}`));
  lines.push('', `== ${t('rep.security')}: ${REPORT.security.grade} (${REPORT.security.score}/100) ==`);
  REPORT.security.checks.forEach((c) => lines.push(`${c.ok ? '[OK]' : '[KO]'} ${c.name}: ${c.detail}`));
  if (REPORT.vulnerabilities.length) {
    lines.push('', `== ${t('rep.toUpdate')} ==`);
    REPORT.vulnerabilities.forEach((v) => lines.push(`(${t('sev.' + v.severity)}) ${v.tech} ${v.version || ''}: ${v.msg} ${v.cves.join(', ')}`));
  }
  try {
    await navigator.clipboard.writeText(lines.join('\n'));
    $('#btn-copy').textContent = '✓';
    setTimeout(() => { $('#btn-copy').textContent = '⧉'; }, 1200);
  } catch (e) { /* clipboard negato */ }
}
