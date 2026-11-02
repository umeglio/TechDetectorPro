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
  ['Framework Backend', '🏗️'], ['Libreria TLS', '🔐'], ['Modulo Apache', '🧩'], ['Database', '🗄️'], ['CMS', '📝'],
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

async function init() {
  $('#ver').textContent = chrome.runtime.getManifest().version;
  document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => switchTab(t.dataset.tab)));
  $('#btn-export').addEventListener('click', exportJSON);
  $('#btn-copy').addEventListener('click', copyReport);

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !/^https?:/.test(tab.url || '')) {
    $('#loading').style.display = 'none';
    $('#tab-tech').appendChild(el('div', 'empty', 'Apri un sito web (http/https) per analizzarlo.'));
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
  const vulns = checkVulnerabilities(techs);

  REPORT = {
    generatedAt: new Date().toISOString(), url: tab.url, ip: capture && capture.ip,
    technologies: techs, server: analysis.server, security: analysis.security,
    vulnerabilities: vulns, headers: analysis.headers, headerSource: capture && capture.source
  };

  $('#loading').style.display = 'none';
  renderTech(techs, vulns);
  renderServer(analysis.server, capture);
  renderSecurity(analysis.security, vulns);
  renderHeaders(analysis.headers, capture);
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
    if (data && sameDoc(data.url, tab.url)) return Object.assign(data, { source: 'navigazione' });
  } catch (e) { /* storage non disponibile */ }
  try {
    const r = await fetch(tab.url, { method: 'GET', credentials: 'include', cache: 'no-store', redirect: 'follow' });
    const headers = [];
    r.headers.forEach((value, name) => headers.push({ name: name.toLowerCase(), value }));
    try { r.body && r.body.cancel(); } catch (e) { /* ignora */ }
    return { url: r.url, ip: null, statusCode: r.status, statusLine: `${r.status} ${r.statusText}`, headers, source: 'richiesta di verifica' };
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
    const ex = find(t.name);
    if (ex) { if (!ex.version && t.version) ex.version = cleanVersion(t.version); if (t.fromHeaders) ex.fromHeaders = true; return; }
    out.push({ name: t.name, version: cleanVersion(t.version), type: t.type || '', category: t.category || 'Altro', fromHeaders: !!t.fromHeaders });
  };
  fromHeaders.forEach(push);
  dom.forEach(push);
  Object.entries(libs).forEach(([name, version]) => {
    const n = LIB_NAME[name] || name;
    // il detector chiama "Angular" anche AngularJS: distinguiamo
    if (name === 'AngularJS') { const a = find('Angular'); if (a && !a.version) { a.name = 'AngularJS'; } }
    push({ name: n, version, type: 'variabile globale', category: LIB_CATEGORY[n] || 'JavaScript Library' });
  });
  return out;
}

/* ---------- rendering ---------- */
function renderTech(techs, vulns) {
  const root = $('#tab-tech');
  $('#cnt-tech').textContent = techs.length;
  if (!techs.length) { root.appendChild(el('div', 'empty', 'Nessuna tecnologia rilevata')); return; }
  const vulnTech = new Set(vulns.filter((v) => v.severity !== 'info').map((v) => v.tech));
  const groups = {};
  techs.forEach((t) => { (groups[t.category] = groups[t.category] || []).push(t); });
  const cats = Object.keys(groups).sort((a, b) => (ORDER.indexOf(a) + 1 || 99) - (ORDER.indexOf(b) + 1 || 99));
  cats.forEach((cat) => {
    const h = el('div', 'category');
    h.append(el('span', 'ico', ICON[cat] || '🔹'), el('span', null, cat), el('span', 'pill', groups[cat].length));
    root.appendChild(h);
    groups[cat].sort((a, b) => a.name.localeCompare(b.name)).forEach((t) => {
      const it = el('div', 'item');
      it.appendChild(el('span', 'name', t.name));
      if (t.version) it.appendChild(el('span', 'badge ver', t.version));
      if (vulnTech.has(t.name)) {
        const w = el('span', 'badge warn', '⚠ da aggiornare');
        w.style.cursor = 'pointer';
        w.addEventListener('click', () => switchTab('security'));
        it.appendChild(w);
      }
      it.appendChild(el('span', 'type', t.fromHeaders ? (t.type || 'header HTTP') : (t.type || '')));
      root.appendChild(it);
    });
  });
}

function renderServer(rows, capture) {
  const root = $('#tab-server');
  if (!rows.length) { root.appendChild(el('div', 'empty', 'Informazioni sul server non disponibili')); return; }
  const kv = el('div', 'kv');
  rows.forEach((r) => {
    kv.appendChild(el('div', 'k', r.label));
    const v = el('div', 'v', r.value);
    if (r.hint) v.appendChild(el('div', 'hint', r.hint));
    kv.appendChild(v);
  });
  root.appendChild(kv);
  if (capture && capture.source !== 'navigazione')
    root.appendChild(el('div', 'note', 'Header ottenuti con una richiesta di verifica: ricarica la pagina per l\'IP del server e gli header originali.'));
  if (!capture) root.appendChild(el('div', 'note', 'Header HTTP non disponibili: ricarica la pagina.'));
}

function renderSecurity(sec, vulns) {
  const root = $('#tab-security');
  const serious = vulns.filter((v) => ['critical', 'high', 'medium'].includes(v.severity)).length;
  const pill = $('#cnt-sec');
  pill.textContent = serious || sec.grade;
  if (serious) pill.classList.add('bad');

  root.appendChild(el('div', 'category', '🧯 Componenti da aggiornare / CVE note'));
  if (!vulns.length) {
    root.appendChild(el('div', 'note', 'Nessuna versione vulnerabile rilevata tra quelle esposte. Le versioni non dichiarate non possono essere verificate.'));
  }
  vulns.forEach((v) => {
    const box = el('div', 'vuln ' + v.severity);
    const sevLabel = { critical: 'critica', high: 'alta', medium: 'media', low: 'bassa', info: 'info' }[v.severity];
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

  root.appendChild(el('div', 'category', '🛡️ Header di sicurezza'));
  const sc = el('div', 'score');
  sc.append(el('div', 'grade ' + sec.grade, sec.grade), el('div', null, `Punteggio ${sec.score}/100 · ${sec.checks.filter((c) => c.ok).length}/${sec.checks.length} controlli superati`));
  root.appendChild(sc);
  sec.checks.forEach((c) => {
    const row = el('div', 'check ' + (c.ok ? 'ok' : 'ko'));
    const body = el('div');
    body.append(el('div', null, c.name), el('div', 'd', c.detail));
    row.append(el('span', 'st', c.ok ? '✓' : '✗'), body);
    root.appendChild(row);
  });
  root.appendChild(el('div', 'note', 'Nota: le distribuzioni Linux (Debian, Ubuntu, RHEL) applicano patch di sicurezza senza cambiare il numero di versione nel banner: verificare sempre sul server.'));
}

function renderHeaders(headers, capture) {
  const root = $('#tab-headers');
  if (!headers || !headers.length) { root.appendChild(el('div', 'empty', 'Nessun header disponibile: ricarica la pagina.')); return; }
  if (capture) root.appendChild(el('div', 'note', `Fonte: ${capture.source} · ${capture.statusLine || capture.statusCode}`));
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
  const lines = [`Tech Detector Pro - ${REPORT.url}`, `IP: ${REPORT.ip || 'n/d'}`, '', '== Tecnologie =='];
  REPORT.technologies.forEach((t) => lines.push(`- [${t.category}] ${t.name}${t.version ? ' ' + t.version : ''}`));
  lines.push('', `== Sicurezza: ${REPORT.security.grade} (${REPORT.security.score}/100) ==`);
  REPORT.security.checks.forEach((c) => lines.push(`${c.ok ? '[OK]' : '[KO]'} ${c.name}: ${c.detail}`));
  if (REPORT.vulnerabilities.length) {
    lines.push('', '== Componenti da aggiornare ==');
    REPORT.vulnerabilities.forEach((v) => lines.push(`(${v.severity}) ${v.tech} ${v.version || ''}: ${v.msg} ${v.cves.join(', ')}`));
  }
  try {
    await navigator.clipboard.writeText(lines.join('\n'));
    $('#btn-copy').textContent = '✓';
    setTimeout(() => { $('#btn-copy').textContent = '⧉'; }, 1200);
  } catch (e) { /* clipboard negato */ }
}
