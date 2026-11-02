/*
 * Tech Detector Pro - gestione delle lingue
 * Autore: Umberto Meglio - Supporto alla creazione: Claude di Anthropic
 *
 * Ogni lingua sta in locales/<codice>.js e si registra con I18N.add().
 * t('chiave', a, b) restituisce il testo nella lingua attiva, sostituendo {0}, {1}...
 * Se una chiave manca nella lingua scelta si usa l'inglese, poi la chiave stessa.
 */
'use strict';

const I18N = {
  dicts: {},
  lang: 'en',
  // lingue più parlate al mondo (nome nativo), in ordine di diffusione
  LANGS: [
    ['en', 'English'], ['zh_CN', '中文'], ['hi', 'हिन्दी'], ['es', 'Español'], ['fr', 'Français'],
    ['ar', 'العربية'], ['bn', 'বাংলা'], ['pt_BR', 'Português'], ['ru', 'Русский'], ['ja', '日本語'],
    ['de', 'Deutsch'], ['it', 'Italiano']
  ],
  RTL: ['ar'],
  add(lang, dict) { this.dicts[lang] = dict; },

  /** Sceglie la lingua: preferenza salvata, altrimenti quella del browser, altrimenti inglese. */
  pick(pref, uiLang) {
    const codes = this.LANGS.map((l) => l[0]);
    if (pref && codes.includes(pref)) return pref;
    const ui = String(uiLang || 'en').replace('-', '_');
    if (codes.includes(ui)) return ui;
    const base = ui.split('_')[0];
    if (base === 'zh') return 'zh_CN';
    if (base === 'pt') return 'pt_BR';
    return codes.includes(base) ? base : 'en';
  },

  set(lang) {
    this.lang = this.dicts[lang] ? lang : 'en';
    if (typeof document !== 'undefined') {
      document.documentElement.lang = this.lang.replace('_', '-');
      document.documentElement.dir = this.RTL.includes(this.lang) ? 'rtl' : 'ltr';
    }
  }
};

function t(key, ...args) {
  const d = I18N.dicts[I18N.lang] || {};
  const en = I18N.dicts.en || {};
  const s = d[key] !== undefined ? d[key] : (en[key] !== undefined ? en[key] : key);
  return String(s).replace(/\{(\d)\}/g, (_, i) => (args[i] !== undefined && args[i] !== null ? args[i] : ''));
}

/** Nome visualizzato di una categoria (gli id interni restano invariati). */
function catLabel(id) {
  const k = 'cat.' + id;
  const s = t(k);
  return s === k ? id : s;
}

/** Applica le traduzioni agli elementi statici con data-i18n / data-i18n-title. */
function applyStaticI18n(root) {
  (root || document).querySelectorAll('[data-i18n]').forEach((e) => { e.textContent = t(e.dataset.i18n); });
  (root || document).querySelectorAll('[data-i18n-title]').forEach((e) => { e.title = t(e.dataset.i18nTitle); });
}

if (typeof module !== 'undefined') module.exports = { I18N, t, catLabel };
