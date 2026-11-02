/*
 * Tech Detector Pro - raccolta informazioni lato pagina
 * Autore: Umberto Meglio - Supporto alla creazione: Claude di Anthropic
 *
 * Eseguita nel MAIN world della pagina per poter leggere le variabili globali
 * delle librerie (window.jQuery, window.angular, ...) e le loro versioni.
 */
function collectPageInfo() {
  'use strict';
  const safe = (fn) => { try { return fn(); } catch (e) { return null; } };
  const nav = safe(() => performance.getEntriesByType('navigation')[0]) || {};
  const meta = (n) => safe(() => document.querySelector(`meta[name="${n}" i]`).content) || null;

  const libs = {};
  const put = (k, v) => { if (v && typeof v === 'string') libs[k] = v; };
  put('jQuery', safe(() => window.jQuery.fn.jquery));
  put('jQuery UI', safe(() => window.jQuery.ui.version));
  put('jQuery Migrate', safe(() => window.jQuery.migrateVersion));
  put('AngularJS', safe(() => window.angular.version.full));
  put('Angular', safe(() => document.querySelector('[ng-version]').getAttribute('ng-version')));
  put('React', safe(() => window.React.version));
  put('Vue.js', safe(() => window.Vue.version));
  put('Next.js', safe(() => window.next.version));
  put('Nuxt', safe(() => window.__NUXT__ && window.$nuxt && window.$nuxt.$nuxt && window.$nuxt.$nuxt.version));
  put('Svelte', safe(() => window.__svelte && Object.keys(window.__svelte.v || {})[0]));
  put('Bootstrap', safe(() => (window.bootstrap && window.bootstrap.Tooltip && window.bootstrap.Tooltip.VERSION) ||
    window.jQuery.fn.tooltip.Constructor.VERSION));
  put(safe(() => window._.flatMapDeep) ? 'Lodash' : 'Underscore.js', safe(() => window._.VERSION));
  put('Moment.js', safe(() => window.moment.version));
  put('Handlebars', safe(() => window.Handlebars.VERSION));
  put('D3.js', safe(() => window.d3.version));
  put('Three.js', safe(() => window.THREE.REVISION && 'r' + window.THREE.REVISION));
  put('Chart.js', safe(() => window.Chart.version));
  put('GSAP', safe(() => window.gsap.version));
  put('Axios', safe(() => window.axios.VERSION));
  put('DOMPurify', safe(() => window.DOMPurify.version));
  put('Prototype', safe(() => window.Prototype.Version));
  put('MooTools', safe(() => window.MooTools.version));
  put('Dojo', safe(() => window.dojo.version.toString()));
  put('Ember.js', safe(() => window.Ember.VERSION));
  put('Backbone.js', safe(() => window.Backbone.VERSION));
  put('Knockout', safe(() => window.ko.version));
  put('Alpine.js', safe(() => window.Alpine.version));
  put('Socket.io', safe(() => window.io.version));
  put('Swiper', safe(() => window.Swiper.version));
  put('TinyMCE', safe(() => window.tinymce.majorVersion + '.' + window.tinymce.minorVersion));
  put('CKEditor', safe(() => (window.CKEDITOR && window.CKEDITOR.version) || window.CKEDITOR_VERSION));

  // versione WordPress dai parametri ?ver= degli asset core
  const generator = meta('generator');
  const wpVer = safe(() => {
    const m = (generator || '').match(/WordPress\s+([\d.]+)/i);
    if (m) return m[1];
    const s = document.querySelector('link[href*="/wp-includes/"][href*="ver="], script[src*="/wp-includes/"][src*="ver="]');
    return s ? (s.href || s.src).match(/ver=([\d.]+)/)[1] : null;
  });
  if (wpVer) libs['WordPress'] = wpVer;

  const externalScripts = Array.from(document.scripts).filter((s) => s.src);
  const crossOrigin = externalScripts.filter((s) => safe(() => new URL(s.src).origin !== location.origin));
  const mixed = location.protocol === 'https:'
    ? Array.from(document.querySelectorAll('script[src^="http:"], link[href^="http:"][rel~="stylesheet"], img[src^="http:"], iframe[src^="http:"]')).length
    : 0;

  return {
    url: location.href,
    protocol: nav.nextHopProtocol || null,
    transferSize: nav.transferSize || null,
    encodedBodySize: nav.encodedBodySize || null,
    ttfb: nav.responseStart ? Math.round(nav.responseStart - nav.requestStart) : null,
    loadTime: nav.loadEventEnd ? Math.round(nav.loadEventEnd) : null,
    domNodes: document.getElementsByTagName('*').length,
    charset: document.characterSet,
    doctype: document.doctype ? (document.doctype.name + (document.doctype.publicId ? ' ' + document.doctype.publicId : '')) : 'assente',
    renderMode: document.compatMode === 'CSS1Compat' ? 'standard' : 'quirks',
    lang: document.documentElement.lang || null,
    lastModified: document.lastModified,
    generator,
    isSecureContext: window.isSecureContext,
    cookieNames: safe(() => document.cookie.split(';').map((c) => c.split('=')[0].trim()).filter(Boolean)) || [],
    scripts: document.scripts.length,
    externalScripts: externalScripts.length,
    crossOriginScripts: crossOrigin.length,
    crossOriginWithoutSRI: crossOrigin.filter((s) => !s.integrity).length,
    mixedContent: mixed,
    serviceWorker: !!(navigator.serviceWorker && navigator.serviceWorker.controller),
    libs
  };
}
