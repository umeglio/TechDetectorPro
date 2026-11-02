/*
 * Tech Detector Pro - service worker
 * Autore: Umberto Meglio - Supporto alla creazione: Claude di Anthropic
 *
 * Cattura gli header HTTP della risposta principale (main_frame) di ogni scheda,
 * insieme a IP del server, codice di stato e URL finale. I dati restano nel
 * browser (chrome.storage.session) e vengono letti dal popup.
 */
'use strict';

const KEY = (tabId) => `tab_${tabId}`;

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const headers = (details.responseHeaders || []).map((h) => ({
      name: h.name.toLowerCase(),
      value: h.value || ''
    }));
    chrome.storage.session.set({
      [KEY(details.tabId)]: {
        url: details.url,
        ip: details.ip || null,
        statusCode: details.statusCode,
        statusLine: details.statusLine || '',
        fromCache: !!details.fromCache,
        headers,
        capturedAt: Date.now()
      }
    }).catch(() => {});
  },
  { urls: ['http://*/*', 'https://*/*'], types: ['main_frame'] },
  ['responseHeaders', 'extraHeaders']
);

// l'IP è disponibile in modo affidabile solo a richiesta completata
chrome.webRequest.onCompleted.addListener(
  async (details) => {
    if (details.tabId < 0 || !details.ip) return;
    const k = KEY(details.tabId);
    const data = (await chrome.storage.session.get(k))[k];
    if (data && data.url === details.url) {
      data.ip = details.ip;
      chrome.storage.session.set({ [k]: data }).catch(() => {});
    }
  },
  { urls: ['http://*/*', 'https://*/*'], types: ['main_frame'] }
);

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove(KEY(tabId)).catch(() => {});
});
