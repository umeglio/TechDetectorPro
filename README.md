# Tech Detector Pro

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-2.0.0-green.svg)
![Manifest](https://img.shields.io/badge/manifest-v3-orange.svg)
![Chrome](https://img.shields.io/badge/Chrome%20%2F%20Edge-116%2B-brightgreen.svg)

<p align="center"><img src="icons/icon128.png" alt="Tech Detector Pro" width="96"></p>

**🇮🇹 [Italiano](#-italiano) · 🇬🇧 [English](#-english)**

---

## 🇮🇹 Italiano

Estensione per Chrome/Edge che analizza il sito aperto e mostra **quali tecnologie usa, quale software gira sul server (con versione), come è configurato e quali componenti sono obsoleti o esposti a CVE note**. Tutta l'analisi avviene nel browser: nessun dato viene inviato a terzi.

<p align="center"><img src="screenshots/security-tab.png" alt="Scheda Sicurezza" width="420"></p>

### Novità della versione 2.0
| Area | Cosa fa |
|---|---|
| **Header HTTP** | Un service worker cattura gli header della risposta principale: `Server`, `X-Powered-By`, `X-AspNet-Version`, `Via`, cookie, cache… |
| **Versioni backend** | Legge versione di **Apache, nginx, IIS, LiteSpeed, Tomcat, PHP, OpenSSL, ASP.NET**, moduli Apache e sistema operativo dichiarato nel banner |
| **Server** | IP del server, stato HTTP, protocollo (HTTP/1.1, HTTP/2, HTTP/3), compressione, cache/CDN, TTFB, tempi di caricamento, charset, doctype, cookie |
| **Versioni frontend** | Versioni reali lette dalle variabili globali: jQuery, jQuery UI, Bootstrap, AngularJS/Angular, React, Vue, Next.js, Lodash, Moment, Handlebars, DOMPurify, Axios, TinyMCE, CKEditor, WordPress… |
| **Sicurezza** | Voto A–F sugli header (HSTS, CSP, X-Content-Type-Options, clickjacking, Referrer-Policy, Permissions-Policy, COOP, CORS), flag dei cookie, contenuti misti, SRI, banner che rivelano versioni |
| **CVE / EOL** | Base dati locale che segnala componenti fuori supporto o con CVE note, con link al NIST NVD |
| **Export** | Report JSON scaricabile o testo copiato negli appunti |
| **UI** | Quattro schede (Tecnologie, Server, Sicurezza, Header), tema chiaro/scuro automatico, icone corrette 16/32/48/128 px |

Restano attivi tutti i rilevamenti precedenti su DOM e script: CMS, framework JS, librerie, CSS framework, analytics, tag manager, advertising, CDN, PaaS, static site generator, PWA, font.

### Installazione
1. `git clone https://github.com/umeglio/TechDetectorPro.git`
2. Apri `chrome://extensions` (o `edge://extensions`) e attiva la **Modalità sviluppatore**
3. **Carica estensione non pacchettizzata** e seleziona la cartella del repository
4. Ricarica le schede già aperte: gli header vengono catturati durante la navigazione

### Utilizzo
Apri un sito e clicca sull'icona. Il badge rosso sulla scheda **Sicurezza** indica quanti componenti vanno aggiornati; nella scheda **Tecnologie** sono marcati con *⚠ da aggiornare*.

### Permessi richiesti
| Permesso | Motivo |
|---|---|
| `activeTab`, `scripting` | Analisi del DOM della scheda attiva |
| `webRequest` | Lettura (solo osservazione) degli header della risposta principale |
| `storage` | Memoria di sessione degli header per scheda (cancellata alla chiusura) |
| `http://*/*`, `https://*/*` | Necessario per leggere header e IP di qualsiasi sito |

### Limiti
- Si vede solo ciò che il server dichiara: se `Server` o `X-Powered-By` sono nascosti, la versione non è rilevabile.
- Le distribuzioni Linux (Debian, Ubuntu, RHEL) applicano **backport** delle patch senza cambiare il numero di versione: un avviso CVE è un indizio da verificare sul server, non una prova.
- Il database CVE è statico (aggiornato a novembre 2026) e va mantenuto in `analyzer.js` → `VULN_RULES`.

### Struttura
```
├── manifest.json   configurazione MV3
├── background.js   service worker: cattura header, IP e stato HTTP
├── detector.js     rilevamento tecnologie da DOM/script (eseguito nella pagina)
├── pageinfo.js     versioni librerie, performance, cookie, SRI (eseguito nella pagina)
├── analyzer.js     analisi header, audit sicurezza, regole CVE/EOL
├── popup.html/css/js  interfaccia
└── icons/          16, 32, 48, 128 px
```

### Contribuire
Le pull request sono benvenute, in particolare per nuove regole in `VULN_RULES` (indicare sempre fonte e CVE).

---

## 🇬🇧 English

A Chrome/Edge extension that inspects the current website and shows **which technologies it uses, which server software (and version) runs behind it, how it is configured and which components are outdated or affected by known CVEs**. Everything runs locally in the browser; no data is sent anywhere.

### What's new in 2.0
| Area | What it does |
|---|---|
| **HTTP headers** | A service worker captures the main document response headers: `Server`, `X-Powered-By`, `X-AspNet-Version`, `Via`, cookies, cache… |
| **Backend versions** | Detects **Apache, nginx, IIS, LiteSpeed, Tomcat, PHP, OpenSSL, ASP.NET** versions, Apache modules and the OS advertised in the banner |
| **Server** | Server IP, HTTP status, protocol (HTTP/1.1, HTTP/2, HTTP/3), compression, cache/CDN, TTFB, load time, charset, doctype, cookies |
| **Frontend versions** | Real versions read from globals: jQuery, jQuery UI, Bootstrap, AngularJS/Angular, React, Vue, Next.js, Lodash, Moment, Handlebars, DOMPurify, Axios, TinyMCE, CKEditor, WordPress… |
| **Security** | A–F grade on headers (HSTS, CSP, X-Content-Type-Options, clickjacking, Referrer-Policy, Permissions-Policy, COOP, CORS), cookie flags, mixed content, SRI, version-leaking banners |
| **CVE / EOL** | Local rule set that flags end-of-life components or versions with known CVEs, linking to NIST NVD |
| **Export** | Downloadable JSON report or plain-text copy to clipboard |
| **UI** | Four tabs (Technologies, Server, Security, Headers), automatic light/dark theme, proper 16/32/48/128 px icons |

All previous DOM/script detections are kept: CMS, JS frameworks, libraries, CSS frameworks, analytics, tag managers, ads, CDN, PaaS, static site generators, PWA, fonts.

### Installation
1. `git clone https://github.com/umeglio/TechDetectorPro.git`
2. Open `chrome://extensions` (or `edge://extensions`) and enable **Developer mode**
3. Click **Load unpacked** and select the repository folder
4. Reload already-open tabs: headers are captured during navigation

### Permissions
| Permission | Why |
|---|---|
| `activeTab`, `scripting` | Inspect the active tab's DOM |
| `webRequest` | Observe (read-only) main document response headers |
| `storage` | Per-tab session storage of headers (cleared when the tab closes) |
| `http://*/*`, `https://*/*` | Required to read headers and IP for any site |

### Limitations
- Only what the server discloses can be detected: hidden `Server`/`X-Powered-By` means no version.
- Linux distributions **backport** security fixes without bumping the version string: a CVE warning is a lead to verify on the server, not proof.
- The CVE rule set is static (updated November 2026) and lives in `analyzer.js` → `VULN_RULES`.

### License
MIT — see [LICENSE](LICENSE).

**Author:** Umberto Meglio · built with the support of Claude by Anthropic
