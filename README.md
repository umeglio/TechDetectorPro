# Tech Detector Pro

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-2.1.1-green.svg)
![Manifest](https://img.shields.io/badge/manifest-v3-orange.svg)
![Chrome](https://img.shields.io/badge/Chrome%20%2F%20Edge-116%2B-brightgreen.svg)

<p align="center"><img src="icons/icon128.png" alt="Tech Detector Pro" width="96"></p>

**🇮🇹 [Italiano](#-italiano) · 🇬🇧 [English](#-english)**

---

## 🇮🇹 Italiano

Estensione per Chrome/Edge che analizza il sito aperto e mostra **quali tecnologie usa, quale software gira sul server (con versione), come è configurato e quali componenti sono obsoleti o esposti a CVE note**. Tutta l'analisi avviene nel browser: nessun dato viene inviato a terzi.

### Screenshot
<p align="center">
  <img src="screenshots/tech-tab.png" alt="Tecnologie / Technologies" width="230">
  <img src="screenshots/server-tab.png" alt="Server" width="230">
  <img src="screenshots/security-tab.png" alt="Sicurezza / Security" width="230">
  <img src="screenshots/headers-tab.png" alt="Header / Headers" width="230">
</p>

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

### Come individua la versione di PHP (2.1)
Nella maggior parte dei siti la versione di PHP **non è dichiarata** (`expose_php = Off`, oppure un proxy o CDN rimuove `X-Powered-By`). Per questo l'estensione la cerca a più livelli e indica sempre **fonte** e **affidabilità**:

| Livello | Tecnica | Affidabilità |
|---|---|---|
| 1 · automatico | `X-Powered-By` sulle risposte generate da PHP: URL con cache-buster per saltare la cache del CDN, `/index.php`, uno script `.php` inesistente (con nginx + PHP-FPM la pagina "File not found." la produce PHP), endpoint del CMS (`wp-login.php`, `xmlrpc.php`, `/user/login`…) | certa |
| 2 · su richiesta | Pulsante **🔎 Ricerca approfondita**: pagine `phpinfo()` dimenticate (`info.php`, `phpinfo.php`, `test.php`…), file Composer esposti (`composer.lock`, `vendor/composer/platform_check.php`), easter egg dei PHP < 5.5 | certa / probabile / minimo |
| 3 · stima | Pacchetto Apache/nginx della distribuzione → PHP di default (es. `Apache/2.4.52 (Ubuntu)` = Ubuntu 22.04 = PHP 8.1) | stima |
| 4 · minimo | Requisito del CMS/framework (es. Laravel 11 → PHP ≥ 8.2, Drupal 11 → PHP ≥ 8.3) | minimo |

Se il sito è chiaramente costruito su un altro backend (Next.js/Nuxt → Node.js, ASP.NET, Java, Django, Rails, siti statici) l'estensione mostra **"PHP non utilizzato"** con il backend reale, invece di cercare una versione che non esiste.

Le stime non producono avvisi CVE "critici" come se fossero certe. La ricerca approfondita fa circa 20 richieste al sito: usala su siti tuoi o per cui hai l'autorizzazione.

<p align="center"><img src="screenshots/php-detection.png" alt="Versione PHP" width="360"></p>

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
├── phpprobe.js     individuazione della versione PHP (4 livelli)
├── popup.html/css/js  interfaccia
└── icons/          16, 32, 48, 128 px
```

### Contribuire
Le pull request sono benvenute, in particolare per nuove regole in `VULN_RULES` (indicare sempre fonte e CVE).

---

## 🇬🇧 English

A Chrome/Edge extension that inspects the current website and shows **which technologies it uses, which server software (and version) runs behind it, how it is configured and which components are outdated or affected by known CVEs**. Everything runs locally in the browser; no data is sent anywhere.

### Screenshots
<p align="center">
  <img src="screenshots/tech-tab.png" alt="Tecnologie / Technologies" width="230">
  <img src="screenshots/server-tab.png" alt="Server" width="230">
  <img src="screenshots/security-tab.png" alt="Sicurezza / Security" width="230">
  <img src="screenshots/headers-tab.png" alt="Header / Headers" width="230">
</p>

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

### How the PHP version is found (2.1)
Most sites **hide** the PHP version (`expose_php = Off`, or a proxy/CDN strips `X-Powered-By`). The extension therefore searches in layers and always reports **source** and **confidence**:

| Layer | Technique | Confidence |
|---|---|---|
| 1 · automatic | `X-Powered-By` on PHP-generated responses: cache-busted URL to bypass the CDN, `/index.php`, a non-existent `.php` script (with nginx + PHP-FPM the "File not found." page is produced by PHP), CMS endpoints (`wp-login.php`, `xmlrpc.php`, `/user/login`…) | certain |
| 2 · on demand | **🔎 Deep search** button: forgotten `phpinfo()` pages, exposed Composer files (`composer.lock`, `vendor/composer/platform_check.php`), PHP < 5.5 easter egg | certain / probable / minimum |
| 3 · estimate | Distribution Apache/nginx package → default PHP (e.g. `Apache/2.4.52 (Ubuntu)` = Ubuntu 22.04 = PHP 8.1) | estimate |
| 4 · minimum | CMS/framework requirement (e.g. Laravel 11 → PHP ≥ 8.2, Drupal 11 → PHP ≥ 8.3) | minimum |

If the site clearly runs on another backend (Next.js/Nuxt → Node.js, ASP.NET, Java, Django, Rails, static sites) the extension shows **"PHP not used"** with the real backend instead of searching for a version that does not exist.

Estimates never raise "critical" CVE warnings as if they were certain. Deep search sends about 20 requests to the site: use it only on sites you own or are authorised to test.

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
