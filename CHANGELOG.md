# Changelog

Autore: Umberto Meglio · realizzato con il supporto di Claude di Anthropic

## 2.2.1
- Database, cache, linguaggi e web server trovati solo come parola nel testo della pagina vengono scartati (es. "Redis" elencato in una dashboard di monitoraggio).
- Riconoscimento di **miraCACHE** da qualsiasi header (`X-Cache`, `Via`…).
- Richiesta di controllo per i siti catch-all, che non vengono più scambiati per siti PHP.
- Icona sorgente `icons/icon.svg` e script `tools/build-icons.sh` e `tools/build-zip.sh`: nessuna dipendenza da Python.
- README riscritto in italiano e inglese, organizzato per funzione.
- Corretto Google Publisher Tag: "googletag" compare anche in "googletagmanager", quindi ogni sito con Tag Manager risultava avere GPT.
- Screenshot rigenerati con la versione 2.2.1.
- Pagina di presentazione per GitHub Pages (`index.html`, italiano/inglese, tema chiaro/scuro).

## 2.2.0
- Regole di rilevamento basate su prove tecniche: PWA (manifest + service worker attivo), Firebase (SDK reale), Google Analytics (ID reali), Integral Ad Science, Open Graph, Webpack, Next.js.
- Distribuzione Linux stimata dal banner del server, con avviso per le release fuori supporto, e rilevamento delle pagine di default.
- Regole **PHP2Shell**: CVE-2026-109618, CVE-2026-109619, CVE-2026-115560.
- Strumenti `tools/php-exposure-scan.sh` e `tools/php-vuln-check.sh`.

## 2.1.1
- Corretto il falso positivo PHP: prima bastava la parola "php" nella pagina.
- Riconoscimento di Next.js App Router e dei backend non PHP ("PHP non utilizzato").
- Regola CVE-2025-55182 (React2Shell) per Next.js; dettaglio sui motivi di una CSP debole.

## 2.1.0
- Individuazione della versione PHP su quattro livelli, con fonte e affidabilità.

## 2.0.0
- Lettura degli header HTTP tramite service worker: versioni di Apache, nginx, IIS, PHP, OpenSSL, ASP.NET, Tomcat.
- Versioni reali delle librerie JavaScript, voto di sicurezza A–F, regole CVE/EOL.
- Popup a quattro schede con tema chiaro/scuro, export JSON, icone 16/32/48/128.

## 1.0
- Prima versione: rilevamento delle tecnologie dalla pagina.
