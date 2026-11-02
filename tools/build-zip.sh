#!/usr/bin/env sh
# =============================================================================
# build-zip.sh - crea dist/tech-detector-pro-<versione>.zip pronto per il
# Chrome Web Store / Edge Add-ons, con i soli file dell'estensione.
# Nessuna dipendenza oltre a zip (o bsdtar).
#
# Autore: Umberto Meglio - Supporto alla creazione: Claude di Anthropic
# =============================================================================
set -eu
cd "$(dirname "$0")/.."
ver=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' manifest.json | head -1)
out="dist/tech-detector-pro-$ver.zip"
mkdir -p dist && rm -f "$out"
FILES="manifest.json background.js detector.js pageinfo.js analyzer.js phpprobe.js popup.html popup.css popup.js icons/icon16.png icons/icon32.png icons/icon48.png icons/icon128.png LICENSE"
if command -v zip >/dev/null 2>&1; then zip -q -X "$out" $FILES
else bsdtar -a -cf "$out" $FILES; fi
echo "$out"
