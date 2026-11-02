#!/usr/bin/env sh
# =============================================================================
# build-icons.sh - genera icons/icon{16,32,48,128}.png da icons/icon.svg
# Usa il primo convertitore disponibile: rsvg-convert, Inkscape o ImageMagick.
# Nessuna dipendenza da Python o Node.js.
#
# Autore: Umberto Meglio - Supporto alla creazione: Claude di Anthropic
# =============================================================================
set -eu
cd "$(dirname "$0")/../icons"
for s in 16 32 48 128; do
  if command -v rsvg-convert >/dev/null 2>&1; then
    rsvg-convert -w "$s" -h "$s" icon.svg -o "icon$s.png"
  elif command -v inkscape >/dev/null 2>&1; then
    inkscape icon.svg -w "$s" -h "$s" -o "icon$s.png" >/dev/null 2>&1
  elif command -v magick >/dev/null 2>&1; then
    magick -background none -density 384 icon.svg -resize "${s}x${s}" "icon$s.png"
  elif command -v convert >/dev/null 2>&1; then
    convert -background none -density 384 icon.svg -resize "${s}x${s}" "icon$s.png"
  else
    echo "Serve uno tra: rsvg-convert (librsvg), inkscape, ImageMagick" >&2; exit 1
  fi
  echo "icons/icon$s.png"
done
