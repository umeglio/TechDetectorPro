#!/usr/bin/env bash
# =============================================================================
# php-exposure-scan.sh - verifica REMOTA e non invasiva di uno o più siti:
# legge la versione PHP esposta negli header e la confronta con le soglie
# PHP2Shell (CVE-2026-109618/109619/115560). Utile per riscontrare le
# segnalazioni CSIRT ("ricerche passive") prima di intervenire sui server.
#
# Autore: Umberto Meglio - Supporto alla creazione: Claude di Anthropic
#
# Uso:  ./php-exposure-scan.sh https://sito1.it https://sito2.it
#       ./php-exposure-scan.sh -f elenco-url.txt
# Richieste per sito: 3 GET (pagina con cache-buster, /index.php, script .php inesistente).
# Usare solo su sistemi propri o per cui si è autorizzati.
# =============================================================================
set -u
declare -A FIXED=( [8.5]=8.5.12 [8.4]=8.4.27 [8.3]=8.3.36 [8.2]=8.2.35 )
vlt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ]; }
URLS=()
if [ "${1:-}" = "-f" ]; then mapfile -t URLS < <(grep -vE '^\s*(#|$)' "$2"); else URLS=("$@"); fi
[ ${#URLS[@]} -eq 0 ] && { echo "uso: $0 URL... | -f file"; exit 2; }
[ -t 1 ] && { R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; N=$'\e[0m'; } || { R=; G=; Y=; N=; }
UA="Mozilla/5.0 (compatible; php-exposure-scan)"
RC=0
printf '%-45s %-28s %-12s %s\n' "SITO" "SERVER" "PHP" "ESITO"
for u in "${URLS[@]}"; do
  base=$(echo "$u" | grep -oE '^https?://[^/]+')
  rnd=$RANDOM$RANDOM
  hdrs=""
  for t in "$u$( [[ $u == *\?* ]] && echo '&' || echo '?')_s=$rnd" "$base/index.php" "$base/x$rnd.php"; do
    hdrs+=$(curl -s -k -o /dev/null -D - -m 10 -A "$UA" "$t" 2>/dev/null)$'\n'
  done
  server=$(echo "$hdrs" | grep -i '^server:' | head -1 | cut -d' ' -f2- | tr -d '\r')
  php=$(echo "$hdrs" | grep -ioE 'PHP/[0-9]+\.[0-9]+\.[0-9]+' | head -1 | cut -d/ -f2)
  sess=$(echo "$hdrs" | grep -ic 'set-cookie:.*PHPSESSID')
  if [ -n "$php" ]; then
    br=${php%.*}
    if [ -n "${FIXED[$br]:-}" ]; then
      if vlt "$php" "${FIXED[$br]}"; then esito="${R}VULNERABILE (aggiornare a ${FIXED[$br]})${N}"; RC=1
      else esito="${G}aggiornata${N} (resta da applicare upload_progress=0)"; fi
    else esito="${R}ramo fuori supporto: VULNERABILE salvo backport della distribuzione${N}"; RC=1; fi
    esito+=" ${Y}+ versione esposta: expose_php=Off${N}"
  elif [ "$sess" -gt 0 ]; then php="nascosta"; esito="${Y}PHP presente, versione non esposta: verificare sul server con php-vuln-check.sh${N}"
  else php="-"; esito="nessuna traccia PHP dagli header"; fi
  printf '%-45s %-28s %-12s %s\n' "${u:0:45}" "${server:0:28}" "$php" "$esito"
done
exit $RC
