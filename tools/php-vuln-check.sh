#!/usr/bin/env bash
# =============================================================================
# php-vuln-check.sh - verifica LOCALE delle installazioni PHP di un server
# rispetto alle vulnerabilità "PHP2Shell" (CVE-2026-109618, CVE-2026-109619,
# CVE-2026-115560) segnalate da CSIRT Italia / ACN.
#
# Autore: Umberto Meglio - Supporto alla creazione: Claude di Anthropic
#
# Uso:   sudo ./php-vuln-check.sh            (report leggibile)
#        sudo ./php-vuln-check.sh --csv      (una riga per binario, per inventari)
# Exit:  0 = nessuna installazione vulnerabile, 1 = almeno una vulnerabile/da verificare
#
# Lo script è in sola lettura: non modifica configurazioni né riavvia servizi.
# =============================================================================
set -u
CSV=0; [ "${1:-}" = "--csv" ] && CSV=1
CVES="CVE-2026-109618 CVE-2026-109619 CVE-2026-115560"
# versioni corrette per ramo (ACN AL07/261021/CSIRT-ITA, php.net, GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp)
# 7.4/8.0/8.1: solo backport minimi in sorgente (branch PHP-x.y-CVE-2026-109618-109619) o patch delle distribuzioni
declare -A FIXED=( [8.5]=8.5.12 [8.4]=8.4.27 [8.3]=8.3.36 [8.2]=8.2.35 )

if [ -t 1 ] && [ $CSV -eq 0 ]; then R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'; else R=; G=; Y=; B=; N=; fi
HOST=$(hostname -f 2>/dev/null || hostname)
WORST=0

vlt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ]; }

# ---- 1. trova tutti i binari PHP (CLI e FPM), anche multi-versione ----------
mapfile -t BINS < <( {
  command -v php php-fpm php-cgi 2>/dev/null
  ls /usr/bin/php[0-9]* /usr/sbin/php-fpm* /usr/bin/php-cgi* 2>/dev/null
  ls /usr/local/bin/php /usr/local/sbin/php-fpm 2>/dev/null
  ls /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm 2>/dev/null       # Remi (RHEL)
  ls /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm 2>/dev/null                    # Plesk
  ls /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/sbin/php-fpm 2>/dev/null  # cPanel
  ls /usr/local/lsws/lsphp*/bin/lsphp /usr/local/lsws/lsphp*/bin/php 2>/dev/null             # LiteSpeed
  ls /opt/bitnami/php/bin/php /opt/bitnami/php/sbin/php-fpm 2>/dev/null
} | xargs -r -n1 readlink -f 2>/dev/null | sort -u )

# ---- 2. backport delle distribuzioni: cerca le CVE nei changelog dei pacchetti
backport_status() {   # $1 = ramo (es. 8.1)
  local hits="" f
  for f in /usr/share/doc/php"$1"-common/changelog.Debian.gz /usr/share/doc/php"$1"-cli/changelog.Debian.gz; do
    [ -r "$f" ] && hits+=$(zgrep -oE 'CVE-2026-(109618|109619|115560)' "$f" 2>/dev/null | sort -u | tr '\n' ' ')
  done
  if command -v rpm >/dev/null 2>&1; then
    hits+=$(rpm -qa 'php*common*' 2>/dev/null | xargs -r rpm -q --changelog 2>/dev/null | grep -oE 'CVE-2026-(109618|109619|115560)' | sort -u | tr '\n' ' ')
  fi
  printf '%s\n' $hits | grep -E '^CVE' | sort -u | paste -sd' ' -
}
# i backport sanano il pacchetto solo se coprono ENTRAMBE le CVE correggibili
has_both() { [[ "$1" == *109618* && "$1" == *109619* ]]; }

ini() { "$1" -n -r 'echo 1;' >/dev/null 2>&1; "$1" -r "echo ini_get('$2');" 2>/dev/null; }
fpm_ini() { "$1" -i 2>/dev/null | awk -F' => ' -v k="$2" '$1==k {print $2; exit}'; }

[ $CSV -eq 1 ] && echo "host;binario;sapi;versione;stato;backport;upload_progress;post_max_size;max_input_nesting_level;expose_php"
[ $CSV -eq 0 ] && echo "${B}== Verifica PHP2Shell su $HOST ($(date '+%Y-%m-%d %H:%M')) ==${N}"
[ ${#BINS[@]} -eq 0 ] && { echo "Nessun binario PHP trovato sull'host."; exit 0; }

declare -A SEEN
for b in "${BINS[@]}"; do
  [ -x "$b" ] || continue
  sapi=cli; case "$b" in *fpm*) sapi=fpm;; *cgi*) sapi=cgi;; *lsphp*) sapi=litespeed;; esac
  ver=$("$b" -v 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  [ -z "$ver" ] && continue
  key="$ver|$sapi|$b"; [ -n "${SEEN[$key]:-}" ] && continue; SEEN[$key]=1
  br=${ver%.*}

  if [ "$sapi" = fpm ]; then
    up=$(fpm_ini "$b" session.upload_progress.enabled); pms=$(fpm_ini "$b" post_max_size)
    nest=$(fpm_ini "$b" max_input_nesting_level); exp=$(fpm_ini "$b" expose_php)
    ser=$(fpm_ini "$b" session.serialize_handler); mem=$(fpm_ini "$b" memory_limit)
  else
    up=$(ini "$b" session.upload_progress.enabled); pms=$(ini "$b" post_max_size)
    nest=$(ini "$b" max_input_nesting_level); exp=$(ini "$b" expose_php)
    ser=$(ini "$b" session.serialize_handler); mem=$(ini "$b" memory_limit)
  fi
  bp=$(backport_status "$br")

  if [ -n "${FIXED[$br]:-}" ] && ! vlt "$ver" "${FIXED[$br]}"; then
    st="AGGIORNATA (>= ${FIXED[$br]})"; lvl=0
  elif has_both "$bp"; then
    st="numero di versione vecchio ma pacchetto con backport di distribuzione per $bp"; lvl=0
  elif [ -n "${FIXED[$br]:-}" ]; then
    st="VULNERABILE (aggiornare a ${FIXED[$br]} o al pacchetto di distribuzione con le patch)"; lvl=2
    [ -n "$bp" ] && st="$st - backport parziale: $bp"
  elif vlt "$br" "8.2"; then
    st="FUORI SUPPORTO senza backport: VULNERABILE (patch minime solo in sorgente per 7.4/8.0/8.1)"; lvl=2
    [ -n "$bp" ] && st="FUORI SUPPORTO, backport parziale: $bp"
  else st="ramo sconosciuto: verificare"; lvl=1; fi
  # CVE-2026-115560 non è sanata dagli aggiornamenti: serve la mitigazione
  upwarn=""; [ "$up" = "1" ] || [ "$up" = "On" ] && upwarn="DA DISABILITARE"
  [ -n "$upwarn" ] && [ $lvl -eq 0 ] && lvl=1

  [ $lvl -gt $WORST ] && WORST=$lvl
  if [ $CSV -eq 1 ]; then
    echo "$HOST;$b;$sapi;$ver;$st;${bp:-};${up:-?};${pms:-?};${nest:-?};${exp:-?}"
  else
    col=$G; [ $lvl -eq 1 ] && col=$Y; [ $lvl -eq 2 ] && col=$R
    echo
    echo "${B}$b${N}  [$sapi]  PHP ${B}$ver${N}"
    echo "  stato ............................ ${col}${st}${N}"
    echo "  session.upload_progress.enabled .. ${up:-?} ${upwarn:+${R}← $upwarn (CVE-2026-115560)${N}}"
    echo "  post_max_size .................... ${pms:-?}  (consigliato ≤ 8M)"
    echo "  max_input_nesting_level .......... ${nest:-?}  (consigliato 4, se compatibile)"
    echo "  expose_php ....................... ${exp:-?}  (consigliato 0/Off)"
    echo "  session.serialize_handler ........ ${ser:-?}  $( [ "${ser:-}" = php_binary ] || [ "${ser:-}" = php_serialize ] && echo "${Y}← con upload_progress attivo e cambio a 'php' via ini_set() = CVE-2026-115560${N}")"
    echo "  memory_limit ..................... ${mem:-?}  (CVE-2026-109618 si innesca con OOM: limitare a livello di container/cgroup)"
    [ "$br" = "8.5" ] && echo "  fatal_error_backtraces ........... $(ini "$b" fatal_error_backtraces)  (consigliato 0)"
  fi
done

# ---- 3. pool PHP-FPM: pm.max_requests -----------------------------------------
if [ $CSV -eq 0 ]; then
  pools=$(ls /etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.d/*.conf /opt/remi/php*/root/etc/php-fpm.d/*.conf 2>/dev/null)
  if [ -n "$pools" ]; then
    echo; echo "${B}Pool PHP-FPM (pm.max_requests, consigliato 50):${N}"
    for p in $pools; do echo "  $p: $(grep -E '^\s*pm\.max_requests' "$p" | tail -1 | sed 's/.*=\s*//' || true)"; done | sed 's/: $/: (non impostato = 0, nessun riciclo)/'
  fi
  # container Docker con PHP
  if command -v docker >/dev/null 2>&1; then
    for c in $(docker ps --format '{{.Names}}' 2>/dev/null); do
      v=$(docker exec "$c" php -r 'echo PHP_VERSION;' 2>/dev/null) && echo "  ${Y}container $c: PHP $v (verificare anche l'immagine)${N}"
    done
  fi
  echo
  case $WORST in
    0) echo "${G}${B}Esito: nessuna installazione vulnerabile rilevata.${N}";;
    1) echo "${Y}${B}Esito: da verificare / mitigazione richiesta (vedi righe gialle).${N}";;
    2) echo "${R}${B}Esito: VULNERABILE. Aggiornare PHP e applicare session.upload_progress.enabled = 0.${N}";;
  esac
  echo "Nota: CVE-2026-115560 NON è sanata da alcuna release: session.upload_progress.enabled = 0 va impostato in php.ini,"
  echo "      nel pool FPM o nella config del web server (non con ini_set() o .user.ini) e i worker vanno riavviati."
  echo "Riferimento: https://www.acn.gov.it/portale/w/php2shell-sanate-vulnerabilita-critiche-in-php"
fi
[ $WORST -eq 0 ]
