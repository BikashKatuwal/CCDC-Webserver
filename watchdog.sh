#!/usr/bin/env bash
# ccdc-watchdog: keep scored services alive on an UNKNOWN Linux box.
# Needs: bash, systemd, root. Usage:
#   watchdog.sh install        copy to /opt/ccdc and start a 60s systemd timer
#   watchdog.sh run [--dry-run]   one check pass (the timer calls this)
#   watchdog.sh status         what it watches, up/down, ports, last log lines
#   watchdog.sh pause [min]    stop acting for N minutes (default 30, auto-expires)
#   watchdog.sh resume         start acting again
#   watchdog.sh forget <svc>   stop expecting a service (you removed it on purpose)
#   watchdog.sh uninstall
# Optional config (root-owned): /etc/ccdc/watchdog.conf
#   EXTRA="svc1 svc2"      extra unit names to watch
#   EXCLUDE="svc3"         never touch these
#   NOPORTCHECK="dovecot"  skip the port check for these
#   PORT_CHECK=0           disable port checks entirely

set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}

DIR=/opt/ccdc
STATE=/var/lib/ccdc
LOGDIR=/var/log/ccdc
LOG=$LOGDIR/watchdog.log
PAUSE=$DIR/pause
CONF=/etc/ccdc/watchdog.conf
EXPECTED=$STATE/watchdog.expected
RESTARTS=$STATE/watchdog.restarts
LOCK=/run/ccdc-watchdog.lock

CANDIDATES="postfix dovecot ssh sshd apache2 httpd nginx mariadb mysql mysqld postgresql rsyslog"
EXTRA=""
EXCLUDE=""
NOPORTCHECK=""
PORT_CHECK=1
FLAP_COUNT=3        # this many restarts...
FLAP_WINDOW=600     # ...within this many seconds = FLAPPING alert
PAUSE_MAX_MIN=30    # a forgotten pause file stops working after this
DRY=0

if [ -r "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ]; then . "$CONF"; fi

log() {
  if [ "$DRY" = 1 ]; then echo "[dry-run] $*"; return; fi
  echo "$(date '+%F %T') $*" >> "$LOG"
  logger -t ccdc-watchdog -- "$*" 2>/dev/null
}

loaded() { [ "$(systemctl show -p LoadState --value "$1.service" 2>/dev/null)" = loaded ]; }
canon()  { local id; id=$(systemctl show -p Id --value "$1.service" 2>/dev/null); echo "${id%.service}"; }
phpfpm() { systemctl list-unit-files 'php*-fpm.service' --no-legend 2>/dev/null | awk '{sub(/\.service$/,"",$1); print $1}'; }

# Services to watch: installed AND (enabled OR currently running OR seen running before).
discover() {
  local u c en
  for u in $CANDIDATES $EXTRA $(phpfpm); do
    loaded "$u" || continue
    c=$(canon "$u"); [ -n "$c" ] || continue
    case " $EXCLUDE " in *" $c "*|*" $u "*) continue ;; esac
    en=$(systemctl is-enabled "$c" 2>/dev/null)
    if [ "$en" = enabled ] || systemctl is-active --quiet "$c" || grep -qxF "$c" "$EXPECTED" 2>/dev/null; then
      echo "$c"
    fi
  done | sort -u
}

is_up() {
  case $1 in
    postfix) postfix status >/dev/null 2>&1 ;;   # systemd says "active (exited)" even when master is dead
    *) systemctl is-active --quiet "$1" ;;
  esac
}

want_ports() {
  [ "$PORT_CHECK" = 1 ] || return 0
  case " $NOPORTCHECK " in *" $1 "*) return 0 ;; esac
  case $1 in
    postfix) echo 25 ;;
    dovecot) echo "143 993 110 995" ;;
    ssh|sshd) local p; p=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | tr '\n' ' '); echo "${p:-22}" ;;
    apache2|httpd|nginx) echo "80 443 8080" ;;
    *) ;;
  esac
}

listening() {  # true if ANY given port has a listener
  local p out; out=$(ss -ltn 2>/dev/null | tail -n +2 | awk '{print $4}')
  for p in "$@"; do echo "$out" | grep -Eq "[:.]$p$" && return 0; done
  return 1
}

cfg_test() {
  case $1 in
    postfix) postfix check ;;
    dovecot) doveconf -n >/dev/null ;;
    ssh|sshd) sshd -t ;;
    apache2) apache2ctl -t ;;
    httpd) apachectl -t ;;
    nginx) nginx -t ;;
    *) true ;;
  esac
}

do_restart() {
  case $1 in
    postfix) systemctl restart 'postfix@-.service' 2>/dev/null || postfix start 2>/dev/null || systemctl restart postfix ;;
    *) systemctl restart "$1" ;;
  esac
}

recent() {
  awk -v s="$1" -v n="$(date +%s)" -v w="$FLAP_WINDOW" '$2==s && n-$1<=w' "$RESTARTS" 2>/dev/null | wc -l
}

fix() {  # fix <service> <down|noport>
  local s=$1 why=$2 out rc n
  out=$(cfg_test "$s" 2>&1); rc=$?
  if [ $rc -ne 0 ]; then
    log "CONFIG-PROBLEM $s ($why): $(echo "$out" | head -2 | tr '\n' ' ')"
    # A running-but-silent service with a bad config: do not restart, it may not come back.
    [ "$why" = noport ] && return
  fi
  if [ "$DRY" = 1 ]; then log "would restart $s ($why)"; return; fi
  n=$(recent "$s")
  systemctl reset-failed "$s" 2>/dev/null
  do_restart "$s" >/dev/null 2>&1
  sleep 3
  echo "$(date +%s) $s" >> "$RESTARTS"
  tail -n 200 "$RESTARTS" > "$RESTARTS.tmp" 2>/dev/null && mv "$RESTARTS.tmp" "$RESTARTS"
  if is_up "$s"; then
    log "RESTARTED $s ($why)"
  else
    log "RESTART-FAILED $s ($why): $(journalctl -u "$s" -n 3 --no-pager -o cat 2>/dev/null | tr '\n' ' ')"
  fi
  if [ "$n" -ge $((FLAP_COUNT - 1)) ]; then
    log "FLAPPING $s: $((n + 1)) restarts in ${FLAP_WINDOW}s - find the cause, consider an incident report"
  fi
}

paused() {
  [ -e "$PAUSE" ] || return 1
  local max age
  max=$(cat "$PAUSE" 2>/dev/null)
  case $max in ''|*[!0-9]*) max=$PAUSE_MAX_MIN ;; esac
  age=$(( ( $(date +%s) - $(stat -c %Y "$PAUSE") ) / 60 ))
  if [ "$age" -ge "$max" ]; then
    log "PAUSE expired after ${age}m, watchdog active again"
    rm -f "$PAUSE"
    return 1
  fi
  return 0
}

run() {
  mkdir -p "$STATE" "$LOGDIR"; touch "$EXPECTED" "$RESTARTS"
  paused && exit 0
  exec 9>"$LOCK"; flock -n 9 || exit 0
  local s ports m
  for s in $(discover); do
    if ! is_up "$s"; then fix "$s" down; continue; fi
    grep -qxF "$s" "$EXPECTED" 2>/dev/null || echo "$s" >> "$EXPECTED"
    ports=$(want_ports "$s")
    [ -n "$ports" ] || continue
    if listening $ports; then
      rm -f "$STATE/miss.$s"
    else
      m=$(( $(cat "$STATE/miss.$s" 2>/dev/null || echo 0) + 1 ))
      echo "$m" > "$STATE/miss.$s"
      if [ "$m" -ge 2 ]; then fix "$s" noport; rm -f "$STATE/miss.$s"; fi   # 2 misses in a row = real
    fi
  done
}

status() {
  echo "== watchdog status $(date '+%F %T') =="
  if [ -e "$PAUSE" ]; then echo "PAUSED ($PAUSE)"; else echo "active"; fi
  local s st p pl
  for s in $(discover); do
    if is_up "$s"; then st=UP; else st=DOWN; fi
    p=$(want_ports "$s"); pl=""
    if [ -n "$p" ]; then if listening $p; then pl="port ok"; else pl="port MISSING ($p)"; fi; fi
    printf '%-14s %-5s %s\n' "$s" "$st" "$pl"
  done
  echo "timer: $(systemctl is-active ccdc-watchdog.timer 2>/dev/null)"
  echo "-- last log lines --"; tail -n 10 "$LOG" 2>/dev/null
}

install_self() {
  command -v systemctl >/dev/null || { echo "systemd required"; exit 1; }
  mkdir -p "$DIR" "$STATE" "$LOGDIR"
  [ "$(readlink -f "$0")" = "$DIR/watchdog.sh" ] || cp "$0" "$DIR/watchdog.sh"
  chown root:root "$DIR/watchdog.sh"; chmod 700 "$DIR/watchdog.sh"
  cat > /etc/systemd/system/ccdc-watchdog.service <<EOF
[Unit]
Description=CCDC watchdog pass
[Service]
Type=oneshot
TimeoutStartSec=50
ExecStart=$DIR/watchdog.sh run
EOF
  cat > /etc/systemd/system/ccdc-watchdog.timer <<EOF
[Unit]
Description=CCDC watchdog every minute
[Timer]
OnBootSec=60
OnUnitActiveSec=60
AccuracySec=5s
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now ccdc-watchdog.timer
  echo "installed. check with: sudo $DIR/watchdog.sh status"
}

uninstall_self() {
  systemctl disable --now ccdc-watchdog.timer 2>/dev/null
  rm -f /etc/systemd/system/ccdc-watchdog.service /etc/systemd/system/ccdc-watchdog.timer
  systemctl daemon-reload
  echo "removed timer. Files in $DIR and $LOGDIR left in place."
}

[ "$(id -u)" = 0 ] || { echo "run as root: sudo $0 $*"; exit 1; }
for a in "$@"; do [ "$a" = --dry-run ] && DRY=1; done

case "${1:-run}" in
  run)       run ;;
  status)    status ;;
  install)   install_self ;;
  uninstall) uninstall_self ;;
  pause)     mkdir -p "$DIR"; echo "${2:-$PAUSE_MAX_MIN}" > "$PAUSE"; echo "paused for ${2:-$PAUSE_MAX_MIN} min" ;;
  resume)    rm -f "$PAUSE"; echo "resumed" ;;
  forget)    [ -n "${2:-}" ] || { echo "usage: forget <service>"; exit 1; }
             sed -i "/^$2\$/d" "$EXPECTED" 2>/dev/null; echo "forgot $2 (if it is still enabled, add it to EXCLUDE in $CONF)" ;;
  *)         sed -n '2,15p' "$0" ;;
esac
