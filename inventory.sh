#!/usr/bin/env bash
# ccdc-inventory: READ-ONLY look at an unknown Linux server.
# It changes nothing. It only writes one report file under /var/log/ccdc/.
#   sudo ./inventory.sh            short summary on screen, full report in a file
#   sudo ./inventory.sh --print    print the full report on screen
# "[FLAG]" means "worth a look", NOT "this is an attack". A fresh install shows some.

set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}
umask 077

OUTDIR=/var/log/ccdc
PRINT=0
[ "${1:-}" = --print ] && PRINT=1
[ "${1:-}" = -h ] && { sed -n '2,7p' "$0"; exit 0; }
[ "$(id -u)" = 0 ] || { echo "run as root: sudo $0"; exit 1; }
mkdir -p "$OUTDIR"
REPORT=$OUTDIR/inventory-$(date +%Y%m%d-%H%M%S).txt
FLAGS=$(mktemp); SUM=$(mktemp)
trap 'rm -f "$FLAGS" "$SUM"' EXIT

have() { command -v "$1" >/dev/null 2>&1; }
sec()  { printf '\n=== %s ===\n' "$*"; }
flag() { echo "$*" >> "$FLAGS"; echo "  [FLAG] $*"; }
sum()  { echo "$*" >> "$SUM"; }
quiet_grep() { grep -vE '^\s*(#|$)' "$@" 2>/dev/null; }

# Which package owns a file? (returns 1 if none)
pkgof() {
  local f=$1 r p
  if have dpkg; then
    for p in "$f" "$(readlink -f "$f")" "${f#/usr}"; do
      r=$(dpkg -S "$p" 2>/dev/null | head -1 | cut -d: -f1)
      [ -n "$r" ] && { echo "$r"; return 0; }
    done
  elif have rpm; then
    r=$(rpm -qf "$f" 2>/dev/null | head -1)
    case $r in ''|*"not owned"*) ;; *) echo "$r"; return 0 ;; esac
  fi
  return 1
}

sys_info() {
  sec "SYSTEM"
  local os
  os=$( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")
  echo "host: $(hostname) ($(hostname -f 2>/dev/null))"
  echo "os: $os   kernel: $(uname -r)"
  uptime -p 2>/dev/null
  echo "-- addresses"; ip -br addr 2>/dev/null
  echo "-- routes";    ip route 2>/dev/null
  echo "-- dns";       quiet_grep /etc/resolv.conf
  echo "-- /etc/hosts"; quiet_grep /etc/hosts
  echo "-- time";      timedatectl 2>/dev/null | grep -E 'Time zone|synchronized'
  sum "Host:     $(hostname) | $os | $(ip -4 -br addr 2>/dev/null | awk '$1!="lo"{printf "%s=%s ",$1,$3}')"
}

KNOWN_PORTS=" 22 25 53 68 80 110 123 143 443 465 587 993 995 "
ports() {
  sec "LISTENING PORTS (proto  address  process)"
  ss -ltnup 2>/dev/null | tail -n +2 | awk '{print $1, $5, $7}'
  local proto la proc port pid name exe
  while read -r proto la proc; do
    case $la in 127.*|\[::1\]*) continue ;; esac
    port=${la##*:}
    pid=$(echo "$proc" | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
    name=$(echo "$proc" | grep -o '"[^"]*"' | head -1 | tr -d '"')
    exe=""; [ -n "$pid" ] && exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
    if [ "$proto" = tcp ]; then
      case "$KNOWN_PORTS" in *" $port "*) ;; *) flag "unusual TCP listener on port $port (${name:-?}, ${exe:-?})" ;; esac
    fi
  done < <(ss -ltnup 2>/dev/null | tail -n +2 | awk '{print $1, $5, $7}')
  sum "Open TCP: $(ss -ltn 2>/dev/null | tail -n +2 | awk '{print $4}' | grep -vE '^(127\.|\[::1\])' | sed 's/.*://' | sort -un | tr '\n' ' ')"
}

odd_processes() {
  sec "PROCESSES RUNNING FROM ODD PLACES"
  local p e n=0
  for p in /proc/[0-9]*; do
    e=$(readlink "$p/exe" 2>/dev/null) || continue
    case "$e" in
      *"(deleted)"*|/tmp/*|/var/tmp/*|/dev/shm/*|/run/user/*|/home/*|/root/*)
        flag "process ${p#/proc/} ($(cat "$p/comm" 2>/dev/null)) runs from $e  [a '(deleted)' binary is often just a package update]"
        n=$((n+1)) ;;
    esac
  done
  [ "$n" = 0 ] && echo "none"
}

services() {
  sec "SERVICES"
  have systemctl || { echo "no systemd"; return; }
  echo "-- running"; systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}'
  echo "-- failed";  systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}'
  [ -d /opt/splunkforwarder ] && echo "splunk forwarder found in /opt/splunkforwarder"
  sum "Services: $(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}' | grep -E 'postfix|dovecot|ssh|apache|nginx|httpd|php|mysql|maria|postgres|rsyslog|fail2ban|splunk|auditd|sssd|winbind|cron' | sed 's/\.service//' | tr '\n' ' ')"
}

auth_integration() {
  sec "AD / DIRECTORY INTEGRATION"
  local s joined=""
  if have realm; then realm list 2>/dev/null; joined=$(realm list 2>/dev/null | head -1); fi
  for s in sssd winbind nslcd; do systemctl is-active --quiet "$s" 2>/dev/null && echo "$s: active"; done
  echo "-- nsswitch"; grep -E '^(passwd|group|shadow):' /etc/nsswitch.conf 2>/dev/null
  echo "-- pam (common-auth / system-auth)"; quiet_grep /etc/pam.d/common-auth /etc/pam.d/system-auth
  if [ -f /etc/sssd/sssd.conf ]; then
    echo "-- sssd.conf (secrets hidden)"
    quiet_grep /etc/sssd/sssd.conf | sed -E 's/((password|secret)[^=]*=).*/\1 <hidden>/I'
  fi
  grep -E 'default_realm' /etc/krb5.conf 2>/dev/null
  sum "Domain join: ${joined:-none found (mail logins may use LDAP directly; see Dovecot)}"
}

mail_stack() {
  local mn rr drv f
  sec "MAIL: POSTFIX"
  if have postconf; then
    postconf -n 2>/dev/null | grep -E '^(myhostname|mydomain|myorigin|mydestination|mynetworks|inet_interfaces|inet_protocols|relayhost|relay_domains|home_mailbox|mailbox_command|mailbox_transport|virtual_[a-z_]+|local_recipient_maps|alias_maps|smtpd_sasl_[a-z_]+|smtpd_tls_[a-z_]+|smtpd_banner|disable_vrfy_command|message_size_limit|milter_[a-z_]+|smtpd_[a-z_]*restrictions) '
    echo "-- effective restrictions"
    postconf smtpd_relay_restrictions smtpd_recipient_restrictions 2>/dev/null
    mn=$(postconf -h mynetworks 2>/dev/null)
    echo "mynetworks (effective): $mn"
    echo "-- master.cf services"; postconf -M 2>/dev/null | awk '{print $1}' | tr '\n' ' '; echo
    echo "-- queue"; postqueue -p 2>/dev/null | tail -1
    echo "$mn" | grep -Eq '(^|[ ,])(0\.0\.0\.0/0|::/0)|/[0-7]([ ,]|$)' && flag "postfix mynetworks looks too wide: $mn"
    rr=$(postconf -h smtpd_relay_restrictions smtpd_recipient_restrictions 2>/dev/null)
    echo "$rr" | grep -q reject_unauth_destination || flag "postfix: reject_unauth_destination not in relay/recipient restrictions (open relay risk)"
    [ -f /etc/aliases ] && grep -Eq '^[^#].*\|' /etc/aliases && flag "/etc/aliases has a pipe-to-command entry"
    sum "Postfix:  $(postconf -h mail_version 2>/dev/null) running=$(postfix status >/dev/null 2>&1 && echo yes || echo NO) mydestination=[$(postconf -h mydestination 2>/dev/null | cut -c1-50)] virtual_domains=[$(postconf -h virtual_mailbox_domains 2>/dev/null)]"
  else
    echo "postfix not installed"; sum "Postfix:  not installed"
  fi

  sec "MAIL: DOVECOT"
  if have doveconf; then
    doveconf -n 2>/dev/null | sed -E 's/((pass|secret|dnpass)[a-z_]*[[:space:]]*=).*/\1 <hidden>/I' | head -120
    drv=$(doveconf -n 2>/dev/null | awk '/^(passdb|userdb)/{k=$1} /driver = /{print k"="$3}' | tr '\n' ' ')
    echo "-- auth drivers: $drv"
    doveconf -n 2>/dev/null | grep -Eq '^auth_(debug|debug_passwords|verbose_passwords) = (yes|plain|sha1)' && flag "dovecot auth debug / password logging is on"
    f=$(doveconf -n 2>/dev/null | awk '/^(passdb|userdb)/{a=""} /args = /{a=$3} /driver = ldap/{print a; exit}')
    if [ -n "$f" ] && [ -r "$f" ]; then
      echo "-- LDAP settings in $f (secrets hidden)"
      quiet_grep "$f" | sed -E 's/^(dnpass|dn_pass|password)[[:space:]]*=.*/\1 = <hidden>/'
      if grep -Eq '^dnpass' "$f" && [ $(( 0$(stat -c %a "$f") & 7 )) -ne 0 ]; then
        flag "$f holds an LDAP password and is readable by everyone"
      fi
    fi
    sum "Dovecot:  $(dovecot --version 2>/dev/null | cut -d' ' -f1) running=$(systemctl is-active dovecot 2>/dev/null) auth: $drv"
  else
    echo "dovecot not installed"; sum "Dovecot:  not installed"
  fi

  sec "MAIL STORAGE"
  local d
  for d in /var/vmail /var/mail /var/spool/mail; do
    [ -d "$d" ] && echo "$d: $(du -sh "$d" 2>/dev/null | cut -f1), $(find "$d" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l) entries"
  done
  ls -d /home/*/Maildir 2>/dev/null
  sum "Mailboxes: $(for d in /var/vmail /var/mail /var/spool/mail; do [ -d "$d" ] && printf '%s(%s entries) ' "$d" "$(find "$d" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"; done)"
}

ssh_cfg() {
  sec "SSH"
  have sshd || { echo "sshd not found"; return; }
  local t; t=$(sshd -T 2>/dev/null)
  echo "$t" | grep -E '^(port|permitrootlogin|passwordauthentication|permitemptypasswords|pubkeyauthentication|allowusers|allowgroups|denyusers|usepam|authorizedkeysfile|authorizedkeyscommand|maxauthtries) '
  echo "$t" | grep -q '^permitrootlogin yes' && flag "ssh PermitRootLogin yes"
  echo "$t" | grep -q '^permitemptypasswords yes' && flag "ssh PermitEmptyPasswords yes"
  echo "$t" | grep -E '^authorizedkeyscommand ' | grep -vq ' none$' && flag "ssh AuthorizedKeysCommand is set (runs a program at login)"
  sum "SSH:      port $(echo "$t" | awk '$1=="port"{printf "%s ",$2}') root=$(echo "$t" | awk '$1=="permitrootlogin"{print $2}') password-auth=$(echo "$t" | awk '$1=="passwordauthentication"{print $2}')"
}

web() {
  sec "WEB"
  local roots="" r
  if have apache2ctl || have apachectl; then
    (apache2ctl -S 2>&1 || apachectl -S 2>&1) | head -20
    roots="$roots $(grep -rhiE '^\s*DocumentRoot' /etc/apache2 /etc/httpd 2>/dev/null | awk '{print $2}' | tr -d '"')"
  fi
  if have nginx; then
    nginx -T 2>/dev/null | grep -E '^\s*(server_name|listen|root)\b' | head -20
    roots="$roots $(nginx -T 2>/dev/null | awk '$1=="root"{gsub(";","",$2); print $2}')"
  fi
  [ -d /var/www ] && roots="$roots /var/www"
  roots=$(for r in $roots; do [ -d "$r" ] && echo "$r"; done | sort -u)
  if [ -z "$roots" ] && ! have apache2ctl && ! have nginx; then
    echo "no web server found"; sum "Web:      no web server found"; return
  fi
  echo "web roots: $roots"
  echo "-- apps found"
  find $roots /usr/share/roundcube* /usr/share/squirrelmail /opt -maxdepth 4 \
    \( -name wp-config.php -o -iname 'roundcube*' -o -iname 'squirrelmail*' -o -name 'config.inc.php' -o -iname phpmyadmin -o -iname nextcloud -o -iname owncloud \) 2>/dev/null | head -20
  for r in $roots; do
    echo "-- scan $r"
    grep -rIlE --include='*.php' --include='*.phtml' --include='*.phar' --include='*.inc' \
      '(eval|assert|system|passthru|shell_exec|exec|popen|proc_open)[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|str_rot13|\$_(GET|POST|REQUEST|COOKIE|SERVER))' "$r" 2>/dev/null \
      | head -20 | while read -r f; do flag "webshell-like code: $f"; done
    find "$r" -type f \( -name '*.php' -o -name '*.phtml' \) \
      \( -ipath '*upload*' -o -ipath '*/tmp/*' -o -ipath '*/temp/*' -o -ipath '*/cache/*' -o -ipath '*/logs/*' -o -ipath '*/files/*' \) 2>/dev/null \
      | head -15 | while read -r f; do flag "PHP file in an upload/temp-type folder: $f"; done
    find "$r" -type f -perm -0002 2>/dev/null | head -15 | while read -r f; do flag "world-writable web file: $f"; done
  done
  sum "Web:      $(for s in apache2 httpd nginx; do systemctl is-active --quiet $s 2>/dev/null && printf '%s=active ' $s; done) roots:$(echo $roots)"
}

users() {
  sec "USERS"
  local u h n f
  echo "-- UID 0 accounts"; awk -F: '$3==0{print $1}' /etc/passwd
  awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | while read -r u; do flag "extra UID 0 account: $u"; done
  echo "-- accounts with a login shell"
  awk -F: '$7!~/(nologin|false|sync|shutdown|halt)$/{printf "%s uid=%s shell=%s home=%s\n",$1,$3,$7,$6}' /etc/passwd
  echo "-- empty passwords"
  awk -F: '$2==""{print $1}' /etc/shadow 2>/dev/null | while read -r u; do flag "account with EMPTY password: $u"; done
  echo "-- sudo/admin groups"; for f in sudo admin wheel; do getent group "$f"; done
  echo "-- sudoers (active lines)"; quiet_grep /etc/sudoers /etc/sudoers.d/*
  grep -rhE 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | while read -r f; do flag "sudoers NOPASSWD: $f"; done
  echo "-- authorized_keys files"
  while IFS=: read -r u _ _ _ _ h _; do
    for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do
      if [ -s "$f" ]; then
        n=$(grep -cvE '^\s*(#|$)' "$f")
        echo "$f ($n keys, modified $(stat -c %y "$f" | cut -d. -f1))"
        flag "authorized_keys for $u: $f ($n keys)"
      fi
    done
  done < /etc/passwd
  echo "-- recent logins"; last -n 10 -a 2>/dev/null; echo "-- logged in now"; who 2>/dev/null
  sum "Users:    $(awk -F: '$7!~/(nologin|false|sync|shutdown|halt)$/' /etc/passwd | wc -l) with a login shell | extra UID0: $(awk -F: '$3==0 && $1!="root"{printf "%s ",$1}' /etc/passwd)$(awk -F: '$3==0 && $1!="root"' /etc/passwd | grep -q . || echo none)"
}

persistence() {
  sec "SCHEDULED JOBS AND STARTUP HOOKS"
  local d f
  echo "-- /etc/crontab and /etc/cron.d"; quiet_grep /etc/crontab /etc/cron.d/*
  echo "-- user crontabs"
  for d in /var/spool/cron/crontabs /var/spool/cron; do
    [ -d "$d" ] || continue
    for f in "$d"/*; do
      [ -f "$f" ] || continue
      echo "[$(basename "$f")]"; quiet_grep "$f"
      [ -n "$(quiet_grep "$f")" ] && flag "user crontab has entries: $f"
    done
  done
  echo "-- cron.hourly/daily/weekly/monthly scripts"
  find /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly -type f -printf '%TY-%Tm-%Td %p\n' 2>/dev/null
  for f in $(find /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d -type f 2>/dev/null); do
    pkgof "$f" >/dev/null || flag "cron file not from a package: $f"
  done
  grep -rElI 'curl |wget |/dev/tcp|nc -|ncat |bash -i|base64|mkfifo|python[0-9.]* -c|perl -e' \
    /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron 2>/dev/null \
    | while read -r f; do pkgof "$f" >/dev/null && continue; flag "cron file with network/shell pattern: $f"; done
  if have systemctl; then
    echo "-- systemd timers (unit -> activates)"
    systemctl list-timers --all --no-legend --plain 2>/dev/null | awk '{print $(NF-1)" -> "$NF}'
    echo "-- custom systemd unit files"
    for f in $(find /etc/systemd/system /usr/local/lib/systemd/system -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' \) 2>/dev/null); do
      echo "$f ($(stat -c %y "$f" | cut -d. -f1))"
      pkgof "$f" >/dev/null || flag "custom systemd unit (not from a package): $f"
    done
  fi
  if [ -s /etc/rc.local ] && grep -vqE '^\s*(#|$|exit 0)' /etc/rc.local; then flag "/etc/rc.local contains commands"; fi
  [ -e /etc/ld.so.preload ] && flag "/etc/ld.so.preload exists: $(cat /etc/ld.so.preload 2>/dev/null)"
  for f in /etc/profile.d/*; do [ -f "$f" ] && { pkgof "$f" >/dev/null || flag "profile.d script not from a package: $f"; }; done
  have atq && { echo "-- at jobs"; atq 2>/dev/null; }
}

recent_changes() {
  sec "FILES CHANGED IN THE LAST 2 DAYS (/etc /var/www /usr/local /opt /root /home /srv)"
  local tmp; tmp=$(mktemp)
  find /etc /var/www /usr/local /opt /root /home /srv -xdev -type f -mtime -2 -not -path '*/.cache/*' \
    -printf '%TY-%Tm-%Td %TH:%TM %u %p\n' 2>/dev/null | sort > "$tmp"
  echo "total: $(wc -l < "$tmp") (newest 60 shown)"; tail -n 60 "$tmp"
  rm -f "$tmp"
}

suid_files() {
  sec "SUID / SGID FILES"
  local f pkg n=0
  while read -r f; do
    n=$((n+1))
    pkg=$(pkgof "$f") || pkg=""
    if [ -z "$pkg" ]; then
      echo "$f  (NOT FROM A PACKAGE)"; flag "SUID/SGID file not from a package: $f"
    else
      echo "$f  ($pkg)"
      case $f in /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/opt/*|/usr/local/*) flag "SUID/SGID file in an unusual place: $f" ;; esac
    fi
  done < <(find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap -o -path /var/lib/docker -o -path /var/lib/containers \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null)
  sum "SUID/SGID files: $n"
}

connections() {
  sec "ESTABLISHED TCP CONNECTIONS"
  ss -tnp state established 2>/dev/null | tail -n +2 | awk '{print $3, "->", $4, $5}'
  local la peer proc ip
  while read -r la peer proc; do
    ip=${peer%:*}; ip=${ip#[}; ip=${ip%]}
    case $ip in 10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|127.*|::1|fe80*|"") continue ;; esac
    flag "connection to non-private address $peer ($proc)"
  done < <(ss -tnp state established 2>/dev/null | tail -n +2 | awk '{print $3, $4, $5}')
}

firewall() {
  sec "HOST FIREWALL"
  have ufw && ufw status 2>/dev/null | head -20
  have iptables && { echo "-- iptables"; iptables -S 2>/dev/null | head -30; }
  have nft && { echo "-- nft tables"; nft list tables 2>/dev/null; }
  systemctl is-active --quiet fail2ban 2>/dev/null && echo "fail2ban: active"
}

packages() {
  sec "KEY PACKAGE VERSIONS"
  if have dpkg-query; then
    dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | grep -E '^(postfix|dovecot-core|dovecot-imapd|dovecot-pop3d|dovecot-ldap|openssh-server|apache2|nginx|php[0-9.]*(-fpm|-cli)?|libapache2-mod-php[0-9.]*|roundcube[a-z-]*|squirrelmail|mariadb-server|mysql-server|postgresql|sssd|winbind|samba|slapd|vsftpd|proftpd[a-z-]*|splunkforwarder|fail2ban|clamav|auditd|ufw|nftables) '
  elif have rpm; then
    rpm -qa 2>/dev/null | grep -E '^(postfix|dovecot|openssh-server|httpd|nginx|php|roundcubemail|mariadb-server|sssd|samba|vsftpd|fail2ban)'
  fi
}

log_files() {
  sec "LOG FILES PRESENT"
  local f
  for f in /var/log/auth.log /var/log/secure /var/log/mail.log /var/log/maillog /var/log/syslog /var/log/messages \
           /var/log/apache2/access.log /var/log/apache2/error.log /var/log/nginx/access.log /var/log/httpd/access_log; do
    [ -f "$f" ] && echo "$f ($(du -h "$f" | cut -f1), last written $(stat -c %y "$f" | cut -d. -f1))"
  done
  if [ ! -f /var/log/auth.log ] && [ ! -f /var/log/secure ]; then flag "no auth.log or secure file (is rsyslog running? logins may only be in journald)"; fi
  if [ ! -f /var/log/mail.log ] && [ ! -f /var/log/maillog ]; then flag "no mail log file found (check rsyslog or journalctl -u postfix)"; fi
}

main() {
  echo "ccdc-inventory $(date '+%F %T') (read-only)"
  sys_info; ports; odd_processes; services; auth_integration; mail_stack; ssh_cfg
  web; users; persistence; recent_changes; suid_files; connections; firewall; packages; log_files
  sec "ITEMS TO REVIEW"
  awk '!s[$0]++' "$FLAGS"
}

main > "$REPORT" 2>/dev/null
chmod 600 "$REPORT"

if [ "$PRINT" = 1 ]; then cat "$REPORT"; exit 0; fi

echo "==== INVENTORY SUMMARY  $(date '+%F %T') ===="
cat "$SUM"
nf=$(awk '!s[$0]++' "$FLAGS" | wc -l)
echo
echo "==== $nf ITEM(S) TO REVIEW (worth a look, not proof of an attack) ===="
awk '!s[$0]++' "$FLAGS" | head -40
[ "$nf" -gt 40 ] && echo "... $((nf-40)) more in the full report"
echo
echo "Full report: $REPORT"
echo "Read it with: sudo less $REPORT"
