#!/bin/bash
# svc - find the mail server's services, show how they connect, flag what is broken
# Usage: svc          (re-runs itself with sudo)
# Discovers what is installed instead of assuming Postfix/Dovecot/Roundcube.
[ "$(id -u)" -eq 0 ] || exec sudo "$(command -v "$0")" "$@"

AD=172.20.240.100
N=0
ok()   { echo "  OK      $1"; }
bad()  { echo "  BROKEN  $1"; N=$((N+1)); }
note() { echo "  ..      $1"; }
has()  { command -v "$1" >/dev/null 2>&1; }

unit() {
  systemctl list-unit-files "$1.service" --no-legend 2>/dev/null | grep -q "^$1.service" || return 1
  if systemctl is-active -q "$1"; then ok "$2: $1 running"; else bad "$2: $1 installed but NOT running"; fi
  return 0
}
group() {
  L=$1; shift; F=0
  for u in "$@"; do unit "$u" "$L" && F=1; done
  [ $F -eq 0 ] && note "$L: none found"
}

echo "== 1. Services installed"
group "mail transfer" postfix exim4 sendmail
group "mail access" dovecot courier-imap cyrus-imapd
group "web server" apache2 nginx
for p in $(systemctl list-unit-files 'php*-fpm.service' --no-legend 2>/dev/null | awk '{print $1}' | sed 's/\.service//'); do unit "$p" "php"; done
group "database" mysql mariadb postgresql
group "directory login" sssd winbind
group "remote access" ssh
group "protection" ufw fail2ban

echo "== 2. Listening ports (protocol address program)"
ss -tulpnH 2>/dev/null | awk '{printf "  %s %s %s\n",$1,$5,$7}' | sort -u | head -30

echo "== 3. How the pieces connect"
if has postconf; then
  VT=$(postconf -h virtual_transport)
  note "postfix hands mail to: $VT"
  note "postfix mydestination: $(postconf -h mydestination)"
  VM=$(postconf -h virtual_mailbox_domains)
  RM=$(postconf -h virtual_mailbox_maps)
  [ -n "$VM" ] && note "postfix virtual domains: $VM"
  if [ -n "$VM" ] && [ -z "$RM" ]; then note "NO recipient check: fake users at $VM are accepted"; fi
  case $VT in
    lmtp:unix:*) S=${VT#lmtp:unix:}
      case $S in /*) ;; *) S=$(postconf -h queue_directory)/$S;; esac
      if [ -S "$S" ]; then ok "postfix -> dovecot LMTP socket present"; else bad "LMTP socket missing: $S"; fi;;
  esac
  if [ "$(postconf -h smtpd_sasl_auth_enable)" = yes ] && [ "$(postconf -h smtpd_sasl_type)" = dovecot ]; then
    SP=$(postconf -h smtpd_sasl_path)
    case $SP in /*) ;; *) SP=$(postconf -h queue_directory)/$SP;; esac
    if [ -S "$SP" ]; then ok "postfix -> dovecot auth socket present"; else bad "auth socket missing: $SP"; fi
  fi
  O=$(postfix check 2>&1)
  if [ -z "$O" ]; then ok "postfix config check clean"; else bad "postfix check: $O"; fi
  case "$(postconf -h smtpd_relay_restrictions) $(postconf -h smtpd_recipient_restrictions)" in
    *reject_unauth_destination*|*defer_unauth_destination*) ok "relay: unauthorised destinations rejected";;
    *) bad "no reject_unauth_destination: possible OPEN RELAY";;
  esac
  case "$(postconf -h mynetworks)" in
    *0.0.0.0/0*) bad "mynetworks trusts everyone: OPEN RELAY";;
    *) note "mynetworks: $(postconf -h mynetworks)";;
  esac
fi

if has doveconf; then
  DC=$(doveconf -n 2>&1)
  if echo "$DC" | grep -qiE 'fatal|error'; then bad "dovecot config: $(echo "$DC" | grep -iE 'fatal|error' | head -1)"; else ok "dovecot config parses"; fi
  note "dovecot protocols: $(echo "$DC" | sed -n 's/^protocols = //p')"
  note "dovecot login method: $(echo "$DC" | grep -oE 'driver = [a-z]+' | sort -u | tr '\n' ' ')"
  ML=$(echo "$DC" | sed -n 's/^mail_location = //p')
  note "mailbox location: $ML"
  MD=$(echo "$ML" | sed -n 's#^[a-z]*:\(/[^%~ :]*\).*#\1#p')
  if [ -n "$MD" ]; then
    if [ -d "$MD" ]; then ok "mail dir exists: $MD"; else bad "mail dir missing: $MD"; fi
  fi
  if echo "$DC" | grep -q 'driver = ldap'; then
    LF=$(echo "$DC" | grep -oE '/[^ ]*ldap[^ ]*\.ext' | head -1)
    if [ -r "$LF" ]; then
      H=$(sed -n 's/^\(uris\|hosts\) *= *//p' "$LF" | head -1 | sed 's#ldaps\?://##g; s#[:/ ].*##')
      note "logins are checked against LDAP server: $H"
      if nc -z -w2 "$H" 389 >/dev/null 2>&1 || nc -z -w2 "$H" 636 >/dev/null 2>&1; then ok "LDAP server $H reachable"; else bad "LDAP server $H NOT reachable (all mail logins will fail)"; fi
      if grep -qE '^(pass|dnpass)' "$LF" && [ $(( $(stat -c %a "$LF") % 10 )) -ne 0 ]; then bad "LDAP bind password file is world-readable: $LF"; fi
    else
      bad "LDAP config file not readable: $LF"
    fi
  elif echo "$DC" | grep -q 'driver = pam'; then
    note "logins go through PAM (see sssd/winbind in section 1)"
    has realm && realm list 2>/dev/null | head -3 | sed 's/^/  ..      /'
  fi
fi

echo "== 4. Active Directory ($AD)"
if ping -c1 -W2 $AD >/dev/null 2>&1; then ok "ping AD"; else note "AD does not answer ping (logins may still work)"; fi
if nc -z -w2 $AD 389 >/dev/null 2>&1; then ok "AD LDAP 389"; else bad "AD LDAP 389 unreachable"; fi
if nc -z -w2 $AD 53 >/dev/null 2>&1; then ok "AD DNS 53"; else bad "AD DNS 53 unreachable"; fi

echo "== 5. Web / webmail"
W=$(ls -d /var/www/*/ /usr/share/roundcube* /usr/share/squirrelmail /usr/share/horde* /etc/roundcube 2>/dev/null | tr '\n' ' ')
if [ -n "$W" ]; then note "web folders: $W"; else note "no webmail folders found"; fi
if has curl; then
  if nc -z -w2 localhost 80 >/dev/null 2>&1; then
    C=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://localhost/)
    case $C in 2*|3*) ok "web answers on 80 (HTTP $C)";; *) bad "web on 80 returns HTTP $C";; esac
  else note "nothing on port 80"; fi
  if nc -z -w2 localhost 443 >/dev/null 2>&1; then
    C=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 4 https://localhost/)
    case $C in 2*|3*) ok "web answers on 443 (HTTP $C)";; *) bad "web on 443 returns HTTP $C";; esac
  else note "nothing on port 443"; fi
fi
RC=/etc/roundcube/config.inc.php
[ -r "$RC" ] && note "roundcube -> $(grep -E 'default_host|imap_host|smtp_host|smtp_server' $RC | tr -d ' \n' | cut -c1-120)"

echo "== 6. What is broken right now"
FU=$(systemctl --failed --no-legend 2>/dev/null | awk '{print $1}' | tr '\n' ' ')
if [ -n "$FU" ]; then bad "failed units: $FU"; else ok "no failed units"; fi
Q=0
has postqueue && Q=$(postqueue -p 2>/dev/null | grep -cE '^[0-9A-F]{8,}')
if [ "$Q" -gt 0 ]; then bad "$Q message(s) stuck in the mail queue (see: sudo grep -E 'deferred|bounced' /var/log/mail.log | tail)"; else ok "mail queue empty"; fi
if [ -r /var/log/mail.log ]; then
  E=$(tail -n 300 /var/log/mail.log | grep -E 'fatal|panic|error:|Error:|warning: .*(denied|refused|failed)|ldap.*failed' | tail -n 4)
  if [ -n "$E" ]; then bad "errors in the last 300 mail.log lines:"; echo "$E" | cut -c1-150 | sed 's/^/            /'; else ok "no errors in recent mail.log"; fi
fi
U=$(df / --output=pcent | tail -1 | tr -dc '0-9')
if [ "$U" -lt 90 ]; then ok "disk / at ${U}%"; else bad "disk / at ${U}%"; fi

echo "=== $N problem(s)"
exit $N
