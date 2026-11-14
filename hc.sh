#!/bin/bash
# hc - health check for the Ubuntu Email server (CCDC)
# Usage: hc [username]     (default user: testuser1)
# The password is typed at the prompt. Never store it in this file.
# Press Enter at the prompt to skip the login tests.

U=${1:-testuser1}
AD=172.20.240.100
F=0
ok() { echo "PASS  $1"; }
no() { echo "FAIL  $1"; F=$((F+1)); }
chk() { if "${@:2}" >/dev/null 2>&1; then ok "$1"; else no "$1"; fi; }

read -rsp "Password for $U (Enter to skip logins): " P; echo

echo "--- listening ports"
for p in 22 25 110 143; do chk "port $p" nc -z -w2 localhost $p; done
for p in 80 443; do
  if nc -z -w2 localhost $p >/dev/null 2>&1; then ok "port $p (web)"; else echo "SKIP  port $p (nothing listening)"; fi
done

echo "--- services"
for s in postfix dovecot ssh; do chk "service $s" systemctl is-active -q $s; done

echo "--- AD dependency"
chk "ping AD" ping -c1 -W2 $AD
chk "LDAP port 389 on AD" nc -z -w2 $AD 389

echo "--- protocol checks"
if { sleep 1; printf 'EHLO hc\r\nQUIT\r\n'; } | nc -w3 localhost 25 | grep -q '^250'; then ok "SMTP EHLO"; else no "SMTP EHLO"; fi

if [ -n "$P" ]; then
  if { sleep 1; printf 'a login "%s" "%s"\r\nb logout\r\n' "$U" "$P"; sleep 1; } | nc -w4 localhost 143 | grep -q '^a OK'; then ok "IMAP login $U"; else no "IMAP login $U"; fi
  if { sleep 1; printf 'user %s\r\n' "$U"; sleep 1; printf 'pass %s\r\n' "$P"; sleep 1; printf 'quit\r\n'; } | nc -w5 localhost 110 | grep -q 'Logged in'; then ok "POP3 login $U"; else no "POP3 login $U"; fi
else
  echo "SKIP  IMAP/POP3 login (no password given)"
fi

echo "--- disk"
USE=$(df / --output=pcent | tail -1 | tr -dc '0-9')
if [ "$USE" -lt 90 ]; then ok "disk / at ${USE}%"; else no "disk / at ${USE}%"; fi

echo "=== $F failure(s)"
exit $F
