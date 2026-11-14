#!/bin/bash
# ev - evidence collector for incident reports (read-only)
# Usage: ev            writes /var/log/ccdc/evidence-<MMDD-HHMM>.txt and prints the path
#        ev -p         also prints the report on screen
# Reads auth.log and mail.log (plus rotated copies). Changes nothing else.
[ "$(id -u)" -eq 0 ] || exec sudo "$(command -v "$0")" "$@"

umask 077
mkdir -p /var/log/ccdc
OUT=/var/log/ccdc/evidence-$(date +%m%d-%H%M).txt
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
IPRE='([0-9]{1,3}\.){3}[0-9]{1,3}'

rl() { # read a log and its rotated copies, oldest first
  ls -tr "$1"* 2>/dev/null | while read -r f; do
    case $f in *.gz) zcat "$f" 2>/dev/null;; *) cat "$f" 2>/dev/null;; esac
  done
}
ts() { # timestamp from a log line (ISO or classic syslog)
  case $1 in [0-9]*) echo "$1" | cut -c1-19;; *) echo "$1" | cut -c1-15;; esac
}
top() { sort | uniq -c | sort -rn | head -"${1:-10}" | sed 's/^/     /'; }

rl /var/log/auth.log > $T/auth
rl /var/log/mail.log > $T/mail
[ -s $T/auth ] || echo "(no auth.log found)" > /dev/null
# if auth.log is missing, fall back to the journal for sshd
[ -s $T/auth ] || journalctl -u ssh -u sshd --no-pager -o short-iso 2>/dev/null > $T/auth

# --- failed / successful events, one line each ---
grep -E 'sshd.*(Failed password|Invalid user|authentication failure|Failed publickey)' $T/auth > $T/ssh_fail
grep -E 'sshd.*Accepted ' $T/auth > $T/ssh_ok
grep -E 'dovecot.*(auth failed|authentication failure)' $T/mail > $T/dov_fail
grep -E 'dovecot.*(imap|pop3)-login: Login: ' $T/mail > $T/dov_ok
grep -E 'postfix.*SASL .* authentication failed' $T/mail > $T/sasl_fail
grep -E 'postfix.*sasl_username=' $T/mail > $T/sasl_ok
grep -E 'postfix.*(NOQUEUE: reject|Relay access denied)' $T/mail > $T/pf_rej

# --- source IPs ---
for f in ssh_fail ssh_ok; do grep -oE "$IPRE" $T/$f | sort > $T/$f.ip; done
for f in dov_fail dov_ok; do grep -oE 'rip=[0-9.]+' $T/$f | cut -d= -f2 | sort > $T/$f.ip; done
for f in sasl_fail pf_rej; do sed -n 's/.*\[\([0-9.]*\)\].*/\1/p' $T/$f | sort > $T/$f.ip; done
sed -n 's/.*\[\([0-9.]*\)\], sasl_method.*/\1/p' $T/sasl_ok | sort > $T/sasl_ok.ip
cat $T/ssh_fail.ip $T/dov_fail.ip $T/sasl_fail.ip | sort > $T/fail.ip
cat $T/ssh_ok.ip $T/dov_ok.ip $T/sasl_ok.ip | sort > $T/ok.ip
cat $T/auth $T/mail > $T/all

{
echo "=============== EVIDENCE REPORT ==============="
echo "host: $(hostname)   collected: $(date '+%F %T %Z')   (VM clock; use ONE clock in the report)"
echo "log span: auth $(head -1 $T/auth | cut -c1-19) .. $(tail -1 $T/auth | cut -c1-19)"
echo "          mail $(head -1 $T/mail | cut -c1-19) .. $(tail -1 $T/mail | cut -c1-19)"
[ -s $T/mail ] || echo "NOTE: no mail.log found (try: journalctl -u postfix -u dovecot)"
echo

echo "== 1. SUMMARY (counts)"
printf '   ssh  failed %-5s ok %-5s\n' "$(wc -l < $T/ssh_fail)" "$(wc -l < $T/ssh_ok)"
printf '   imap/pop3 (dovecot) failed %-5s ok %-5s\n' "$(wc -l < $T/dov_fail)" "$(wc -l < $T/dov_ok)"
printf '   smtp auth failed %-5s ok %-5s   relay/recipient rejects %s\n' "$(wc -l < $T/sasl_fail)" "$(wc -l < $T/sasl_ok)" "$(wc -l < $T/pf_rej)"
echo

echo "== 2. TOP SOURCE IPs OF FAILED LOGINS (all services)"
top 10 < $T/fail.ip
echo
echo "== 3. TIMELINE for the top 5 failing IPs (first seen / last seen / count)"
sort $T/fail.ip | uniq -c | sort -rn | head -5 | while read -r n ip; do
  F=$(grep -F "$ip" $T/all | head -1); L=$(grep -F "$ip" $T/all | tail -1)
  echo "   $ip  first $(ts "$F")  last $(ts "$L")  failures $n"
done
echo
echo "== 4. ACCOUNTS TARGETED (failed)"
echo "   ssh:"
sed -n 's/.*Failed password for \(invalid user \)\?\([^ ]*\) from.*/\2/p; s/.*Invalid user \([^ ]*\) from.*/\1/p' $T/ssh_fail | top 8
echo "   imap/pop3:"
grep -oE 'user=<[^>]*>' $T/dov_fail | top 8
echo "   smtp:"
grep -oE 'SASL [A-Za-z]+ authentication failed' $T/sasl_fail | sort | uniq -c | sed 's/^/     /'
echo
echo "== 5. SUCCESSFUL LOGINS by source IP (who got in)"
echo "   ssh:";        top 10 < $T/ssh_ok.ip
echo "   imap/pop3:";  top 10 < $T/dov_ok.ip
echo "   smtp auth:";  top 10 < $T/sasl_ok.ip
echo "   -- ssh successes (raw, last 20)"
tail -20 $T/ssh_ok | cut -c1-170 | sed 's/^/     /'
echo
echo "== 6. !! IPs with FAILURES and then a SUCCESS (possible guessed password)"
sort -u $T/fail.ip > $T/f.u; sort -u $T/ok.ip > $T/o.u
B=$(comm -12 $T/f.u $T/o.u)
if [ -n "$B" ]; then echo "$B" | sed 's/^/   CHECK  /'; echo "   (LAN testers and the AD server are normal. Unknown IPs are not.)"; else echo "   none"; fi
echo
echo "== 7. SMTP relay / recipient rejects (top IPs, then last 10 raw)"
top 8 < $T/pf_rej.ip
tail -10 $T/pf_rej | cut -c1-170 | sed 's/^/     /'
echo
echo "== 8. Account and privilege changes (what an attacker leaves behind)"
grep -E 'useradd|new user|usermod|userdel|groupadd|passwd\[|chpasswd|sudo: .*COMMAND=|su\[.*(session opened|FAILED)|session opened for user root' $T/auth | tail -25 | cut -c1-170 | sed 's/^/   /'
echo
echo "== 9. Raw evidence: last 15 failed lines per service"
echo "   -- ssh";   tail -15 $T/ssh_fail  | cut -c1-170 | sed 's/^/     /'
echo "   -- dovecot"; tail -15 $T/dov_fail | cut -c1-170 | sed 's/^/     /'
echo "   -- smtp auth"; tail -15 $T/sasl_fail | cut -c1-170 | sed 's/^/     /'
echo
echo "== 10. On the box right now"
w -h 2>/dev/null | cut -c1-100 | sed 's/^/   /'
last -n 8 -a 2>/dev/null | head -8 | cut -c1-110 | sed 's/^/   /'
echo
echo "== 11. REPORT CHECKLIST (fill from above)"
echo "   Source IP(s):        section 2/3"
echo "   Destination IP:      $(hostname -I | awk '{print $1}')  (ports 22/25/110/143)"
echo "   Timeline:            section 3 first/last seen"
echo "   Accounts affected:   section 4 and 6 (and section 8 for new accounts)"
echo "   Passwords cracked:   section 6 and 5 (success after failures)"
echo "   Remediation:         block the IP at the firewall (not a subnet), reset the password via PCR, run hc"
} > "$OUT"

chmod 600 "$OUT"
echo "saved: $OUT"
[ "${1:-}" = "-p" ] && cat "$OUT"
exit 0
