#!/bin/bash
# aud - read-only recon/audit of a Linux server (first 5 minutes of CCDC)
# Usage: aud          files changed in the last 120 minutes
#        aud 30       files changed in the last 30 minutes
# Changes nothing. CHECK = look at it and decide; it is not always bad.
[ "$(id -u)" -eq 0 ] || exec sudo "$(command -v "$0")" "$@"

M=${1:-120}
W=0
PAT='curl|wget| nc |ncat|/dev/tcp|base64|bash -i|python[0-9.]* -c|perl -e|/tmp/|/dev/shm|chmod \+s'
ok()   { echo "  OK      $1"; }
note() { echo "  ..      $1"; }
flag() { echo "  CHECK   $1"; W=$((W+1)); }
has()  { command -v "$1" >/dev/null 2>&1; }

echo "== 1. Who is on the box"
w -h 2>/dev/null | cut -c1-100 | sed 's/^/     /'
echo "  -- last logins"
last -n 8 -a 2>/dev/null | head -9 | cut -c1-110 | sed 's/^/     /'
echo "  -- live connections (local <-> remote program)"
ss -tnpH state established 2>/dev/null | awk '{print "     "$3" <-> "$4" "$5}' | head -15

echo "== 2. Listening ports (compare with your baseline)"
ss -tulpnH 2>/dev/null | awk '{printf "     %s %s %s\n",$1,$5,$7}' | sort -u | head -30

echo "== 3. Accounts"
U0=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd)
if [ -n "$U0" ]; then flag "extra UID 0 account(s): $U0"; else ok "only root has UID 0"; fi
E=$(awk -F: '$2==""{print $1}' /etc/shadow)
if [ -n "$E" ]; then flag "empty password: $E"; else ok "no empty passwords"; fi
D=$(cut -d: -f3 /etc/passwd | sort | uniq -d | tr '\n' ' ')
if [ -n "$D" ]; then flag "duplicate UID(s): $D"; else ok "no duplicate UIDs"; fi
note "accounts with a login shell:"
awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print "     "$1" (uid "$3") "$7}' /etc/passwd
note "accounts with a password set: $(awk -F: '$2 !~ /^[!*]/ {print $1}' /etc/shadow | tr '\n' ' ')"
note "account files last changed:"
stat -c '     %y  %n' /etc/passwd /etc/shadow /etc/group /etc/sudoers 2>/dev/null | cut -c1-70

echo "== 4. sudo"
note "sudo group: $(getent group sudo | cut -d: -f4)   admin group: $(getent group admin | cut -d: -f4)"
grep -rhvE '^\s*(#|$|Defaults)' /etc/sudoers /etc/sudoers.d 2>/dev/null | sed 's/^/     /'
if grep -rqE 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null; then flag "NOPASSWD sudo rule present (see lines above)"; else ok "no NOPASSWD rules"; fi

echo "== 5. SSH"
KF=$(find /root /home -maxdepth 3 -name 'authorized_keys*' -type f 2>/dev/null)
if [ -z "$KF" ]; then ok "no authorized_keys files"; else
  for f in $KF; do flag "ssh key file: $f ($(grep -c . "$f") key(s)) $(awk '{print $NF}' "$f" | tr '\n' ' ' | cut -c1-70)"; done
fi
S=$(sshd -T 2>/dev/null)
for k in permitrootlogin passwordauthentication permitemptypasswords maxauthtries; do L=$(echo "$S" | grep -i "^$k "); [ -n "$L" ] && note "$L"; done
[ -z "$S" ] && note "sshd -T gave no output (is sshd installed?)"
echo "$S" | grep -qi '^permitrootlogin yes' && flag "root can log in over SSH"
echo "$S" | grep -qi '^permitemptypasswords yes' && flag "SSH allows empty passwords"

echo "== 6. Cron and scheduled jobs"
CJ=$(grep -vE '^\s*(#|$)' /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null)
echo "$CJ" | cut -c1-130 | sed 's/^/     /'
echo "$CJ" | grep -E "$PAT" | cut -c1-120 | while read -r l; do echo "  CHECK   cron line with suspicious pattern: $l"; done
for f in /var/spool/cron/crontabs/*; do [ -f "$f" ] && flag "user crontab exists: $f"; done
grep -lE "$PAT" /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* 2>/dev/null | while read -r f; do echo "  CHECK   suspicious pattern in $f"; done
if has atq; then A=$(atq 2>/dev/null); [ -n "$A" ] && flag "at job(s) queued: $A"; fi

echo "== 7. Systemd timers and startup files"
systemctl list-timers --all --no-pager 2>/dev/null | head -22 | cut -c1-125 | sed 's/^/     /'
for f in $(find /etc/systemd/system -maxdepth 1 -type f \( -name '*.service' -o -name '*.timer' \) 2>/dev/null); do
  flag "custom unit file: $f  $(grep -m1 '^ExecStart' "$f" | cut -c1-80)"
done
if [ -s /etc/rc.local ]; then flag "/etc/rc.local has content:"; grep -vE '^\s*(#|$)' /etc/rc.local | sed 's/^/            /'; fi

echo "== 8. SUID/SGID files not on the normal list"
KNOWN='sudo|sudoedit|su|passwd|chsh|chfn|gpasswd|newgrp|mount|umount|pkexec|fusermount|fusermount3|ssh-agent|write|bsd-write|wall|expiry|chage|dotlockfile|crontab|at|unix_chkpwd|pam_extrausers_chkpwd|dbus-daemon-launch-helper|polkit-agent-helper-1|ssh-keysign|snap-confine|ping|postdrop|postqueue|plocate|mlocate|locate|mail-lock|mail-unlock|mail-touchlock|utempter|screen'
T=0
while read -r f; do
  T=$((T+1))
  b=${f##*/}
  if ! echo "$b" | grep -Eqx "$KNOWN"; then flag "unexpected SUID/SGID: $f"; fi
done < <(find / -xdev -type f -perm /6000 2>/dev/null)
note "$T SUID/SGID files in total"

echo "== 9. Files changed in the last $M minutes"
find /etc /root /home /usr/local /opt /var/www /var/spool/cron /tmp /var/tmp /dev/shm -xdev -type f -mmin -"$M" -not -path '*/.cache/*' 2>/dev/null | head -40 | sed 's/^/     /'
find /tmp /var/tmp /dev/shm -type f -perm /111 2>/dev/null | while read -r f; do echo "  CHECK   executable file in a temp folder: $f"; done

echo "=== $W item(s) to check"
exit 0
