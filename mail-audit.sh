#!/usr/bin/env bash
# mail-audit.sh - READ-ONLY mail config audit (Postfix + Dovecot)
#
# Prints postconf -n and doveconf -n, detects the auth method in use
# (LDAP / SQL / PAM+sssd / passwd-file ...), and checks for open relay,
# sender spoofing, and "any domain user can log in" problems.
# It changes nothing on the system.
#
# Usage:  sudo ./mail-audit.sh
# Output: printed to screen and saved to /var/log/ccdc/mail-audit-<timestamp>.txt
#         (view with: sudo less /var/log/ccdc/mail-audit-*.txt)

set -u
export LC_ALL=C

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo $0"
  exit 1
fi

OUTDIR=/var/log/ccdc
TS=$(date +%Y%m%d-%H%M%S)
OUT="$OUTDIR/mail-audit-$TS.txt"
mkdir -p "$OUTDIR"
exec > >(tee "$OUT") 2>&1

FAILS=0
WARNS=0
ok()   { echo "  [ OK ] $*"; }
warn() { echo "  [WARN] $*"; WARNS=$((WARNS + 1)); }
bad()  { echo "  [FAIL] $*"; FAILS=$((FAILS + 1)); }
info() { echo "  [INFO] $*"; }
hdr()  { echo; echo "== $* =="; }

have() { command -v "$1" >/dev/null 2>&1; }
pf()   { postconf -h "$1" 2>/dev/null; }
dc()   { doveconf -h "$1" 2>/dev/null; }
# split a comma/space separated list into one token per line
toks() { echo "$1" | tr ',' ' ' | tr -s ' \t\n' '\n' | sed '/^$/d'; }
has_tok() { toks "$1" | grep -qx -- "$2"; }
# hide secrets in config dumps
mask() { sed -E 's/(password|pass|dnpass|secret)([[:space:]]*=[[:space:]]*)[^[:space:]]+/\1\2********/Ig'; }

POSTFIX=0; DOVECOT=0
have postconf && POSTFIX=1
have doveconf && DOVECOT=1

echo "Mail config audit - $(date)  host: $(hostname)"
echo "Saved to: $OUT"

# ---------------------------------------------------------------- 1
hdr "1. POSTFIX CONFIG (postconf -n)"
if [ $POSTFIX -eq 1 ]; then
  postconf -n | mask
else
  info "postconf not found - Postfix not installed?"
fi

# ---------------------------------------------------------------- 2
hdr "2. DOVECOT CONFIG (doveconf -n)"
if [ $DOVECOT -eq 1 ]; then
  doveconf -n 2>&1 | mask
else
  info "doveconf not found - Dovecot not installed?"
fi

# ---------------------------------------------------------------- 3
hdr "3. AUTH METHOD DETECTION (not assuming LDAP)"
AUTH_LDAP=0; AUTH_SQL=0; AUTH_PAM=0; AUTH_FILE=0; AUTH_OTHER=0

if [ $DOVECOT -eq 1 ]; then
  echo "  Dovecot passdb/userdb drivers:"
  DRIVERS=$(doveconf -n 2>/dev/null | awk '
    /^(passdb|userdb)/ {blk=$1}
    /^}/ {blk=""}
    blk && /driver[[:space:]]*=/ {gsub(/^[ \t]+/,""); print "    " blk ": " $0}')
  if [ -n "$DRIVERS" ]; then
    echo "$DRIVERS"
  else
    info "no explicit passdb/userdb in 'doveconf -n' (check the !include lines below)"
  fi
  echo "  Auth files included by Dovecot:"
  grep -rhE '^[[:space:]]*!include' /etc/dovecot/conf.d/10-auth.conf 2>/dev/null | sed 's/^/    /'

  ALLDRV=$(echo "$DRIVERS" | tr 'A-Z' 'a-z')
  echo "$ALLDRV" | grep -q 'ldap'  && AUTH_LDAP=1
  echo "$ALLDRV" | grep -qE 'sql'  && AUTH_SQL=1
  echo "$ALLDRV" | grep -qE 'pam|bsdauth' && AUTH_PAM=1
  echo "$ALLDRV" | grep -qE 'passwd|shadow' && AUTH_FILE=1
  echo "$ALLDRV" | grep -qE 'static|checkpassword|lua|oauth2' && AUTH_OTHER=1
fi

if [ $POSTFIX -eq 1 ]; then
  SASL_EN=$(pf smtpd_sasl_auth_enable)
  SASL_TYPE=$(pf smtpd_sasl_type)
  SASL_PATH=$(pf smtpd_sasl_path)
  echo "  Postfix SMTP AUTH: enable=$SASL_EN type=$SASL_TYPE path=$SASL_PATH"
  MAPS="$(pf virtual_mailbox_maps) $(pf virtual_alias_maps) $(pf local_recipient_maps) $(pf smtpd_sender_login_maps) $(pf alias_maps)"
  echo "$MAPS" | grep -qi 'ldap'  && { AUTH_LDAP=1; info "Postfix lookup maps use LDAP"; }
  echo "$MAPS" | grep -qiE 'mysql|pgsql|sqlite' && { AUTH_SQL=1; info "Postfix lookup maps use SQL"; }
  if [ "$SASL_EN" = "yes" ] && [ "$SASL_TYPE" = "cyrus" ]; then
    info "Postfix uses Cyrus SASL (saslauthd). Check /etc/default/saslauthd MECHANISMS"
    grep -E '^(MECHANISMS|START)' /etc/default/saslauthd 2>/dev/null | sed 's/^/    /'
  fi
fi

echo "  Directory/identity services on this host:"
if have systemctl; then
  for s in sssd winbind slapd saslauthd; do
    st=$(systemctl is-active "$s" 2>/dev/null)
    [ "$st" = "active" ] && { echo "    $s: active"; }
  done
fi
if grep -E '^passwd:' /etc/nsswitch.conf 2>/dev/null | grep -q 'sss\|winbind\|ldap'; then
  echo "    nsswitch passwd uses a directory (sss/winbind/ldap): domain users are visible as system users"
  AUTH_PAM=1
fi
grep -lE 'pam_sss|pam_winbind|pam_ldap' /etc/pam.d/* 2>/dev/null | sed 's/^/    PAM uses directory auth in: /'
have realm && realm list 2>/dev/null | sed 's/^/    realm: /'

echo "  Conclusion:"
[ $AUTH_LDAP  -eq 1 ] && echo "    -> LDAP / Active Directory lookups detected"
[ $AUTH_SQL   -eq 1 ] && echo "    -> SQL database auth detected"
[ $AUTH_PAM   -eq 1 ] && echo "    -> PAM / system accounts (may be local users or AD through sssd/winbind)"
[ $AUTH_FILE  -eq 1 ] && echo "    -> passwd-file / shadow auth detected"
[ $AUTH_OTHER -eq 1 ] && echo "    -> static/other driver detected (see section 6 for risk)"
[ $((AUTH_LDAP + AUTH_SQL + AUTH_PAM + AUTH_FILE + AUTH_OTHER)) -eq 0 ] && echo "    -> could not determine; read sections 1 and 2 manually"

# ---------------------------------------------------------------- 4
hdr "4. OPEN RELAY CHECKS (Postfix)"
if [ $POSTFIX -eq 0 ]; then
  info "skipped - Postfix not installed"
else
  MYNET=$(pf mynetworks)
  info "mynetworks = $MYNET"
  for t in $(toks "$MYNET"); do
    case "$t" in
      0.0.0.0/0|::/0|\[::\]/0) bad "mynetworks contains $t (EVERYONE is trusted to relay)"; continue ;;
    esac
    case "$t" in
      *:*|*[a-zA-Z]*) continue ;;   # IPv6 or map reference, skip CIDR math
    esac
    if [[ "$t" == */* ]]; then
      cidr=${t#*/}
      if [ "$cidr" -lt 16 ] 2>/dev/null; then
        warn "mynetworks has a very wide range: $t"
      fi
    fi
  done
  [ "$(pf mynetworks_style)" = "host" ] || info "mynetworks_style=$(pf mynetworks_style)"

  RR=$(pf smtpd_relay_restrictions)
  RC=$(pf smtpd_recipient_restrictions)
  info "smtpd_relay_restrictions     = $RR"
  info "smtpd_recipient_restrictions = $RC"

  check_order() {  # $1=list; prints reason and returns 1 if unsafe
    local seen=0 t
    for t in $(toks "$1"); do
      case "$t" in
        defer_unauth_destination|reject_unauth_destination) seen=1 ;;
        permit) if [ $seen -eq 0 ]; then echo "bare 'permit' comes before reject_unauth_destination"; return 1; fi ;;
      esac
    done
    [ $seen -eq 1 ] || { echo "no reject_unauth_destination / defer_unauth_destination present"; return 1; }
    return 0
  }

  if [ -n "$RR" ]; then LISTNAME=smtpd_relay_restrictions; LIST=$RR; else LISTNAME=smtpd_recipient_restrictions; LIST=$RC; fi
  if REASON=$(check_order "$LIST"); then
    ok "$LISTNAME blocks unauthenticated relay to outside domains"
  else
    bad "$LISTNAME: $REASON  -> OPEN RELAY RISK"
  fi

  has_tok "$LIST" permit_mynetworks && info "permit_mynetworks is active: anyone on mynetworks can relay"
  has_tok "$LIST" permit_sasl_authenticated && ok "authenticated users may relay (expected)"

  # --- live probe: stops at RCPT TO, never sends a message
  smtp_probe() {  # host from to -> prints the server's reply to RCPT TO
    timeout 20 bash -c '
      exec 3<>/dev/tcp/$0/25 || exit 9
      rd(){ local l; while IFS= read -r -t 8 l <&3; do echo "$l"; [[ ${l:3:1} == " " ]] && break; done; }
      rd >/dev/null
      printf "EHLO mail-audit.local\r\n" >&3; rd >/dev/null
      printf "MAIL FROM:<%s>\r\n" "$1" >&3; rd >/dev/null
      printf "RCPT TO:<%s>\r\n" "$2" >&3; rd
      printf "RSET\r\nQUIT\r\n" >&3
    ' "$1" "$2" "$3" 2>/dev/null
  }

  echo "  Live probe (RCPT TO an outside address; no mail is sent):"
  HOSTS="127.0.0.1"
  MYIP=$(hostname -I 2>/dev/null | awk '{print $1}')
  [ -n "${MYIP:-}" ] && HOSTS="$HOSTS $MYIP"
  for h in $HOSTS; do
    R=$(smtp_probe "$h" "audit-probe@example.com" "audit-probe@example.org" | tail -1)
    case "$R" in
      250*) warn "$h accepted relay to outside domain: '$R'. Expected ONLY because this host is in mynetworks. Re-test from ANOTHER machine (see end of report)" ;;
      4*|5*) ok "$h refused relay: '$R'" ;;
      "")   info "$h: no response (port 25 closed or filtered?)" ;;
      *)    info "$h: '$R'" ;;
    esac
  done
fi

# ---------------------------------------------------------------- 5
hdr "5. SENDER SPOOFING / INJECTION CHECKS (Postfix)"
if [ $POSTFIX -eq 1 ]; then
  info "mydomain=$(pf mydomain)  mydestination=$(pf mydestination)"
  info "virtual_mailbox_domains=$(pf virtual_mailbox_domains)  virtual_alias_domains=$(pf virtual_alias_domains)"

  SR=$(pf smtpd_sender_restrictions)
  info "smtpd_sender_restrictions = $SR"
  has_tok "$SR" reject_non_fqdn_sender      || warn "reject_non_fqdn_sender not set in smtpd_sender_restrictions"
  has_tok "$SR" reject_unknown_sender_domain || warn "reject_unknown_sender_domain not set (note: needs working DNS)"

  ALLR="$SR $RC $RR"
  if echo "$ALLR" | grep -q 'check_sender_access'; then
    ok "check_sender_access present (can reject your own domain from unauthenticated senders)"
  else
    warn "no check_sender_access: outsiders can send as nobody@$(pf mydomain) or any of your addresses"
  fi

  SLM=$(pf smtpd_sender_login_maps)
  if [ -z "$SLM" ]; then
    warn "smtpd_sender_login_maps is empty: any logged-in user can send as ANY address"
  elif echo "$ALLR" | grep -q 'reject_sender_login_mismatch'; then
    ok "sender login maps enforced (reject_sender_login_mismatch)"
  else
    warn "smtpd_sender_login_maps set but reject_sender_login_mismatch is not used"
  fi

  [ "$(pf disable_vrfy_command)" = "yes" ] && ok "VRFY disabled" || warn "disable_vrfy_command is not yes (lets anyone test which accounts exist)"
  [ "$(pf smtpd_sasl_auth_enable)" = "yes" ] && info "SMTP AUTH is enabled"
  pf smtpd_sasl_security_options | grep -q noanonymous || warn "smtpd_sasl_security_options lacks noanonymous"
  [ "$(pf smtpd_tls_auth_only)" = "yes" ] || info "smtpd_tls_auth_only is not yes (AUTH allowed without TLS; may be needed for scoring, so judge before changing)"

  for p in always_bcc recipient_bcc_maps sender_bcc_maps smtpd_milters non_smtpd_milters transport_maps canonical_maps sender_canonical_maps recipient_canonical_maps; do
    v=$(pf "$p")
    [ -n "$v" ] && warn "$p is set to '$v' (check it is yours: used to copy or redirect mail)"
  done

  echo "  Aliases that run commands or write files (persistence):"
  if grep -nE '^[^#].*[:,][[:space:]]*"?\|' /etc/aliases 2>/dev/null; then
    warn "pipe aliases found above in /etc/aliases"
  else
    ok "no pipe aliases in /etc/aliases"
  fi
  ls /home/*/.forward /root/.forward 2>/dev/null | while read -r f; do warn ".forward file: $f"; done

  echo "  master.cf services (enabled):"
  postconf -Mf 2>/dev/null | awk '{printf "    %-14s %s\n",$1,$2}' | sort -u
  postconf -Mf 2>/dev/null | awk '$2=="pipe" || $2=="spawn"' | while read -r l; do warn "pipe/spawn service: $l"; done
  echo "  master.cf per-service overrides (postconf -P):"
  postconf -P 2>/dev/null | sed 's/^/    /'
else
  info "skipped - Postfix not installed"
fi

# ---------------------------------------------------------------- 6
hdr "6. DOVECOT CHECKS"
if [ $DOVECOT -eq 1 ]; then
  info "protocols=$(dc protocols)  listen=$(dc listen)"
  AM=$(dc auth_mechanisms)
  info "auth_mechanisms = $AM"
  echo "$AM" | grep -qi anonymous && bad "ANONYMOUS auth mechanism is enabled"

  DPA=$(dc disable_plaintext_auth); DPA=${DPA:-$(dc auth_allow_cleartext)}
  info "ssl=$(dc ssl)  disable_plaintext_auth=$(dc disable_plaintext_auth)"
  [ "$(dc disable_plaintext_auth)" = "no" ] && warn "plaintext auth allowed without TLS (may be needed for scoring, so judge before changing)"

  if doveconf -n 2>/dev/null | grep -qiE 'nopassword|allow_all_logins'; then
    bad "passdb with nopassword/allow_all_logins found: logins may succeed WITHOUT a password"
    doveconf -n 2>/dev/null | grep -niE 'nopassword|allow_all_logins' | sed 's/^/    /'
  else
    ok "no nopassword / allow_all_logins passdb"
  fi

  AUF=$(dc auth_username_format)
  info "auth_username_format = ${AUF:-<default>}"
  case "$AUF" in
    *%n*|*%Ln*) warn "username format strips the domain: user@anything-else maps to the same account" ;;
  esac

  # --- LDAP
  if [ $AUTH_LDAP -eq 1 ]; then
    echo "  LDAP settings:"
    for f in /etc/dovecot/dovecot-ldap.conf.ext /etc/dovecot/dovecot-ldap*.ext; do
      [ -f "$f" ] || continue
      echo "    file: $f"
      grep -vE '^[[:space:]]*(#|$)' "$f" | mask | sed 's/^/      /'
      grep -qE '^(user_filter|pass_filter)' "$f" \
        || warn "no user_filter/pass_filter in $f: any valid directory user may log in to mail"
      grep -E '^(user_filter|pass_filter)' "$f" | grep -qiE 'memberOf|group' \
        && ok "filter restricts by group" \
        || info "filters do not mention a group. Consider limiting mail login to a mail group"
      grep -qE '^tls[[:space:]]*=[[:space:]]*yes|^uris[[:space:]]*=[[:space:]]*ldaps' "$f" \
        || info "LDAP connection may be unencrypted"
    done
  fi

  # --- SQL
  if [ $AUTH_SQL -eq 1 ]; then
    echo "  SQL settings:"
    for f in /etc/dovecot/dovecot-sql.conf.ext /etc/dovecot/dovecot-sql*.ext; do
      [ -f "$f" ] || continue
      echo "    file: $f"
      grep -vE '^[[:space:]]*(#|$)' "$f" | mask | sed 's/^/      /'
    done
  fi

  # --- PAM
  if [ $AUTH_PAM -eq 1 ]; then
    echo "  PAM service file for dovecot (/etc/pam.d/dovecot):"
    grep -vE '^[[:space:]]*(#|$)' /etc/pam.d/dovecot 2>/dev/null | sed 's/^/      /'
    info "With PAM, every account the OS can see can log in to mail (local AND domain users). See section 7"
  fi

  # --- passwd-file
  if [ $AUTH_FILE -eq 1 ]; then
    echo "  passwd-file locations:"
    doveconf -n 2>/dev/null | grep -E 'args.*(passwd|users)' | sed 's/^/      /'
    ls -l /etc/dovecot/users /etc/dovecot/passwd 2>/dev/null | sed 's/^/      /'
  fi

  echo "  Dovecot auth failures logged recently (last 5):"
  grep -hiE 'dovecot.*auth.*fail|auth failed' /var/log/mail.log 2>/dev/null | tail -5 | sed 's/^/      /'
else
  info "skipped - Dovecot not installed"
fi

# ---------------------------------------------------------------- 7
hdr "7. WHO CAN LOG IN TO THE SERVER ITSELF"
if have sshd; then
  sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|allowusers|allowgroups|denyusers|denygroups|permitemptypasswords) ' | sed 's/^/    /'
  PRL=$(sshd -T 2>/dev/null | awk '/^permitrootlogin /{print $2}')
  [ "$PRL" = "no" ] && ok "root SSH login disabled" || warn "PermitRootLogin is '$PRL'"
  if sshd -T 2>/dev/null | grep -qE '^(allowusers|allowgroups) '; then
    ok "SSH is restricted with AllowUsers/AllowGroups"
  else
    warn "no AllowUsers/AllowGroups: every account the OS knows (including domain users via sssd) can try SSH"
  fi
else
  info "sshd not found"
fi
if [ -f /etc/sssd/sssd.conf ]; then
  echo "  sssd access control:"
  grep -E '^(access_provider|simple_allow_users|simple_allow_groups|ldap_access_filter|use_fully_qualified_names|ad_gpo_access_control)' /etc/sssd/sssd.conf | sed 's/^/    /'
  grep -qE '^access_provider[[:space:]]*=[[:space:]]*(simple|ldap)' /etc/sssd/sssd.conf \
    && ok "sssd access_provider restricts who may log in" \
    || warn "sssd has no access_provider restriction: all domain users may log in here (use 'realm permit' or simple_allow_groups)"
fi

# ---------------------------------------------------------------- summary
hdr "SUMMARY"
echo "  FAIL: $FAILS    WARN: $WARNS"
echo "  Report saved to: $OUT"
cat <<'EOF'

  Confirm relay protection from ANOTHER machine (the probe above ran from this host):
    swaks --server <this-server-ip> --from nobody@localdomain.org --to someone@example.org
  Good result: "Relay access denied" (554 5.7.1).
  Test a spoof of your own domain the same way, with --to a local mailbox.

  This script changes nothing. After any fix you make, rerun your health check:
  tightening mail settings can break the scoring engine's mail flow.
EOF
