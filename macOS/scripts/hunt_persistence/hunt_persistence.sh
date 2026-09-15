#!/bin/bash
# hunt_persistence.sh — all-in-one read-only macOS persistence triage.  (v1.19)  author: Suvas Patel
#
# Sweeps every persistence surface documented in "12 - Persistence Mechanisms/"
# and ranks anomalies by severity so an analyst triages true positives first.
# Run with system privileges for full coverage: `sudo bash hunt_persistence.sh <mode>`.
#
# READ-ONLY / NON-DESTRUCTIVE: only read commands (plutil, codesign, defaults,
# launchctl print, stat, find, ls). Nothing is written, loaded, or unloaded.
# Console-only output — no report file, no footprint left on the host.
#
# Findings are ranked from the FLAGS that fire:
#   [HIGH]     act first  — strong indicators (bad signature, DYLD inject, emond rule…)
#   [NOTABLE]  review     — worth a look (interpreter/downloader, orphan, forced ssh opts…)
#   [LOW]      context     — expected-but-verify (signed third-party ext, recency alone…)
# Use --min-severity to hide lower tiers; counts are always tallied so nothing is dropped.
#
# Usage:
#   bash hunt_persistence.sh <MODE> [options]
#
#   MODE (required):
#     quick   launchd cron loginitems sysext helpers ssh authmods apps
#     deep    quick + dylib shell longtail trojan profiles
#   Always shown: SIP/Gatekeeper posture (top), user accounts + last 5 logins (bottom)
#   Signature depth is controlled by the --gk / --gk-unsigned flags below, not by mode.
#
#   Coverage is ALWAYS full — every item on the host is scanned. The recency window
#   below only adds a RECENT *highlight* flag to items changed inside it; it never
#   limits what is checked. All timestamps are shown in UTC.
#
#   Options:
#     --days N               Recency-highlight window in days (default 14; flags recent items)
#     --since YYYY-MM-DD      Highlight items modified on/after this date (overrides --days)
#     --modules a,b,c         Run only these modules (overrides MODE)
#     --user NAME             Limit per-user surfaces to one user (default: all)
#     --min-severity T        Only print findings >= T (high|notable|low; default low)
#     --verbose               Show the full detail block for EVERY item, including clean ones
#     --gk                    Run spctl (Gatekeeper) on EVERY item, any status -> appends [notarized]/[not notarized]
#                             (thorough but SLOW: ~4-24s/app; may hang on network-restricted hosts)
#                             (alias: --gatekeeper-check)
#     --gk-unsigned           Run spctl ONLY on unsigned items (fast; confirms Gatekeeper would reject them)
#                             (alias: --gatekeeper-check-unverified)
#     --suspect-only          Hide clean 'ok' lines
#     -h | --help
#
#   Signature default (no --gk flag): "signed: Vendor" from codesign -dvvv (fast, offline).
#
# Part of the macOS DFIR Field Reference — see "12 - Persistence Mechanisms/".

VERSION="1.19"; AUTHOR="Suvas Patel"
RAW_ARGS="$*"
NOW=$(date +%s)
RECENT=14; SINCE_EPOCH=""; SINCE_DATE=""
MODE=""; MODULES=""; SUSPECT_ONLY=""; ONLY_USER=""; MIN_SEV=1; VERBOSE=""; GK_MODE=""
HI=0; NO=0; LO=0; OK=0; UNR=0
SEC_NAME=""; SEC_COUNT=0; FIRED=""; SIG_TEAM=""; SEC_EMPTY=""

usage(){ sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'; }

# ---------- shared helpers ----------
get(){ plutil -extract "$1" raw -o - "$2" 2>/dev/null; }
flush_section(){ [ -n "$SEC_NAME" ] && [ "$SEC_COUNT" -eq 0 ] && printf '  %s\n' "${SEC_EMPTY:-Nothing present}"; SEC_NAME=""; }
# section NAME [empty-message] — empty-message prints when the section reports nothing.
section(){ flush_section; SEC_NAME="$1"; SEC_EMPTY="${2:-Nothing present}"; SEC_COUNT=0; printf '\n===== %s =====\n' "$1"; }
reset_analysis(){ FLAGS=""; SIG="n/a"; SCORE=0; SIG_TEAM=""; NOTARY=""; }

# flag NAME — record the flag and add its severity weight to SCORE
flag(){
  FLAGS="$FLAGS $1"
  case "$1" in
    SIG-INVALID|DYLD-*|EMOND-RULE|LOGIN-HOOK|LOGOUT-HOOK|HIDDEN-ACCOUNT|\
    HELPER-TRUST-MISMATCH|PAM-CUSTOM-MODULE|UNSIGNED-SYSBIN|NON-APPLE-SYSBIN)        SCORE=$((SCORE+5));;
    UNSIGNED|APPLE-MASQUERADE|SUDO-NOPASSWD)                                         SCORE=$((SCORE+4));;
    SUSPICIOUS-PATH|INTERP/DOWNLOAD|FORCED-OPTIONS|SSHD-EXEC-DIRECTIVE|\
    SSH-CONFIG-EXEC|AUTH-PLUGIN|ATRUN-ENABLED|NONSTANDARD-PERIODIC|\
    LOCAL-PERIODIC-OVERRIDE|STAGED-DYLIB|HIGH-RISK-SYSEXT|ROOT-SSH-KEY|\
    INSTALLED-PROFILE|WEAK-DYLIB-HIJACKABLE|NEW-ACCOUNT|LOW-UID-ACCOUNT|\
    SUDOERS-USER-GRANT|RC-LOCAL-PRESENT)                                             SCORE=$((SCORE+3));;
    ORPHAN|NOT-NOTARIZED|THIRD-PARTY-KEXT|THIRD-PARTY-KEXT-LOADED|FOLDER-ACTION|\
    MDIMPORTER|RELAUNCH-AT-LOGIN|AT-JOB-PRESENT|LEGACY-LOGINITEM|HELPER-NO-DAEMON)   SCORE=$((SCORE+2));;
    *)                                                                              SCORE=$((SCORE+1));;
  esac
}

tier(){ if [ "$SCORE" -ge 5 ]; then echo HIGH; elif [ "$SCORE" -ge 3 ]; then echo NOTABLE; else echo LOW; fi; }
rank(){ case "$1" in HIGH) echo 3;; NOTABLE) echo 2;; *) echo 1;; esac; }

flag_help(){ case "$1" in
  SIG-INVALID)          echo "signed code now fails codesign --verify — binary/bundle tampered or modified";;
  UNSIGNED-SYSBIN)      echo "unsigned Mach-O in a SIP/SSV-sealed system dir — platform binaries there are all Apple-signed (swap/implant)";;
  NON-APPLE-SYSBIN)     echo "system binary with a valid but NON-Apple signature — re-signed/replaced platform binary";;
  UNSIGNED)             echo "no code signature at all — untrusted payload";;
  NOT-NOTARIZED)        echo "signed but fails Gatekeeper notarization";;
  APPLE-MASQUERADE)     echo "com.apple.* label living outside /System — Apple never installs there";;
  DYLD-INJECT)          echo "DYLD_INSERT_LIBRARIES in a plist — dylib injected into the launched process";;
  DYLD-GLOBAL)          echo "global/launchd.conf DYLD_INSERT_LIBRARIES — injects into everything";;
  DYLD-IN-RC)           echo "DYLD_* set in a shell init file — injection at shell start";;
  STAGED-DYLIB)         echo "loose .dylib/.so in a drop dir (/tmp, /Users/Shared…) — staged payload";;
  WEAK-DYLIB-HIJACKABLE) echo "weak-linked dylib missing in a writable path — a slot to drop a malicious lib";;
  SUSPICIOUS-PATH)      echo "target lives in /tmp, /Users/Shared, /private/var/folders, or a hidden dir";;
  INTERP/DOWNLOAD)      echo "runs a shell/interpreter/downloader (sh -c, python, curl, base64, nc…)";;
  ORPHAN)               echo "referenced executable is missing — stale or half-removed persistence";;
  LOGIN-HOOK|LOGOUT-HOOK) echo "deprecated loginwindow hook runs a script at login/logout (rarely legit)";;
  EMOND-RULE)           echo "emond rule present — emond is empty by default, so any rule is suspect";;
  ATRUN-ENABLED)        echo "atrun enabled (disabled by default) — 'at' scheduling turned on";;
  AT-JOB-PRESENT)       echo "a queued 'at' one-shot job exists";;
  CRONTAB-PRESENT)      echo "a user crontab exists (uncommon on macOS)";;
  NONSTANDARD-PERIODIC|LOCAL-PERIODIC-OVERRIDE) echo "script in a non-standard/local periodic dir — root exec hiding in maintenance";;
  FORCED-OPTIONS)       echo "authorized_keys entry uses command=/no-pty/etc — scripted backdoor access";;
  ROOT-SSH-KEY)         echo "authorized_keys on root or a service account — high-value backdoor";;
  SSH-CONFIG-EXEC)      echo "~/.ssh/config runs a command (ProxyCommand/LocalCommand/Match exec)";;
  SSHD-EXEC-DIRECTIVE)  echo "sshd runs a command / redirected key file (ForceCommand/AuthorizedKeysCommand/File)";;
  REMOTE-LOGIN-ON)      echo "Remote Login (sshd) is enabled — confirm it should be";;
  AUTH-PLUGIN)          echo "third-party SecurityAgent authorization plugin — sees credentials at login";;
  HIGH-RISK-SYSEXT)     echo "third-party Endpoint Security / Network extension — sees all events or all traffic";;
  THIRD-PARTY-SYSEXT)   echo "non-Apple system extension (activated)";;
  THIRD-PARTY-KEXT)     echo "non-Apple kernel extension on disk";;
  THIRD-PARTY-KEXT-LOADED) echo "non-Apple kext loaded in the running kernel";;
  SMLOGINITEM-HELPER)   echo "app-bundled login-item helper (Contents/Library/LoginItems)";;
  RELAUNCH-AT-LOGIN)    echo "app in the reopen-at-login list";;
  LEGACY-LOGINITEM)     echo "legacy com.apple.loginitems.plist present";;
  HELPER-NO-DAEMON)     echo "privileged helper with no LaunchDaemon referencing it — unusual";;
  HELPER-TRUST-MISMATCH) echo "helper's signing Team ID != the Team ID its client app requires — hijack/fake";;
  SUDO-NOPASSWD)        echo "sudoers grants passwordless sudo (NOPASSWD) — privilege-escalation backdoor";;
  SUDOERS-USER-GRANT)   echo "a specific user (not root/%admin) is granted sudo — added backdoor account";;
  PAM-CUSTOM-MODULE)    echo "PAM config references a non-standard/planted .so module — auth backdoor";;
  RC-LOCAL-PRESENT)     echo "/etc/rc.local present (not default on macOS) — legacy boot-time execution";;
  FOLDER-ACTION)        echo "AppleScript folder-action attached to a watched folder";;
  MDIMPORTER)           echo "non-Apple Spotlight importer (.mdimporter) loaded by mdworker";;
  INSTALLED-PROFILE)    echo "configuration profile / MDM management present — can install daemons, certs, proxies";;
  HIDDEN-ACCOUNT)       echo "a real user account marked hidden — classic backdoor account";;
  LOW-UID-ACCOUNT)      echo "system UID (<500) but has an interactive login shell — account hiding";;
  NEW-ACCOUNT)          echo "user account created inside the recency window";;
  RECENT)               echo "created/modified inside the recency window (cross-ref FSEvents) — often a normal update";;
  *)                    echo "";;
esac; }
print_legend(){
  [ -z "$FIRED" ] && return
  printf '\n----- flags seen this run (what each means) -----\n'
  local f h
  for f in $FIRED; do h=$(flag_help "$f"); printf '  %-22s %s\n' "$f" "$h"; done
}

# All human home directories INCLUDING root (/var/root). Every per-user artifact
# check iterates this, so we cover all users + root uniformly (needs sudo to read
# other users' files; unreadable ones degrade to nothing/??).
user_homes(){
  if [ -n "$ONLY_USER" ]; then
    [ "$ONLY_USER" = root ] && { [ -d /var/root ] && echo /var/root; return; }
    [ -d "/Users/$ONLY_USER" ] && echo "/Users/$ONLY_USER"; return
  fi
  for h in /Users/*; do
    case "$h" in */Shared|*/.localized|*/Guest) continue;; esac
    [ -d "$h" ] && echo "$h"
  done
  [ -d /var/root ] && echo /var/root
}

check_orphan(){ [ -n "$1" ] && [ ! -e "$1" ] && flag ORPHAN; }
check_path(){ echo "$1" | grep -qiE '/tmp/|/private/tmp/|/var/tmp/|/Users/Shared/|/private/var/folders/|/\.[A-Za-z]' && flag SUSPICIOUS-PATH; }
check_interp(){ echo "$1" | grep -qiE 'sh -c|/bin/bash|/bin/zsh|/bin/sh|python|perl|ruby|osascript|curl|wget|nscurl|base64|eval|/dev/tcp|/dev/udp| nc | ncat|xxd' && flag INTERP/DOWNLOAD; }

check_recent(){
  local mt; mt=$(stat -f %m "$1" 2>/dev/null); [ -z "$mt" ] && return
  if [ -n "$SINCE_EPOCH" ]; then
    [ "$mt" -ge "$SINCE_EPOCH" ] && flag "RECENT>=${SINCE_DATE}"
  else
    [ $(((NOW-mt)/86400)) -lt "$RECENT" ] && flag "RECENT<${RECENT}d"
  fi
}

# vendor_name: the signer's name from `codesign -dvvv` output — "Sophos", "Apple", "" (ad-hoc).
vendor_name(){ # $1 = codesign -dvvv output
  local cs="$1" name
  name=$(printf '%s' "$cs" | sed -n 's/.*Authority=Developer ID Application: //p' | head -1 | sed -E 's/ \([A-Z0-9]{10}\)$//')
  [ -n "$name" ] && { echo "$name"; return; }
  printf '%s' "$cs" | grep -qiE 'Authority=Apple Mac OS Application Signing' && { echo "App Store"; return; }
  printf '%s' "$cs" | grep -qiE 'Authority=(Software Signing|Apple Root CA)' && { echo "Apple"; return; }
  echo ""
}
# check_sig — the shared signature verdict.
#
# DEFAULT (fast, offline): `codesign -dvvv` → shows WHO signed it — "signed: Sophos", "Apple",
# "unsigned". Bare binaries also get `codesign --verify` (reliable, catches tampering). No spctl.
#
# OPT-IN Gatekeeper (spctl) — an assessment is 4–24s/app (network notarization lookup):
#   --gk           → run spctl on EVERY item (any status)
#   --gk-unsigned  → run spctl ONLY on unsigned items
# Both run on every persistence object, any mode. spctl only truly assesses .app/installer bundles;
# on a BARE binary it returns "rejected (the code is valid but does not seem to be an app)" — that
# is NOT a notarization failure, so we detect that reason and skip it (no bracket, no flag). Only a
# genuine rejection (no usable signature / unnotarized / revoked) becomes [not notarized].
check_sig(){ # $1 = target path
  local bin="$1" tgt cs t v sp unsigned=""
  SIG_TEAM=""
  { [ -z "$bin" ] || [ ! -e "$bin" ]; } && { SIG="no target"; return; }
  case "$bin" in *.app/*) tgt="${bin%%.app/*}.app";; *) tgt="$bin";; esac
  cs=$(codesign -dvvv "$tgt" 2>&1)
  case "$cs" in *[Pp]ermission\ denied*|*[Nn]o\ such\ file*|*not\ readable*) SIG="unreadable (needs root)"; return;; esac
  # ---- signer verdict (fast, offline) ----
  if printf '%s' "$cs" | grep -qi 'not signed\|no signature\|code object is not signed'; then
    flag UNSIGNED; SIG="unsigned"; unsigned=1
  else
    t=$(printf '%s' "$cs" | awk -F= '/TeamIdentifier=/{print $2}'); [ "$t" = "not set" ] && t=""
    SIG_TEAM="$t"; v=$(vendor_name "$cs")
    case "$tgt" in
      *.app) [ "$v" = Apple ] && SIG="Apple" || SIG="signed: ${v:-ad-hoc}";;
      *)     # bare Mach-O: codesign --verify is the reliable tamper check
        if codesign --verify "$tgt" 2>/dev/null; then [ "$v" = Apple ] && SIG="Apple" || SIG="signed: ${v:-ad-hoc}"
        else flag SIG-INVALID; SIG="invalid (tampered)"; fi;;
    esac
  fi
  # ---- opt-in Gatekeeper (spctl) — runs on EVERY item type when requested ----
  if [ "$GK_MODE" = all ] || { [ "$GK_MODE" = unsigned ] && [ -n "$unsigned" ]; }; then
    sp=$(spctl -a -vv -t exec "$tgt" 2>&1)
    case "$sp" in
      *accepted*)                     NOTARY="notarized";;                    # notarized app
      *"does not seem to be an app"*) : ;;                                    # valid bare binary — spctl can't app-assess it; code IS valid → no verdict, no flag
      *rejected*)                     NOTARY="not notarized"                  # genuine reject: no usable sig / unnotarized / revoked
        [ -z "$unsigned" ] && case " $FLAGS " in *" SIG-INVALID "*) ;; *) flag SIG-INVALID;; esac;;   # a *signed* item Gatekeeper rejects = suspect
      *)                              : ;;                                    # could not assess (PWAs / stubs)
    esac
  fi
}
# Signature shown to the analyst: verdict only in regular output; verdict + Team ID under --verbose.
sig_display(){ if [ -n "$VERBOSE" ] && [ -n "$SIG_TEAM" ]; then echo "$SIG  (team $SIG_TEAM)"; else echo "$SIG"; fi; }
# Notarization renders as its OWN bracket after the signer bracket → "[signed: Vendor] [notarized]"
notary_suffix(){ [ -n "$NOTARY" ] && printf ' [%s]' "$NOTARY"; }

collect_flags(){ local f; for f in $1; do case "$f" in RECENT*) f=RECENT;; esac; case " $FIRED " in *" $f "*) ;; *) FIRED="$FIRED $f";; esac; done; }
# Only prints fields that have content — no "sig: n/a" noise for config-file items (no signature).
detail(){ # $1=tag $2=label $3=path $4=exec $5=extra
  printf '\n%s %s\n   path : %s\n' "$1" "$2" "$3"
  [ -n "$4" ] && [ "$4" != "<none>" ] && [ "$4" != "$3" ] && printf '   exec : %s\n' "$4"   # skip when exec == path (BTM/login-helper/hook items)
  case "$SIG" in n/a|"no target") ;; *) printf '   sig  : %s%s\n' "$(sig_display)" "$(notary_suffix)";; esac   # "no target" == orphan; ORPHAN flag already says so
  [ -n "$5" ] && printf '   info : %s\n' "$5"
  [ -n "$FLAGS" ] && printf '   FLAGS:%s\n' "$FLAGS"
}
report(){ # $1=label $2=path $3=exec $4=extra_kv
  SEC_COUNT=$((SEC_COUNT+1))
  if [ -n "$FLAGS" ]; then
    local t; t=$(tier)
    case "$t" in HIGH) HI=$((HI+1));; NOTABLE) NO=$((NO+1));; LOW) LO=$((LO+1));; esac
    collect_flags "$FLAGS"
    [ "$(rank "$t")" -ge "$MIN_SEV" ] && detail "[$t]" "$1" "$2" "$3" "$4"
  else
    OK=$((OK+1))
    if [ -n "$VERBOSE" ]; then detail "[ ok ]" "$1" "$2" "$3" "$4"
    elif [ -z "$SUSPECT_ONLY" ]; then
      case "$SIG" in n/a|"no target") printf '  ok  %s\n' "$1";; *) printf '  ok  %-46s [%s]%s\n' "$1" "$(sig_display)" "$(notary_suffix)";; esac
    fi
  fi
}

# ---------- host context (always shown) ----------
host_posture(){
  local sip gk
  sip=$(csrutil status 2>/dev/null | sed -n 's/.*status: *//p' | tr -d '.')
  gk=$(spctl --status 2>/dev/null)
  printf '\n----- Host Posture -----\n'
  case "$sip" in
    *enabled*) printf '  SIP        : enabled\n';;
    '')        printf '  SIP        : unknown (need root / non-recovery)\n';;
    *)         printf '  SIP        : %s   <-- SIP WEAKENED — major protection loss\n' "$sip";;
  esac
  case "$gk" in
    *enabled*)  printf '  Gatekeeper : enabled\n';;
    *disabled*) printf '  Gatekeeper : DISABLED   <-- unsigned/unnotarized apps allowed\n';;
    *)          printf '  Gatekeeper : %s\n' "${gk:-unknown}";;
  esac
}

# Convert a `last`-style "Mmm DD HH:MM" (already UTC via TZ) to "YYYY-MM-DD HH:MM:SS".
# last has no seconds (→ :00) and no year (→ current year assumed).
fmt_last_time(){
  local dt out; dt=$(printf '%s' "$1" | grep -oE '[A-Z][a-z][a-z] +[0-9]{1,2} +[0-9]{2}:[0-9]{2}' | head -1)
  [ -z "$dt" ] && { echo ""; return; }
  # `last` has no seconds — format to the minute and pin seconds to :00 (don't let date fill wall-clock seconds)
  out=$(date -u -j -f "%Y %b %e %H:%M" "$(date -u +%Y) $(printf '%s' "$dt" | tr -s ' ')" "+%Y-%m-%d %H:%M" 2>/dev/null)
  [ -n "$out" ] && echo "${out}:00"
}

account_summary(){
  section "User accounts (times UTC)  (T1136 — Create Account)"
  # AD binding context: on a bound Mac, pure NETWORK accounts live in the AD node and are not
  # enumerable via the local node below — say so, so their absence isn't mistaken for "clean".
  local adinfo; adinfo=$(dsconfigad -show 2>/dev/null | awk -F'= ' '/Active Directory Domain/{print $2}')
  [ -n "$adinfo" ] && printf '  AD-bound to: %s  (pure network accounts live in the AD node — not fully enumerable locally)\n' "$adinfo"
  printf '  %-16s %-6s %-9s %-6s %-12s %-20s %-20s %s\n' USER UID TYPE ADMIN LOGIN-SCRN CREATED LAST-LOGIN SHELL
  local hiddenlist u uid home shell hidden bmt born llt lscreen new note isadmin typ aa
  hiddenlist=$(defaults read /Library/Preferences/com.apple.loginwindow HiddenUsersList 2>/dev/null)
  while read -r u uid; do
    case "$uid" in ''|*[!0-9]*) continue;; esac
    case "$u" in _*) continue;; esac                   # skip Apple `_service` accounts (naming convention)
    shell=$(dscl . -read /Users/"$u" UserShell 2>/dev/null | awk '{print $2}')
    # Skip pure service accounts: a non-login shell (false/nologin) = not an interactive user.
    # NOTE: we do NOT skip low UIDs here — a NON-`_` UID<500 account WITH a real login shell is a
    # classic TA hiding trick, so those are surfaced and flagged below.
    case "$shell" in */false|*/nologin|/dev/null|/usr/sbin/uucico|'') continue;; esac
    home=$(dscl . -read /Users/"$u" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
    hidden=$(dscl . -read /Users/"$u" IsHidden 2>/dev/null | awk '{print $2}')
    # Effective admin (catches AD-group-mapped admins that the local admin group misses)
    isadmin=no; dsmemberutil checkmembership -U "$u" -G admin 2>/dev/null | grep -qi 'is a member' && isadmin=yes
    # Account type from AuthenticationAuthority
    aa=$(dscl . -read /Users/"$u" AuthenticationAuthority 2>/dev/null)
    case "$aa" in
      *LocalCachedUser*) typ="mobile-AD";;
      *Kerberosv5*Kerberos*|*NetLogon*) typ="network";;
      *ShadowHash*|*) typ="local";;
    esac
    bmt=$(stat -f %B "$home" 2>/dev/null)
    born=$([ -n "$bmt" ] && date -u -r "$bmt" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo unknown)
    llt=$(fmt_last_time "$(TZ=UTC last -1 "$u" 2>/dev/null | grep -vE '^wtmp|^$' | head -1)"); [ -z "$llt" ] && llt="never"
    lscreen=shown
    case "$hidden" in 1|true|TRUE) lscreen=hidden;; esac
    printf '%s' "$hiddenlist" | grep -q "\"$u\"" && lscreen=hidden
    new=""; if [ -n "$bmt" ]; then
      if [ -n "$SINCE_EPOCH" ]; then [ "$bmt" -ge "$SINCE_EPOCH" ] && new=1
      else [ $(((NOW-bmt)/86400)) -lt "$RECENT" ] && new=1; fi
    fi
    note=""
    if [ "$lscreen" = hidden ]; then HI=$((HI+1)); collect_flags HIDDEN-ACCOUNT; note="   <== HIDDEN from login screen (backdoor?)"
    elif [ "$uid" -gt 0 ] && [ "$uid" -lt 500 ]; then NO=$((NO+1)); collect_flags LOW-UID-ACCOUNT; note="   <== system UID but interactive shell (hiding?)"
    elif [ -n "$new" ]; then NO=$((NO+1)); collect_flags NEW-ACCOUNT; note="   <== created inside recency window"; fi
    printf '  %-16s %-6s %-9s %-6s %-12s %-20s %-20s %s%s\n' "$u" "$uid" "$typ" "$isadmin" "$lscreen" "$born" "$llt" "$shell" "$note"
    SEC_COUNT=$((SEC_COUNT+1))
  done < <(dscl . -list /Users UniqueID 2>/dev/null)
}

recent_logins(){
  section "Recent logins (last 5, UTC)"
  local out; out=$(TZ=UTC last 2>/dev/null | grep -vE '^wtmp|^$|^reboot|^shutdown' | head -5)
  [ -n "$out" ] && { echo "$out" | sed 's/^/  /'; SEC_COUNT=1; }
}

module_apps(){
  section "Installed non-Apple apps  (name · sha256 · signature; grouped by location)"
  # Verdict via check_sig: default = signer ("signed: Vendor", fast); add --gk / --gk-unsigned
  # for the Gatekeeper [notarized]/[not notarized] verdict (any mode).
  local roots=(/Applications /Applications/Utilities /opt) h root app exe bid hash any sigcell note
  while IFS= read -r h; do roots+=("$h/Applications"); done < <(user_homes)
  for root in "${roots[@]}"; do
    [ -d "$root" ] || continue
    any=""
    # -prune so we don't descend INTO .app bundles (their nested helper .apps); maxdepth keeps /opt bounded
    while IFS= read -r app; do
      [ -e "$app" ] || continue
      bid=$(defaults read "$app/Contents/Info" CFBundleIdentifier 2>/dev/null)
      case "$bid" in com.apple.*) continue;; esac                              # skip Apple apps (OS + App Store)
      exe="$app/Contents/MacOS/$(defaults read "$app/Contents/Info" CFBundleExecutable 2>/dev/null)"
      [ -f "$exe" ] || continue
      if [ -z "$any" ]; then printf '\n  %s/\n' "$root"; printf '    %-30s %-66s %s\n' NAME SHA-256 SIGNATURE; any=1; fi
      reset_analysis; check_sig "$app"
      hash=$(shasum -a 256 "$exe" 2>/dev/null | awk '{print $1}')
      sigcell="$SIG$(notary_suffix)"
      # Chromium browser-generated PWAs ("Add to Applications") all share ONE app_mode_loader shim
      # binary, so their sha256 is identical across PWAs — the app identity lives in Info.plist, not
      # the executable. Note it so identical hashes aren't mistaken for cloning/tampering.
      case "$exe" in */app_mode_loader) note="  (Chrome PWA — shared shim)";; *) note="";; esac
      printf '    %-30s %-66s %s%s%s\n' "$(basename "$app" .app)" "${hash:-?}" "$sigcell" \
        "$([ -n "$VERBOSE" ] && [ -n "$SIG_TEAM" ] && echo "  team=$SIG_TEAM")" "$note"
      SEC_COUNT=$((SEC_COUNT+1))
    done < <(find "$root" -maxdepth 3 -name '*.app' -prune 2>/dev/null)
  done
  # Package managers (their casks/GUI apps already appear above; formulae are CLI). Show the
  # manager, version and install prefix (asked from the tool itself — not hardcoded). The log
  # location is a documented per-user path shown as a literal pointer (not $HOME-resolved, which
  # would be wrong under sudo). Standard install paths below are how brew/MacPorts/Fink ship —
  # they only gate detection, never produce a finding.
  # Candidate manager binaries at their documented install paths (detection only — never a finding).
  # Homebrew (both arch prefixes), MacPorts, Fink, Nix, pkgsrc/pkgin, and conda/miniconda/miniforge
  # (system + per-user installs). Different hosts ship different managers, so we probe them all and
  # list whichever are present. Version/prefix are asked from the tool itself, not hardcoded.
  local pm name ver prefix logs any2="" h
  local pms=(/opt/homebrew/bin/brew /usr/local/bin/brew /opt/local/bin/port /sw/bin/fink \
             /nix/var/nix/profiles/default/bin/nix /run/current-system/sw/bin/nix /opt/pkg/bin/pkgin \
             /opt/anaconda3/bin/conda /opt/miniconda3/bin/conda /opt/miniforge3/bin/conda)
  while IFS= read -r h; do pms+=("$h/anaconda3/bin/conda" "$h/miniconda3/bin/conda" "$h/miniforge3/bin/conda"); done < <(user_homes)
  for pm in "${pms[@]}"; do
    [ -x "$pm" ] || continue
    [ -z "$any2" ] && { printf '\n  Package managers:\n'; any2=1; }
    name=$(basename "$pm"); logs=""
    case "$name" in
      brew) ver=$("$pm" --version 2>/dev/null | head -1 | sed 's/ (.*//'); prefix=$("$pm" --prefix 2>/dev/null); logs='~/Library/Logs/Homebrew';;   # strip "(shallow or no git repository)"
      port) ver=$("$pm" version 2>/dev/null | awk '{print $NF}');           prefix=$(dirname "$(dirname "$pm")"); logs='<prefix>/var/macports/logs';;
      nix)  ver=$("$pm" --version 2>/dev/null | awk '{print $NF}');         prefix="/nix/store";;
      conda) ver=$("$pm" --version 2>/dev/null | awk '{print $NF}');        prefix=$(dirname "$(dirname "$pm")");;
      *)    ver=$("$pm" --version 2>/dev/null | head -1 | awk '{print $NF}'); prefix=$(dirname "$(dirname "$pm")");;
    esac
    printf '    %-10s %-16s prefix=%s%s\n' "$name" "${ver:-?}" "${prefix:-?}" "${logs:+   logs=$logs}"
    SEC_COUNT=$((SEC_COUNT+1))
  done
}

# ---------- modules ----------
module_launchd(){
  section "Launch Agents & Daemons  (T1543.001/.004)"
  local dirs=(/Library/LaunchDaemons /Library/LaunchAgents)
  while IFS= read -r h; do dirs+=("$h/Library/LaunchAgents"); done < <(user_homes)
  local d p label bin args ral ka first
  for d in "${dirs[@]}"; do
    [ -d "$d" ] || continue
    first=1                                     # print the directory once, then its items under it
    for p in "$d"/*.plist; do
      [ -e "$p" ] || continue
      [ -n "$first" ] && { printf '\n  %s/\n' "$d"; first=""; }
      if ! plutil -p "$p" >/dev/null 2>&1; then
        UNR=$((UNR+1)); SEC_COUNT=$((SEC_COUNT+1)); printf '    ??  %-46s [unreadable — needs root]\n' "$(basename "$p" .plist)"; continue
      fi
      reset_analysis
      label=$(get Label "$p"); [ -z "$label" ] && label=$(basename "$p" .plist)
      bin=$(get Program "$p"); [ -z "$bin" ] && bin=$(get ProgramArguments.0 "$p")
      args=$(plutil -extract ProgramArguments xml1 -o - "$p" 2>/dev/null | tr -d '\n')
      case "$label" in com.apple.*) flag APPLE-MASQUERADE;; esac
      check_orphan "$bin"; check_path "$bin $args"; check_interp "$args"
      plutil -extract EnvironmentVariables xml1 -o - "$p" 2>/dev/null | grep -qi 'DYLD_INSERT_LIBRARIES' && flag DYLD-INJECT
      check_recent "$p"; check_sig "$bin"
      ral=$(get RunAtLoad "$p"); ka=$(get KeepAlive "$p")
      # Surface the trigger keys (context, not scored): beaconing / event-triggered / session
      local si llt trig=""
      si=$(get StartInterval "$p"); [ -n "$si" ] && trig="$trig StartInterval=${si}s"
      plutil -extract StartCalendarInterval xml1 -o - "$p" >/dev/null 2>&1 && trig="$trig CalendarInterval"
      plutil -extract WatchPaths        xml1 -o - "$p" >/dev/null 2>&1 && trig="$trig WatchPaths"
      plutil -extract QueueDirectories  xml1 -o - "$p" >/dev/null 2>&1 && trig="$trig QueueDirectories"
      [ "$(get StartOnMount "$p")" = true ] && trig="$trig StartOnMount"
      llt=$(get LimitLoadToSessionType "$p"); [ -n "$llt" ] && trig="$trig Session=$llt"
      report "$label" "$(basename "$p")" "$bin" "RunAtLoad=${ral:-no} KeepAlive=${ka:-no}${trig:+  trig:$trig}"
    done
  done
}

module_cron(){
  section "Cron / at / periodic  (T1053.003/.002)" "No cron, at, or periodic jobs present"
  # Root-only spool dirs (700 root:wheel). If they exist but we can't read them, SAY SO — otherwise a
  # non-root run silently reports "no cron jobs" (false-negative) while a planted crontab sits unseen.
  local d
  for d in /usr/lib/cron/tabs /var/at/jobs; do
    if [ -d "$d" ] && ! ls "$d" >/dev/null 2>&1; then
      UNR=$((UNR+1)); SEC_COUNT=$((SEC_COUNT+1))
      printf '  ??  %-46s [unreadable — needs root; planted crontabs here would be missed]\n' "$d"
    fi
  done
  local tabs=(/etc/crontab) f body
  for f in /usr/lib/cron/tabs/* /etc/cron.d/*; do [ -e "$f" ] && tabs+=("$f"); done
  for f in "${tabs[@]}"; do
    [ -e "$f" ] || continue
    body=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null | tr '\n' ';')
    [ -z "$body" ] && continue
    reset_analysis; flag CRONTAB-PRESENT
    check_interp "$body"; check_path "$body"; check_recent "$f"
    report "crontab:$(basename "$f")" "$f" "" "lines=[$body]"
  done
  for f in /etc/periodic/*/* /usr/local/etc/periodic/*/* /etc/daily.local /etc/weekly.local /etc/monthly.local /etc/periodic.local; do
    [ -f "$f" ] || continue
    reset_analysis
    case "$f" in /usr/local/*) flag NONSTANDARD-PERIODIC;; /etc/*.local) flag LOCAL-PERIODIC-OVERRIDE;; esac
    body=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null | tr '\n' ';')
    check_interp "$body"; check_path "$body"; check_recent "$f"
    report "periodic:$(basename "$f")" "$f" "" ""
  done
  for f in /var/at/jobs/*; do
    [ -f "$f" ] || continue
    reset_analysis; flag AT-JOB-PRESENT
    check_interp "$(tr '\n' ';' < "$f" 2>/dev/null)"; check_recent "$f"
    report "at:$(basename "$f")" "$f" "" ""
  done
  if launchctl print-disabled system 2>/dev/null | grep -i atrun | grep -qi 'false'; then
    reset_analysis; flag ATRUN-ENABLED
    report "com.apple.atrun" "launchctl print-disabled system" "" "atrun enabled (disabled by default)"
  fi
}

module_loginitems(){
  section "Login Items & Background Tasks  (T1547.015)  — login items, agents/daemons (BTM), login helpers, hooks" "No login items, helpers, or hooks found"
  local name path disp state
  # 1. Modern Background Task Management database (state column: enabled/disabled)
  local name path disp typ state kind meaning extra
  while IFS=$'\t' read -r name path disp typ; do
    [ -z "$name" ] && continue
    case "$disp" in *disabled*) state="disabled";; *enabled*) state="enabled ";; *) state="?       ";; esac
    case "$typ" in *daemon*) kind="daemon (runs as root at boot)";; *agent*) kind="agent (runs at your login)";; *app*) kind="login item (app opens at login)";; *) kind="background item";; esac
    # Plain-English meaning so a junior analyst can act on it
    case "$disp" in
      *enabled*disallowed*) meaning="ENABLED but user has NOT allowed it (blocked) — $kind";;
      *enabled*)            meaning="ENABLED — auto-runs; $kind";;
      *disabled*)           meaning="disabled — registered but not running; $kind";;
      *)                    meaning="$kind";;
    esac
    extra="$meaning"; [ -n "$VERBOSE" ] && extra="$meaning   [raw disposition: $disp]"
    reset_analysis
    check_orphan "$path"; check_path "$path"; check_sig "$path"
    report "$state btm:$name" "${path:-<no exec path>}" "$path" "$extra"
  done < <(sfltool dumpbtm 2>/dev/null | awk '
    /^[[:space:]]*$/ { if(n!="" && p!=""){print n"\t"p"\t"d"\t"ty}; n="";p="";d="";ty=""; next }
    /Name:/ && n=="" { sub(/^[^:]*:[[:space:]]*/,""); n=$0 }
    /Executable Path:/ { sub(/^[^:]*:[[:space:]]*/,""); p=$0 }
    /Disposition:/ { sub(/^[^:]*:[[:space:]]*/,""); d=$0 }
    /Type:/ { sub(/^[^:]*:[[:space:]]*/,""); ty=$0 }
    END { if(n!="" && p!=""){print n"\t"p"\t"d"\t"ty} }')     # skip developer/grouping records with no exec path
  # 2. SMLoginItem helper apps bundled inside installed apps
  local apps=(/Applications/*/Contents/Library/LoginItems/*.app) app h u f p
  while IFS= read -r h; do apps+=("$h"/Applications/*/Contents/Library/LoginItems/*.app); done < <(user_homes)
  for app in "${apps[@]}"; do
    [ -e "$app" ] || continue
    reset_analysis
    # Don't flag a login helper just for existing — a verified/notarized helper is fine (→ ok).
    # Let signature/path/recency decide; only genuinely suspicious ones get flagged.
    check_path "$app"; check_sig "$app"; check_recent "$app"
    report "loginhelper:$(basename "$app")" "$app" "$app" ""
  done
  # 3. Reopen-at-login list — resolve and analyse each entry
  while IFS= read -r h; do
    u=$(basename "$h"); f="$h/Library/Preferences/com.apple.loginwindow.plist"
    [ -e "$f" ] || continue
    while IFS= read -r p; do
      [ -z "$p" ] && continue
      reset_analysis; flag RELAUNCH-AT-LOGIN
      check_orphan "$p"; check_path "$p"; check_sig "$p"; check_recent "$f"
      report "relaunch:$u:$(basename "$p")" "$p" "$p" ""
    done < <(plutil -extract TALAppsToRelaunchAtLogin xml1 -o - "$f" 2>/dev/null \
             | grep -oE '<string>[^<]*</string>' | sed -E 's|</?string>||g' | grep -E '\.app$|^/')
  done < <(user_homes)
  # 4. Legacy per-user login items plist
  while IFS= read -r h; do
    f="$h/Library/Preferences/com.apple.loginitems.plist"
    [ -e "$f" ] || continue
    reset_analysis; flag LEGACY-LOGINITEM; check_recent "$f"
    report "legacy-loginitems:$(basename "$h")" "$f" "" "review CustomListItems entries"
  done < <(user_homes)
  # 5. Login / Logout hooks (deprecated — run a script at login/logout; almost nothing legit uses them)
  local key hook
  while IFS= read -r h; do
    f="$h/Library/Preferences/com.apple.loginwindow.plist"
    [ -e "$f" ] || continue
    for key in LoginHook LogoutHook; do
      hook=$(get "$key" "$f"); [ -z "$hook" ] && continue
      reset_analysis
      [ "$key" = LoginHook ] && flag LOGIN-HOOK || flag LOGOUT-HOOK
      check_path "$hook"; check_orphan "$hook"; check_sig "$hook"; check_recent "$f"
      report "$key:$(basename "$h")" "$f" "$hook" "runs at $key"
    done
  done < <(user_homes)
  # (SharedFileList / backgrounditems.btm stores are the on-disk backing for the BTM data already
  #  parsed above via `sfltool dumpbtm`; listing the raw files adds no value, so they're omitted.)
}

module_sysext(){
  section "System Extensions & Kexts  (T1547.006)"
  local c1 c2 team bundle name state cat="" line bid extpath
  while IFS= read -r line; do
    case "$line" in
      '--- '*) cat=$(echo "$line" | awk '{print $2}'); cat="${cat##*.}"; continue;;   # category header
    esac
    IFS=$'\t' read -r c1 c2 team bundle name state <<<"$line"
    echo "$team" | grep -qE '^[A-Z0-9]{10}$' || continue      # a real ext row has a 10-char teamID
    case "$bundle" in com.apple.*) continue;; esac
    bid="${bundle%% *}"
    reset_analysis; flag THIRD-PARTY-SYSEXT
    # Resolve the activated on-disk bundle and verify ITS signature (not just the list's Team ID)
    extpath=$(find /Library/SystemExtensions -type d -name "${bid}.systemextension" 2>/dev/null | head -1)
    if [ -n "$extpath" ]; then check_sig "$extpath"; check_recent "$extpath"; else SIG="activated (on-disk bundle not found)"; SIG_TEAM="$team"; extpath="/Library/SystemExtensions (activated)"; fi
    # Endpoint Security / Network extensions see all events or all traffic — elevate for review
    case "$cat" in endpoint_security|network_extension) flag HIGH-RISK-SYSEXT;; esac
    report "sysext:$bid" "$extpath" "$bid" "type=${cat:-?} state=$state"
  done < <(systemextensionsctl list 2>/dev/null)
  # (NetworkExtension provider = the sysext itself, already surfaced above; the
  #  com.apple.networkextension*.plist files are OS bookkeeping, not rogue configs.)
  # Third-party kexts on disk
  local k
  for k in /Library/Extensions/*.kext /System/Library/Extensions/*.kext.disabled; do
    [ -e "$k" ] || continue
    reset_analysis; flag THIRD-PARTY-KEXT
    check_sig "$k"; check_recent "$k"
    report "kext:$(basename "$k")" "$k" "$k" ""
  done
  # Third-party kexts actually LOADED in the kernel (may lack a /Library/Extensions bundle)
  local kb
  while read -r kb; do
    [ -z "$kb" ] && continue
    reset_analysis; flag THIRD-PARTY-KEXT-LOADED; SIG="loaded"
    report "kext-loaded:$kb" "kextstat" "$kb" "loaded in kernel"
  done < <(kextstat 2>/dev/null | awk 'NR>1{print $6}' | grep -vE '^com\.apple\.|^$')
}

module_helpers(){
  section "Privileged Helper Tools  (T1543.004 / SMJobBless + SMAppService)"
  local h base helperteam reqline reqteam declaredby app plist smp k
  # One pass over apps: build a map "helperid<TAB>requiredTeamID<TAB>appName" from every app that
  # declares a helper via the (legacy) SMPrivilegedExecutables trust link. Modern SMAppService
  # helpers won't appear here — that is NORMAL, so absence is context, never a finding.
  local map; map=$(for app in /Applications/*.app; do
    plist="$app/Contents/Info.plist"; [ -e "$plist" ] || continue
    smp=$(plutil -extract SMPrivilegedExecutables xml1 -o - "$plist" 2>/dev/null) || continue
    echo "$smp" | awk -v a="$(basename "$app")" '
      /<key>/   { k=$0; gsub(/.*<key>|<\/key>.*/,"",k) }
      /<string>/{ s=$0; gsub(/.*<string>|<\/string>.*/,"",s);
                  if (match(s,/[A-Z0-9]{10}/)) t=substr(s,RSTART,10); else t="";
                  if (k!=""){ print k"\t"t"\t"a; k="" } }'
  done)
  for h in /Library/PrivilegedHelperTools/*; do
    [ -e "$h" ] || continue
    reset_analysis
    base=$(basename "$h")
    check_path "$h"; check_sig "$h"; check_recent "$h"
    helperteam=$(codesign -dvvv "$h" 2>&1 | awk -F= '/TeamIdentifier=/{print $2}')
    # Every legit helper is launched by a LaunchDaemon that references it; a helper with none is odd
    grep -rlq "$base" /Library/LaunchDaemons/ 2>/dev/null || flag HELPER-NO-DAEMON
    # Trust link: if an app DOES declare this helper, its required Team ID must match the helper's.
    reqline=$(printf '%s\n' "$map" | awk -F'\t' -v b="$base" '$1==b{print;exit}')
    reqteam=$(printf '%s' "$reqline" | cut -f2); declaredby=$(printf '%s' "$reqline" | cut -f3)
    if [ -n "$declaredby" ] && [ -n "$helperteam" ] && [ -n "$reqteam" ] && [ "$helperteam" != "$reqteam" ]; then
      flag HELPER-TRUST-MISMATCH                               # app requires a different Team ID than the helper is signed by
    fi
    report "helper:$base" "$h" "$h" "declared-by=${declaredby:-none (SMAppService or standalone)}"
  done
}

module_ssh(){
  section "SSH keys, config & activity  (T1098.004 / T1563.001)  — mtimes show when SSH was last used" "No SSH keys or config found for any user"
  local h f n acct mt mtu
  while IFS= read -r h; do
    acct=$(basename "$h")
    [ -d "$h/.ssh" ] || continue
    # authorized_keys (INBOUND — planted backdoor keys). last-modified ~ when a key was added/used.
    for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do
      [ -e "$f" ] || continue
      reset_analysis; flag AUTHORIZED_KEYS-PRESENT
      case "$acct" in root|daemon|nobody|_*) flag ROOT-SSH-KEY;; esac    # root/service keys = high-value
      grep -qE 'command=|no-pty|permitopen=|environment=' "$f" 2>/dev/null && flag FORCED-OPTIONS
      check_recent "$f"
      n=$(grep -cvE '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null)
      mt=$(stat -f %m "$f" 2>/dev/null); mtu=$([ -n "$mt" ] && date -u -r "$mt" '+%Y-%m-%d %H:%M:%S UTC')
      report "authorized_keys:$acct" "$f" "" "keys=$n  last-modified=${mtu:-?}"
    done
    # known_hosts (OUTBOUND — hosts this account SSH'd TO = lateral movement) + last outbound activity.
    f="$h/.ssh/known_hosts"
    if [ -e "$f" ]; then
      reset_analysis
      n=$(grep -cvE '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null)
      mt=$(stat -f %m "$f" 2>/dev/null); mtu=$([ -n "$mt" ] && date -u -r "$mt" '+%Y-%m-%d %H:%M:%S UTC')
      check_recent "$f"
      report "known_hosts:$acct" "$f" "" "outbound-hosts=$n  last-modified=${mtu:-?}"
    fi
    # private keys on the host (material for lateral movement) + last-modified.
    for f in "$h/.ssh"/id_* "$h/.ssh"/*.pem; do
      [ -f "$f" ] || continue
      case "$f" in *.pub) continue;; esac
      reset_analysis
      mt=$(stat -f %m "$f" 2>/dev/null); mtu=$([ -n "$mt" ] && date -u -r "$mt" '+%Y-%m-%d %H:%M:%S UTC')
      check_recent "$f"
      report "private-key:$acct/$(basename "$f")" "$f" "" "last-modified=${mtu:-?}"
    done
    # ssh client config
    f="$h/.ssh/config"
    if [ -e "$f" ]; then
      reset_analysis
      grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -qiE 'LocalCommand|ProxyCommand|Match[[:space:]]+exec|PermitLocalCommand' && flag SSH-CONFIG-EXEC
      check_recent "$f"
      report "ssh_config:$acct" "$f" "" ""
    fi
  done < <(user_homes)
  local body
  for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*; do
    [ -e "$f" ] || continue
    reset_analysis
    body=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null)
    echo "$body" | grep -qiE 'ForceCommand|AuthorizedKeysCommand|PermitRootLogin[[:space:]]+yes' && flag SSHD-EXEC-DIRECTIVE
    # AuthorizedKeysFile is benign at its default (.ssh/authorized_keys); flag only an absolute/redirected path
    echo "$body" | grep -iE '^[[:space:]]*AuthorizedKeysFile' | grep -qE '(^|[[:space:]])/' && flag SSHD-EXEC-DIRECTIVE
    check_recent "$f"
    report "sshd:$(basename "$f")" "$f" "" ""
  done
  # Remote Login (sshd) enabled? Best-effort read-only check — confirm it should be on.
  if launchctl print-disabled system 2>/dev/null | grep -i 'com.openssh.sshd' | grep -qi 'false'; then
    reset_analysis; flag REMOTE-LOGIN-ON
    report "remote-login (sshd)" "launchctl print-disabled system" "" "sshd enabled — confirm expected"
  fi
}

module_dylib(){
  section "Dylib injection / hijack  (T1574.006/.001/.004)" "No dylib injection or hijack indicators found"
  local v; v=$(launchctl getenv DYLD_INSERT_LIBRARIES 2>/dev/null)
  if [ -n "$v" ]; then
    reset_analysis; flag DYLD-GLOBAL; check_path "$v"
    report "launchd DYLD_INSERT_LIBRARIES" "launchctl getenv" "$v" ""
  fi
  # launchd.conf is read very early — DYLD/setenv here injects into everything (deprecated but honored on older macOS)
  local c
  for c in /etc/launchd.conf /Users/*/.launchd.conf; do
    [ -e "$c" ] || continue
    grep -qi 'DYLD_INSERT_LIBRARIES\|setenv DYLD' "$c" 2>/dev/null || continue
    reset_analysis; flag DYLD-GLOBAL; check_recent "$c"
    report "launchd.conf:$c" "$c" "" "$(grep -i 'DYLD\|setenv' "$c" 2>/dev/null | tr '\n' ';')"
  done
  # Staged/planted dylibs in classic drop dirs (bounded — no home-wide scan)
  local d f
  for d in /tmp /private/tmp /var/tmp /Users/Shared; do
    [ -d "$d" ] || continue
    while IFS= read -r f; do
      [ -e "$f" ] || continue
      reset_analysis; flag STAGED-DYLIB; check_path "$f"; check_sig "$f"; check_recent "$f"
      report "dylib:$(basename "$f")" "$f" "$f" ""
    done < <(find "$d" -maxdepth 4 -type f \( -name '*.dylib' -o -name '*.so' \) 2>/dev/null)
  done
  # Hijackable weak-dylib slots: LC_LOAD_WEAK_DYLIB in a third-party app whose target is MISSING
  # AND lives in a WRITABLE (non-SIP) location = a slot an attacker can drop a dylib into.
  # Weak links to /usr/lib and /System are normal (dyld shared cache) and SIP-protected — an
  # attacker cannot plant there, so they are never hijackable and are excluded. @rpath refs are
  # resolved against the binary's LC_RPATH list (and @loader_path/@executable_path within it).
  local app exe wd rel bid rpaths rp resolved found
  for app in /Applications/*.app; do
    [ -e "$app" ] || continue
    bid=$(defaults read "$app/Contents/Info" CFBundleIdentifier 2>/dev/null)
    case "$bid" in com.apple.*) continue;; esac   # Apple apps have library validation; skip
    exe="$app/Contents/MacOS/$(defaults read "$app/Contents/Info" CFBundleExecutable 2>/dev/null)"
    [ -x "$exe" ] || continue
    # collect this binary's runtime search paths (LC_RPATH), resolving @loader/@executable_path
    rpaths=$(otool -l "$exe" 2>/dev/null | awk '/LC_RPATH/{r=1;next} r&&/ path /{print $2;r=0}')
    while IFS= read -r wd; do
      case "$wd" in
        /usr/lib/*|/System/*|/Library/Apple/*) continue;;   # SIP-protected / dyld cache — not hijackable
        /*) [ -e "$wd" ] && continue;;                        # absolute path present → fine
        @loader_path/*|@executable_path/*) rel="${wd#@*path/}"; [ -e "$(dirname "$exe")/$rel" ] && continue;;
        @rpath/*)                                            # resolve against each LC_RPATH entry
          rel="${wd#@rpath/}"; found=""
          while IFS= read -r rp; do
            [ -z "$rp" ] && continue
            case "$rp" in @loader_path*|@executable_path*) rp="$(dirname "$exe")/${rp#@*path/}";; esac
            [ -e "$rp/$rel" ] && { found=1; break; }
          done <<EOF
$rpaths
EOF
          [ -n "$found" ] && continue;;                       # resolved somewhere → fine
        *) continue;;                                        # other relative form — skip
      esac
      reset_analysis; flag WEAK-DYLIB-HIJACKABLE; check_recent "$app"
      report "weakdylib:$(basename "$app")" "$exe" "$wd" "weak-dylib target missing in a writable path — hijackable slot"
    done < <(otool -l "$exe" 2>/dev/null | awk '/LC_LOAD_WEAK_DYLIB/{w=1;next} w&&/ name /{print $2;w=0}')
  done
}

module_shell(){
  section "Shell & terminal init files  (T1546.004)  — bash · zsh · sh · fish · tcsh/csh · ksh · iTerm2" "No shell/terminal init anomalies found"
  # System-wide init for every shell family
  local files=(/etc/zprofile /etc/zshrc /etc/zshenv /etc/profile /etc/bashrc /etc/bash.bashrc \
               /etc/paths /etc/paths.d/* /etc/zprofile.d/* /etc/profile.d/* \
               /etc/csh.cshrc /etc/csh.login /usr/local/etc/fish/config.fish) h r f body
  # Per-user init for every shell family + iTerm2 auto-launch scripts (all users incl root)
  while IFS= read -r h; do
    for r in .zshrc .zprofile .zshenv .zlogin .zlogout \
             .bash_profile .bashrc .bash_login .bash_logout .profile \
             .tcshrc .cshrc .login .logout .kshrc \
             .config/fish/config.fish; do files+=("$h/$r"); done
    # iTerm2 runs any script in this dir on launch — a real persistence spot
    for s in "$h/Library/Application Support/iTerm2/Scripts/AutoLaunch"/* \
             "$h/Library/Application Support/iTerm2/DynamicProfiles"/*; do
      [ -f "$s" ] && files+=("$s")
    done
  done < <(user_homes)
  # Tighter than the shared check_interp: shell rc files legitimately contain
  # `eval "$(brew shellenv)"`, interpreter names, and ~/.dotfile paths. Only flag
  # patterns that are genuinely malicious in a login script (download / decode /
  # reverse shell / inline interpreter one-liner / anti-forensics).
  local evil='curl |wget |nscurl|base64|/dev/tcp/|/dev/udp/|nc -e| ncat |bash -i|python[0-9]? -c|perl -e|ruby -e|osascript -e|unset HISTFILE|history -c'
  local s
  for f in "${files[@]}"; do
    [ -f "$f" ] || continue
    reset_analysis
    body=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null | tr '\n' ';')
    [ -z "$body" ] && continue
    echo "$body" | grep -qiE "$evil" && flag INTERP/DOWNLOAD
    echo "$body" | grep -qi 'DYLD_INSERT_LIBRARIES\|DYLD_LIBRARY_PATH' && flag DYLD-IN-RC
    check_recent "$f"
    report "shell:$f" "$f" "" ""
  done
  # iTerm2 profiles that run a command / send text at login (persistence via terminal profile)
  while IFS= read -r h; do
    f="$h/Library/Preferences/com.googlecode.iterm2.plist"
    [ -e "$f" ] || continue
    if plutil -p "$f" 2>/dev/null | grep -qiE '"(Command|Initial Text|Send Text At Start)"[[:space:]]*=>[[:space:]]*"[^"]'; then
      reset_analysis; flag INTERP/DOWNLOAD; check_recent "$f"
      report "iterm2-profile:$(basename "$h")" "$f" "" "profile runs a command / sends text at start — review"
    fi
  done < <(user_homes)
}

module_longtail(){
  section "Long-tail  (emond / auth plugins / folder actions / spotlight)  (T1546)" "No long-tail persistence found"
  local f h s
  for f in /etc/emond.d/rules/*.plist; do
    [ -e "$f" ] || continue
    reset_analysis; flag EMOND-RULE; check_recent "$f"
    report "emond:$(basename "$f")" "$f" "" "emond is empty by default — any rule is suspect"
  done
  for f in /Library/Security/SecurityAgentPlugins/*.bundle /Library/Security/SecurityAgentPlugins/*.plugin; do
    [ -e "$f" ] || continue
    reset_analysis; flag AUTH-PLUGIN; check_sig "$f"; check_recent "$f"
    report "authplugin:$(basename "$f")" "$f" "$f" ""
  done
  while IFS= read -r h; do
    for s in "$h/Library/Scripts/Folder Action Scripts"/*; do
      [ -e "$s" ] || continue
      reset_analysis; flag FOLDER-ACTION; check_recent "$s"
      report "folderaction:$(basename "$s")" "$s" "" ""
    done
  done < <(user_homes)
  local imp=(/Library/Spotlight/*.mdimporter)
  while IFS= read -r h; do imp+=("$h/Library/Spotlight"/*.mdimporter); done < <(user_homes)
  for f in "${imp[@]}"; do
    [ -e "$f" ] || continue
    case "$f" in /System/*) continue;; esac
    reset_analysis; flag MDIMPORTER; check_sig "$f"; check_recent "$f"
    report "mdimporter:$(basename "$f")" "$f" "$f" ""
  done
}

module_trojan(){
  section "Trojanized binaries / apps  (T1554 / T1036)"
  local b app out rc dir actions nbin=0 napp=0
  # ALL system binaries. These dirs are on the SIP/SSV-sealed system volume, so every Mach-O in them
  # is Apple-signed by construction — any anomaly implies SIP/SSV was defeated (near-zero FP on a
  # healthy host). We flag three swap/tamper cases (all HIGH):
  #   SIG-INVALID       signed but broken seal  = patched/tampered in place
  #   UNSIGNED-SYSBIN   unsigned Mach-O          = swapped-in unsigned implant  (scripts/text are legit → skipped)
  #   NON-APPLE-SYSBIN  valid seal, non-Apple    = re-signed replacement (attacker's/ad-hoc/stolen cert)
  for dir in /bin /sbin /usr/bin /usr/sbin /usr/libexec; do
    [ -d "$dir" ] || continue
    for b in "$dir"/*; do
      [ -f "$b" ] || continue
      nbin=$((nbin+1))
      out=$(codesign --verify "$b" 2>&1); rc=$?
      if [ "$rc" -eq 0 ]; then
        # valid seal — but a platform binary must carry Apple's "Software Signing" LEAF authority.
        # (Matching "Apple Root CA" would be wrong: Developer-ID certs chain to it too, so every valid
        # macOS signature would look "Apple". "Software Signing" is Apple's private platform signer —
        # a TA cannot reproduce it, so its absence = a re-signed/replaced binary.)
        if ! codesign -dvvv "$b" 2>&1 | grep -q 'Authority=Software Signing'; then
          reset_analysis; flag NON-APPLE-SYSBIN; SIG="signed (non-Apple)"; check_recent "$b"
          report "sysbin:$b" "$b" "$b" "valid signature but NOT Apple — re-signed/replaced platform binary"
        fi
        continue
      fi
      case "$out" in
        *[Pp]ermission\ denied*|*[Nn]o\ such\ file*|*not\ readable*) UNR=$((UNR+1)); continue;;
        *not\ signed*|*no\ signature*|*code\ object\ is\ not\ signed*)
          # unsigned: anomalous ONLY if it's a Mach-O — unsigned scripts/text are legitimate here
          case "$(file -b "$b" 2>/dev/null)" in
            *Mach-O*) reset_analysis; flag UNSIGNED-SYSBIN; SIG="unsigned"; check_recent "$b"
                      report "sysbin:$b" "$b" "$b" "unsigned Mach-O in a sealed system dir (expected Apple-signed)";;
          esac
          continue;;
      esac
      # broken seal on signed code = tampered in place
      reset_analysis; flag SIG-INVALID; SIG="invalid (tampered)"; check_recent "$b"
      report "sysbin:$b" "$b" "$b" ""
    done
  done
  # Installed apps — flag ONLY broken signatures (skip merely-unsigned → low noise)
  for app in /Applications/*.app; do
    [ -e "$app" ] || continue
    napp=$((napp+1))
    codesign -dvvv "$app" 2>&1 | grep -qi 'not signed\|no signature' && continue   # unsigned legit → skip
    out=$(codesign --verify --verbose=2 "$app" 2>&1) && continue                    # valid → skip
    case "$out" in *[Pp]ermission\ denied*|*[Nn]o\ such\ file*|*not\ readable*) UNR=$((UNR+1)); continue;; esac
    # Benign seal drift: apps that write Python bytecode caches (__pycache__/*.pyc) into their
    # own bundle on first run break the seal WITHOUT being tampered. Skip pyc-only drift.
    actions=$(echo "$out" | grep -iE '^file (added|modified|missing)')
    if [ -n "$actions" ] && [ -z "$(echo "$actions" | grep -viE '__pycache__|\.pyc([[:space:]]|$)')" ]; then
      continue
    fi
    reset_analysis; flag SIG-INVALID; SIG="invalid (tampered)"; check_recent "$app"
    report "app:$(basename "$app")" "$app" "$app" ""
  done
  # Always print a summary so the section gives output (this is a bulk integrity scan, not an
  # inventory — listing every clean binary would be thousands of lines).
  printf '  Verified %d system binaries + %d /Applications apps — broken / unsigned-Mach-O / non-Apple signatures listed above are the only findings.\n' "$nbin" "$napp"
  SEC_COUNT=$((SEC_COUNT+1))
}

module_profiles(){
  section "Configuration Profiles  (T1478 — MDM/profile persistence & control)"
  # Installed configuration profiles (needs root). A profile can install LaunchDaemons,
  # trusted certs, proxies, or restrictions — persistence + control.
  local out name f
  out=$(profiles show -all 2>/dev/null)
  [ -z "$out" ] && out=$(profiles -P 2>/dev/null)
  if [ -n "$out" ]; then
    while IFS= read -r name; do
      [ -z "$name" ] && continue
      reset_analysis; flag INSTALLED-PROFILE
      report "profile:$name" "profiles show" "" "confirm this is an expected MDM/admin profile"
    done < <(echo "$out" | sed -nE 's/.*attribute: name: (.+)/\1/p')
  fi
  # MDM-managed preferences (present only on managed devices)
  if [ -d "/Library/Managed Preferences" ] && [ -n "$(ls -A '/Library/Managed Preferences' 2>/dev/null)" ]; then
    reset_analysis; flag INSTALLED-PROFILE; check_recent "/Library/Managed Preferences"
    report "managed-prefs" "/Library/Managed Preferences" "" "device is under MDM/profile management"
  fi
}

module_authmods(){
  section "Sudoers · PAM · legacy rc  (T1548.003 / T1556.003 / T1037)" "No sudoers, PAM, or rc anomalies found"
  if [ "$(id -u)" -ne 0 ]; then printf '  !! NOT running as root — /etc/sudoers and some PAM files are unreadable. Re-run with sudo.\n'; SEC_COUNT=$((SEC_COUNT+1)); fi
  local f body grants mods
  # 1. sudoers — passwordless sudo (NOPASSWD) or a specific non-root/non-%group user granted rights
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    case "$f" in */README) continue;; esac
    body=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$|^[[:space:]]*Defaults' "$f" 2>/dev/null)
    [ -z "$body" ] && continue
    reset_analysis
    printf '%s' "$body" | grep -qi 'NOPASSWD' && flag SUDO-NOPASSWD
    grants=$(printf '%s\n' "$body" | grep -E '^[A-Za-z_][A-Za-z0-9_.-]*[[:space:]].*=' | grep -vE '^root[[:space:]]|^%')
    [ -n "$grants" ] && flag SUDOERS-USER-GRANT
    check_recent "$f"
    report "sudoers:$(basename "$f")" "$f" "" "grants=[$(printf '%s' "$body" | tr '\n' ';')]"
  done
  # 2. PAM — a module reference that is NOT a standard pam_*.so (absolute path or planted .so) = backdoor
  for f in /etc/pam.d/*; do
    [ -f "$f" ] || continue
    reset_analysis
    mods=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -oE '[^[:space:]]*\.so')
    [ -n "$mods" ] && printf '%s\n' "$mods" | grep -qvE '^pam_[A-Za-z0-9_]+\.so$' && flag PAM-CUSTOM-MODULE
    check_recent "$f"
    report "pam:$(basename "$f")" "$f" "" "modules=[$(printf '%s' "$mods" | tr '\n' ' ')]"
  done
  # 3. legacy rc startup — rc.local isn't present by default; rc.common is (flag only if modified/interp)
  for f in /etc/rc.local /etc/rc.common /etc/rc.server; do
    [ -f "$f" ] || continue
    reset_analysis
    case "$f" in */rc.local) flag RC-LOCAL-PRESENT;; esac
    body=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null | tr '\n' ';')
    check_interp "$body"; check_path "$body"; check_recent "$f"
    report "rc:$(basename "$f")" "$f" "" ""
  done
}

# ---------- arg parsing ----------
while [ $# -gt 0 ]; do
  case "$1" in
    quick|deep) MODE="$1";;
    --days) RECENT="$2"; shift;;
    --since) SINCE_DATE="$2"; SINCE_EPOCH=$(date -j -f "%Y-%m-%d" "$2" +%s 2>/dev/null); shift;;
    --modules) MODULES="$2"; shift;;
    --user) ONLY_USER="$2"; shift;;
    --min-severity) case "$2" in high|HIGH) MIN_SEV=3;; notable|NOTABLE) MIN_SEV=2;; low|LOW) MIN_SEV=1;; *) echo "bad --min-severity (high|notable|low)" >&2; exit 2;; esac; shift;;
    --verbose|-v) VERBOSE=1;;
    --gk|--gatekeeper-check) GK_MODE=all;;
    --gk-unsigned|--gatekeeper-check-unverified) GK_MODE=unsigned;;
    --suspect-only) SUSPECT_ONLY=1;;
    -h|--help) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 2;;
  esac
  shift
done

[ -z "$MODE" ] && [ -z "$MODULES" ] && { echo "ERROR: MODE (quick|deep) or --modules required" >&2; usage; exit 2; }
[ -n "$SINCE_DATE" ] && [ -z "$SINCE_EPOCH" ] && { echo "ERROR: bad --since date (want YYYY-MM-DD)" >&2; exit 2; }

quick_mods="launchd cron loginitems sysext helpers ssh authmods apps"
deep_mods="$quick_mods dylib shell longtail trojan profiles"
if [ -n "$MODULES" ]; then run="${MODULES//,/ }"
elif [ "$MODE" = deep ]; then run="$deep_mods"
else run="$quick_mods"; fi

# ---------- run ----------
echo "hunt_persistence.sh  v${VERSION}    author: ${AUTHOR}"
echo "Ran at   : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "Hostname : $(hostname -s 2>/dev/null)"
echo "Command  : hunt_persistence.sh ${RAW_ARGS:-<none>}"
if [ "$(id -u)" -ne 0 ]; then
  printf '\n!! WARNING: not running as root. Root-only paths (other users, /var/at,\n'
  printf '!! sfltool BTM, login/logout hooks, some plists) will be incomplete or shown as ??.\n'
  printf '!! Re-run with system privileges (sudo) for full coverage.\n'
fi

host_posture

for m in $run; do
  case "$m" in
    launchd) module_launchd;;
    cron) module_cron;;
    loginitems) module_loginitems;;
    sysext) module_sysext;;
    helpers) module_helpers;;
    ssh) module_ssh;;
    dylib) module_dylib;;
    shell) module_shell;;
    longtail) module_longtail;;
    trojan) module_trojan;;
    profiles) module_profiles;;
    authmods) module_authmods;;
    apps) module_apps;;
    *) echo "unknown module: $m" >&2;;
  esac
done

account_summary
recent_logins
flush_section

echo
echo "==== $HI HIGH · $NO NOTABLE · $LO LOW · $OK clean · $UNR unreadable ===="
echo "Triage order: work [HIGH] first, then [NOTABLE]. [LOW] = context/expected-but-verify (hide with --min-severity notable)."
print_legend
