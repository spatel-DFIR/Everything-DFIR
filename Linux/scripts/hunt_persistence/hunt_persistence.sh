#!/bin/bash
# hunt_persistence.sh — read-only Linux persistence triage.  (v2.3)  author: Suvas Patel
#
# Blocks, in order:
#   1. HOST TRIAGE      — what this box is (distro/kernel/init/pkg mgr, AppArmor/SELinux,
#                         auditd, integrity tooling, kernel taint, ld.so.preload).
#   2. RECENCY DIGEST   — the fast timeline: the 20 newest-modified persistence files
#                         (or, with --since/--days, every one in the window). Inventory only.
#   3. CURRENT PERSISTENCE (inventory) — what is actually armed, listed for you to eyeball;
#                         includes which resolved targets are RUNNING right now (armed & live).
#                         NOT scored — this is the lay of the land.
#   4. ANOMALIES        — the short, evidence-backed queue. ~empty on a clean host.
#
# Why this shape: on Linux the base OS ships THOUSANDS of legitimate "persistence-shaped"
# things (udev RUN+=, apt hooks, socket units, generators, cron PATH= lines). The mechanism
# is not the signal. An item becomes an ANOMALY only when it carries EVIDENCE, in priority:
#   (a) behavioral payload  — command downloads+execs, decodes+execs, reverse shell,
#                             or runs from /tmp /dev/shm /var/tmp / a hidden dir
#   (b) integrity break     — packaged file fails debsums/rpm -V; hidden kernel module
#   (c) hard absolutes      — populated ld.so.preload, pam_permit sufficient, UID-0 non-root,
#                             empty shadow password, core_pattern piping outside the distro
#                             default, modprobe install= shell, LD_PRELOAD in a live process
#   (d) incident recency    — with --since/--days, a persistence file changed in the window
# Package ownership is the Linux baseline (dpkg/rpm): it GATES content-scanning (a packaged,
# unmodified file is trusted) and acts as a +modifier, not a standalone wall of findings.
#
# READ-ONLY / NON-DESTRUCTIVE. Console-only. Run as root for full coverage.
#
# Usage:  bash hunt_persistence.sh [options]
#   --since YYYY-MM-DD   incident window: promote items changed on/after this date
#   --days N             incident window: promote items changed in the last N days
#   --deep               add slow checks: package integrity (debsums / rpm -Va) + full-fs SUID/caps
#   --modules a,b,c      limit to surfaces: cron systemd initscripts shell ssh pam accounts
#                        preload kmod procscan triggers integrity
#   --min-severity T     anomaly filter: high | notable  (default: show both)
#   --inventory-only     triage + inventory, skip the anomaly scan
#   --anomalies-only     triage + anomalies, skip the inventory listing
#   -h | --help
#
# Part of the Linux DFIR Field Reference — see "09 - Persistence Mechanisms/".

VERSION="2.3"; AUTHOR="Suvas Patel"
RAW_ARGS="$*"
NOW=$(date +%s)
WINDOW_SET=""; SINCE_EPOCH=""; RECENT_DAYS=""
DEEP=""; MODULES=""; MIN_SEV=2; SHOW_INV=1; SHOW_ANOM=1
PKGMGR=""; INIT=""; DISTRO=""
HI=0; NO=0

# Accounts that should not own a cron/unit/key or hold an interactive login shell.
SVC_ACCTS="www-data|nobody|postgres|apache|nginx|mysql|mariadb|daemon|bin|sys|games|mail|news|uucp|proxy|list|irc|gnats|ftp|redis|memcached|mongodb|rabbitmq|elasticsearch|tomcat|jenkins|zabbix|prometheus|grafana|haproxy|varnish|sshd|_apt|systemd-network|systemd-resolve|messagebus|syslog|tss|landscape|pollinate"
# Directories not to descend into on full-filesystem scans (container/overlay internals, virtual FS).
PRUNE="/proc /sys /run /dev /var/lib/docker /var/lib/containers /var/lib/lxc /var/lib/lxd /var/lib/snapd /snap"

usage(){ sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; }

# ================= output plumbing =================
# Inventory prints inline (block 2). Anomalies are buffered (block 3) so the two never interleave.
ANOM_HIGH=""; ANOM_NOTABLE=""; UNOWNED_LIST=""
inv_head(){ [ -n "$SHOW_INV" ] && printf '\n-- %s --\n' "$1"; }
inv(){ [ -n "$SHOW_INV" ] && printf '   %s\n' "$1"; }
inv_none(){ [ -n "$SHOW_INV" ] && printf '   (none)\n'; }
note_unowned(){ UNOWNED_LIST="${UNOWNED_LIST}
   $1"; }

# ================= evidence scoring for one item =================
EV_SCORE=0; EV_REASONS=""
ev_reset(){ EV_SCORE=0; EV_REASONS=""; }
ev(){ EV_SCORE=$((EV_SCORE+$1)); case " $EV_REASONS " in *" $2 "*) ;; *) EV_REASONS="$EV_REASONS $2";; esac; }
ev_tier(){ if [ "$EV_SCORE" -ge 5 ]; then echo HIGH; elif [ "$EV_SCORE" -ge 3 ]; then echo NOTABLE; else echo LOW; fi; }

# scan_cmd COMMAND [context] — add payload evidence found in a command string.
# The tight, high-confidence patterns that separate an implant from OS plumbing.
scan_cmd(){
  local c="$1"
  echo "$c" | grep -qiE '/dev/tcp/|/dev/udp/|nc[[:space:]]+[^;|]*-e|ncat[[:space:]]+[^;|]*-e|bash[[:space:]]+-i|(^|[[:space:]])sh[[:space:]]+-i|socat[[:space:]]+[^;|]*exec' && ev 5 REVERSE-SHELL
  echo "$c" | grep -qiE '(curl|wget|fetch)[^;&|]*\|[^;&|]*(ba)?sh|(curl|wget|fetch)[^;&|]*\|[^;&|]*(python|perl|php|ruby)' && ev 5 DOWNLOAD-EXEC
  echo "$c" | grep -qiE '(base64|xxd|openssl[[:space:]]+enc)[^;&|]*(-d|-D|-r)[^;&|]*\|[^;&|]*(ba)?sh' && ev 5 DECODE-EXEC
  echo "$c" | grep -qiE '(python[0-9]?|perl|ruby|php)[[:space:]]+-[ce][^;]*(socket|subprocess|exec|/dev/tcp|os\.system)' && ev 5 SCRIPT-SHELL
  echo "$c" | grep -qiE '/tmp/|/dev/shm/|/var/tmp/|/run/shm/' && ev 4 TEMP-PATH
  # hidden component nested in a SYSTEM dir (implants love /usr/lib/.x, /var/tmp/.s) —
  # excludes /home/*/.config /.cache /.ssh etc. which are ubiquitous and benign.
  echo "$c" | grep -qiE '/(usr|opt|etc|var|srv|boot|root|lib|lib64)/[^;:[:space:]]*/\.[A-Za-z0-9]' && ev 2 HIDDEN-SYSPATH
  echo "$c" | grep -qiE 'eval[[:space:]]+["'\''`]?\$\(|eval[[:space:]]+["'\''`]?base64' && ev 3 EVAL-OBFUSCATED
}
# modifiers (never create a finding alone unless an absolute already fired)
mod_immutable(){ local a; a=$(lsattr -d "$1" 2>/dev/null | awk '{print $1}'); case "$a" in *i*|*a*) ev 2 IMMUTABLE;; esac; }
mod_recent(){ [ -n "$WINDOW_SET" ] || return; is_recent "$1" && ev 2 RECENT; }
mod_svcacct(){ echo "$1" | grep -qE "^($SVC_ACCTS)$" && ev 2 SVC-ACCT; }

# finish_item SOURCE LABEL WHERE WHAT — queue as an anomaly iff evidence reached NOTABLE+.
finish_item(){
  [ "$EV_SCORE" -lt 3 ] && return
  local t block; t=$(ev_tier)
  block=$(printf '\n[%s] %s: %s\n   where: %s\n   what : %s\n   why  :%s\n' "$t" "$1" "$2" "$3" "$4" "$EV_REASONS")
  case "$t" in HIGH) ANOM_HIGH="$ANOM_HIGH$block"; HI=$((HI+1));; NOTABLE) ANOM_NOTABLE="$ANOM_NOTABLE$block"; NO=$((NO+1));; esac
}
# absolute ABSOLUTE-shaped findings bypass the evidence stacking (always HIGH/NOTABLE).
queue_abs(){ # tier source label where what
  local block; block=$(printf '\n[%s] %s: %s\n   where: %s\n   what : %s\n' "$1" "$2" "$3" "$4" "$5")
  case "$1" in HIGH) ANOM_HIGH="$ANOM_HIGH$block"; HI=$((HI+1));; NOTABLE) ANOM_NOTABLE="$ANOM_NOTABLE$block"; NO=$((NO+1));; esac
}

# ================= timestamps =================
mtime_epoch(){ stat -c %Y "$1" 2>/dev/null; }
mtime_utc(){ local m; m=$(mtime_epoch "$1"); [ -n "$m" ] && date -u -d "@$m" '+%Y-%m-%d %H:%M UTC' 2>/dev/null; }
is_recent(){ local m; m=$(mtime_epoch "$1"); [ -z "$m" ] && return 1
  if [ -n "$SINCE_EPOCH" ]; then [ "$m" -ge "$SINCE_EPOCH" ]; else [ $(((NOW-m)/86400)) -lt "${RECENT_DAYS:-14}" ]; fi; }

# ================= package provenance (usrmerge-aware) =================
# pkg_owns FILE -> 0 owned, 1 unowned, 2 unknown (symlink / no pkg mgr).
# dpkg's DB records pre-usrmerge paths (/lib not /usr/lib), so we query both forms.
pkg_owns(){
  local f="$1"
  { [ -e "$f" ] && [ ! -L "$f" ]; } || return 2
  case "$PKGMGR" in
    dpkg)
      dpkg -S "$f" >/dev/null 2>&1 && return 0
      case "$f" in
        /usr/lib/*|/usr/bin/*|/usr/sbin/*) dpkg -S "${f#/usr}" >/dev/null 2>&1 && return 0;;
        /lib/*|/lib64/*|/bin/*|/sbin/*)    dpkg -S "/usr$f"    >/dev/null 2>&1 && return 0;;
      esac
      return 1;;
    rpm)    rpm -qf "$f"    >/dev/null 2>&1 && return 0 || return 1;;
    pacman) pacman -Qo "$f" >/dev/null 2>&1 && return 0 || return 1;;
    apk)    apk info -W "$f" >/dev/null 2>&1 && return 0 || return 1;;
    *) return 2;;
  esac
}
# pkg_changed FILE -> 0 modified, 1 unchanged, 2 can't check. Opportunistic single-file verify.
pkg_changed(){
  local f="$1"
  case "$PKGMGR" in
    rpm)  rpm -Vf "$f" 2>/dev/null | grep -qE '^..5|^..[[:alpha:]]{0,8}5' && return 0 || return 1;;
    dpkg) command -v debsums >/dev/null 2>&1 || return 2
          debsums -s "$f" >/dev/null 2>&1 && return 1 || return 0;;
    *) return 2;;
  esac
}

# All home directories from /etc/passwd (real users, service accounts, root).
user_homes(){
  { getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null; } | awk -F: '{print $6}' | sort -u | while IFS= read -r h; do
    case "$h" in ''|/|/nonexistent|/dev/null|/proc/*|/bin|/sbin|/usr/sbin|/run/*) continue;; esac
    [ -d "$h" ] && echo "$h"
  done
}
# find(1) with container/virtual dirs pruned.
find_real(){ local p args=(); for p in $PRUNE; do args+=(-path "$p" -o); done; find "$1" -xdev \( "${args[@]}" -false \) -prune -o "${@:2}" 2>/dev/null; }

# ----- inventory display helpers (context columns: owner + resolved path) -----
own_tag(){ pkg_owns "$1"; case $? in 0) printf 'pkg-owned';; 1) printf 'UNOWNED';; *) printf '-';; esac; }
# first on-disk path for a systemd unit name (templates + aliases included)
resolve_unit(){ local n="$1" d; for d in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system; do [ -e "$d/$n" ] && { printf '%s' "$d/$n"; return; }; done; }
# first non-empty ExecStart= value of a unit / drop-in file
first_execstart(){ grep -hE '^[[:space:]]*ExecStart=' "$1" 2>/dev/null | sed -E 's/^[[:space:]]*ExecStart=//' | grep -vE '^[[:space:]]*$' | head -1; }

# ================= exec_target: the shared command→binary parser =================
# Resolve a systemd ExecStart= value (or a cron/shell command) down to the binary it
# actually runs, so provenance/recency/proc-correlation all reason about the SAME thing:
#   ET_BIN     target executable — absolute path, bare name, or $VAR
#   ET_CLASS   system | tmp | home | hidden | unknown   (where the binary lives)
#   ET_OWNER   pkg-owned | UNOWNED | -   (own_tag on ET_BIN when it is an existing abs path)
#   ET_PAYLOAD when ET_BIN is a shell run with -c, the payload string (else empty)
# Handles systemd exec prefixes (@ - + ! :), leading VAR=value env-assignments, and
# `/bin/sh -c '<payload>'` (payload is handed to the existing scan_cmd).
ET_BIN=""; ET_CLASS=""; ET_OWNER='-'; ET_PAYLOAD=""
exec_target(){
  ET_BIN=""; ET_CLASS=unknown; ET_OWNER='-'; ET_PAYLOAD=""
  local s="$1" tok
  s=${s#ExecStart=}
  s="${s#"${s%%[![:space:]]*}"}"
  # strip systemd exec prefixes (@ - + ! :) that lead the command
  while :; do case "$s" in [-@+!:]*) s=${s#?}; s="${s#"${s%%[![:space:]]*}"}";; *) break;; esac; done
  # strip leading VAR=value env-assignments (cron / shell)
  while :; do tok=${s%%[[:space:]]*}; case "$tok" in [A-Za-z_]*=*) s=${s#"$tok"}; s="${s#"${s%%[![:space:]]*}"}";; *) break;; esac; done
  tok=${s%%[[:space:]]*}; ET_BIN="$tok"
  # shell -c payload → hand to scan_cmd downstream
  case "$tok" in
    sh|bash|dash|zsh|ksh|*/sh|*/bash|*/dash|*/zsh|*/ksh)
      case " $s " in *" -c "*) ET_PAYLOAD=${s#*-c }; ET_PAYLOAD="${ET_PAYLOAD#"${ET_PAYLOAD%%[![:space:]]*}"}"; ET_PAYLOAD=${ET_PAYLOAD#[\"\']}; ET_PAYLOAD=${ET_PAYLOAD%[\"\']};; esac;;
  esac
  case "$ET_BIN" in
    /tmp/*|/dev/shm/*|/var/tmp/*|/run/shm/*) ET_CLASS=tmp;;
    /home/*) ET_CLASS=home;;
    /usr/*|/opt/*|/etc/*|/var/*|/srv/*|/boot/*|/root/*|/bin/*|/sbin/*|/lib/*|/lib64/*)
      case "$ET_BIN" in */.[!/]*) ET_CLASS=hidden;; *) ET_CLASS=system;; esac;;
    /*) ET_CLASS=system;;
    *) ET_CLASS=unknown;;
  esac
  case "$ET_BIN" in /*) [ -e "$ET_BIN" ] && ET_OWNER=$(own_tag "$ET_BIN");; esac
}
# Provenance evidence for the binary just parsed by exec_target. The net-new signal over
# scan_cmd (which already scans the raw line for tmp/hidden/payload) is EXEC-UNOWNED:
# the unit/cron FILE may be packaged & trusted, yet it runs a binary no package owns.
ev_exec_target(){
  [ "$ET_CLASS" = system ] && [ "$ET_OWNER" = UNOWNED ] && ev 2 EXEC-UNOWNED
  [ -n "$ET_PAYLOAD" ] && scan_cmd "$ET_PAYLOAD"
}
# strip a cron line's schedule (+ user field on system crontabs) → the command
cron_cmd(){ awk -v hu="${2:-0}" 'NR==1{ s=($1 ~ /^@/)?2:6; if(hu=="1")s++; o=""; for(i=s;i<=NF;i++)o=o (i>s?" ":"") $i; print o }' <<<"$1"; }

# Armed persistence targets (resolved unit/cron binaries) and the suspect subset (items that
# reached an anomaly). module_procscan correlates these against /proc/*/exe: armed AND live.
ARMED_TARGETS=""; SUSPECT_TARGETS=""
arm_target(){ case "$1" in /*) case "$ARMED_TARGETS" in *"
$1	"*) ;; *) ARMED_TARGETS="$ARMED_TARGETS
$1	$2";; esac;; esac; }
suspect_target(){ case "$1" in /*) SUSPECT_TARGETS="$SUSPECT_TARGETS
$1";; esac; }

# ================= BLOCK 2 pre-pass: recency digest =================
# One master list of persistence-relevant files (surface<TAB>path), stat-only.
persistence_files(){
  _emit(){ local s="$1"; shift; local f; for f in "$@"; do [ -f "$f" ] && printf '%s\t%s\n' "$s" "$f"; done; }
  _emit cron      /etc/crontab /etc/cron.d/*
  _emit cron-run  /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*
  _emit cron      /var/spool/cron/crontabs/* /var/spool/cron/*
  _emit systemd   /etc/systemd/system/*.service /etc/systemd/system/*.timer /etc/systemd/system/*.socket /etc/systemd/system/*.path /etc/systemd/system/*.d/*.conf /run/systemd/system/*.service /run/systemd/system/*.timer
  _emit init      /etc/rc.local /etc/rc.d/rc.local /etc/init.d/* /etc/local.d/*.start
  _emit shell     /etc/profile /etc/bash.bashrc /etc/bashrc /etc/profile.d/*
  _emit preload   /etc/ld.so.preload /etc/ld.so.conf.d/*
  _emit kmod      /etc/modprobe.d/* /etc/modules-load.d/*
  _emit pam       /etc/pam.d/*
  _emit ssh       /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*
  _emit udev      /etc/udev/rules.d/*.rules
  _emit autostart /etc/xdg/autostart/*.desktop
  _emit motd      /etc/update-motd.d/*
  _emit nm-disp   /etc/NetworkManager/dispatcher.d/*
  _emit inetd     /etc/inetd.conf /etc/xinetd.d/*
  _emit apt-hook  /etc/apt/apt.conf.d/*
  local h
  while IFS= read -r h; do
    _emit user-shell "$h"/.bashrc "$h"/.bash_profile "$h"/.bash_login "$h"/.profile "$h"/.zshrc "$h"/.zshenv "$h"/.zprofile
    _emit user-ssh   "$h"/.ssh/authorized_keys "$h"/.ssh/authorized_keys2 "$h"/.ssh/rc
    _emit user-auto  "$h"/.config/autostart/*.desktop
    _emit sysd-user  "$h"/.config/systemd/user/*.service "$h"/.config/systemd/user/*.timer
  done < <(user_homes)
}
# resolved →target binary for a digest row (systemd units + real crontabs only)
digest_target(){
  case "$1" in
    systemd|sysd-user) exec_target "$(first_execstart "$2")"; [ -n "$ET_BIN" ] && printf '%s' "$ET_BIN";;
    cron) local l; l=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$|^[A-Z_]+=' "$2" 2>/dev/null | head -1)
          [ -z "$l" ] && return
          case "$2" in /etc/crontab|/etc/cron.d/*) exec_target "$(cron_cmd "$l" 1)";; *) exec_target "$(cron_cmd "$l" 0)";; esac
          [ -n "$ET_BIN" ] && printf '%s' "$ET_BIN";;
  esac
}
module_recency(){
  printf '\n===== RECENCY DIGEST — persistence files, newest-modified first =====\n'
  if [ -n "$WINDOW_SET" ]; then
    printf '   every persistence file modified in the incident window. Inventory only — not a verdict.\n'
  else
    printf '   the 20 most-recently-modified persistence files — a fast "what was touched" timeline.\n   Inventory only, not scored; an implant floats to the top here.\n'
  fi
  local TAB rows shown; TAB=$(printf '\t')
  rows=$(persistence_files | while IFS="$TAB" read -r s f; do
           m=$(mtime_epoch "$f"); [ -n "$m" ] && printf '%s\t%s\t%s\n' "$m" "$s" "$f"
         done | sort -rn -k1,1)
  if [ -n "$WINDOW_SET" ]; then
    shown=$(printf '%s\n' "$rows" | while IFS="$TAB" read -r m s f; do is_recent "$f" && printf '%s\t%s\t%s\n' "$m" "$s" "$f"; done)
  else
    shown=$(printf '%s\n' "$rows" | head -20)
  fi
  [ -z "$shown" ] && { printf '   (none found)\n'; return; }
  printf '   %-16s %-11s %-9s %s\n' 'MODIFIED (UTC)' 'SURFACE' 'OWNER' 'PATH  → target'
  printf '%s\n' "$shown" | while IFS="$TAB" read -r m s f; do
    md=$(date -u -d "@$m" '+%Y-%m-%d %H:%M' 2>/dev/null)
    case "$f" in /run/*) o="runtime/volatile";; *) o=$(own_tag "$f");; esac; t=$(digest_target "$s" "$f")
    printf '   %-16s %-11s %-9s %s%s\n' "$md" "$s" "$o" "$f" "${t:+  → $t}"
  done
}

# ================= BLOCK 1: host triage =================
detect_env(){
  if   command -v dpkg   >/dev/null 2>&1; then PKGMGR=dpkg
  elif command -v rpm    >/dev/null 2>&1; then PKGMGR=rpm
  elif command -v pacman >/dev/null 2>&1; then PKGMGR=pacman
  elif command -v apk    >/dev/null 2>&1; then PKGMGR=apk; fi
  if   [ -d /run/systemd/system ] || command -v systemctl >/dev/null 2>&1; then INIT=systemd
  elif command -v rc-status >/dev/null 2>&1; then INIT=openrc
  elif [ -d /etc/runit ] || [ -d /etc/sv ]; then INIT=runit
  else INIT=sysv; fi
  DISTRO=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")
}
triage(){
  printf '\n===== HOST TRIAGE =====\n'
  printf '  Hostname   : %s\n' "$(hostname 2>/dev/null)"
  printf '  Distro     : %s\n' "$DISTRO"
  printf '  Kernel     : %s\n' "$(uname -r 2>/dev/null)"
  command -v systemd-detect-virt >/dev/null 2>&1 && printf '  Virt       : %s\n' "$(systemd-detect-virt 2>/dev/null)"
  printf '  Booted     : %s\n' "$(uptime -s 2>/dev/null || echo unknown)"
  printf '  Init       : %s\n' "$INIT"
  printf '  Pkg mgr    : %s\n' "${PKGMGR:-none (provenance checks disabled)}"
  # LSM
  local sel aa
  command -v getenforce >/dev/null 2>&1 && sel="SELinux=$(getenforce 2>/dev/null)"
  if command -v aa-status >/dev/null 2>&1; then
    if aa-status --enabled 2>/dev/null; then aa="AppArmor=enabled ($(aa-status 2>/dev/null | awk '/profiles are in enforce/{print $1" enforce"}'))"; else aa="AppArmor=disabled"; fi
  fi
  printf '  LSM        : %s\n' "${sel:-${aa:-none detected}}"; [ -n "$sel" ] && [ -n "$aa" ] && printf '               %s\n' "$aa"
  # auditd
  local aud="not present" ar
  if command -v auditctl >/dev/null 2>&1 || pidof auditd >/dev/null 2>&1; then
    if pidof auditd >/dev/null 2>&1; then
      ar=$(auditctl -l 2>/dev/null | grep -vc '^No rules$')
      aud="running, ${ar:-?} rules loaded"
    else aud="installed but NOT running  <-- audit trail gap"; fi
  fi
  printf '  auditd     : %s\n' "$aud"
  # integrity tooling available for --deep
  local tools=""
  command -v debsums >/dev/null 2>&1 && tools="$tools debsums"
  [ "$PKGMGR" = rpm ] && tools="$tools rpm-verify"
  command -v aide >/dev/null 2>&1 && tools="$tools aide"
  printf '  Integrity  : %s\n' "${tools:- none (install debsums / use rpm -V for --deep integrity)}"
  # kernel taint
  local taint bits=""
  taint=$(cat /proc/sys/kernel/tainted 2>/dev/null)
  if [ -n "$taint" ] && [ "$taint" != 0 ]; then
    [ $(( (taint>>12)&1 )) -eq 1 ] && bits="$bits out-of-tree"
    [ $(( (taint>>13)&1 )) -eq 1 ] && bits="$bits unsigned-module"
    printf '  Taint      : %s%s  <-- nonzero; investigate loaded modules\n' "$taint" "${bits:+ —$bits}"
  else printf '  Taint      : %s\n' "${taint:-unknown}"; fi
  # ld.so.preload — fastest userland-rootkit tell
  if [ -s /etc/ld.so.preload ]; then printf '  ld.preload : PRESENT + NON-EMPTY  <-- see anomalies\n'
  else printf '  ld.preload : clean\n'; fi
  # scale
  if [ "$INIT" = systemd ]; then
    printf '  systemd    : %s enabled unit-files, %s active timers\n' \
      "$(systemctl list-unit-files --state=enabled --no-legend 2>/dev/null | wc -l | tr -d ' ')" \
      "$(systemctl list-timers --all --no-legend 2>/dev/null | grep -c . )"
  fi
  printf '  Window     : %s\n' "$([ -n "$WINDOW_SET" ] && echo "incident — recency promotes findings" || echo "none (recency is context only; use --since/--days for IR)")"
}

# ================= modules =================
module_cron(){
  [ -n "$SHOW_INV" ] && printf '\n===== CURRENT PERSISTENCE: cron / at =====\n'
  local d f u line first
  inv_head "cron jobs — grouped by file (full path · mtime UTC · package owner shown for remediation)"
  local any=""
  # per-user spools (700 root — say so if unreadable)
  for d in /var/spool/cron/crontabs /var/spool/cron /etc/crontabs; do
    [ -d "$d" ] || continue
    if ! ls "$d" >/dev/null 2>&1; then inv "?? $d/   [unreadable — needs root]"; continue; fi
    for f in "$d"/*; do
      [ -f "$f" ] || continue; u=$(basename "$f"); first=1
      while IFS= read -r line; do
        [ -z "$line" ] && continue; any=1
        [ -n "$first" ] && { inv "$f   (user spool '$u' · mtime $(mtime_utc "$f"))"; first=""; }
        inv "      $line"
        ev_reset; scan_cmd "$line"; mod_svcacct "$u"; mod_recent "$f"; mod_immutable "$f"
        exec_target "$(cron_cmd "$line" 0)"; ev_exec_target; arm_target "$ET_BIN" "cron:$u"
        echo "$line" | grep -q '@reboot' && [ "$EV_SCORE" -gt 0 ] && ev 1 AT-REBOOT
        finish_item cron "user:$u" "$f" "$line"
        [ "$EV_SCORE" -ge 3 ] && suspect_target "$ET_BIN"
      done < <(grep -vE '^[[:space:]]*#|^[[:space:]]*$|^[A-Z_]+=' "$f" 2>/dev/null)
    done
  done
  for f in /etc/crontab /etc/cron.d/*; do
    [ -f "$f" ] || continue; first=1
    while IFS= read -r line; do
      [ -z "$line" ] && continue; any=1
      [ -n "$first" ] && { inv "$f   (mtime $(mtime_utc "$f") · $(own_tag "$f"))"; first=""; }
      inv "      $line"
      ev_reset; scan_cmd "$line"; mod_recent "$f"; mod_immutable "$f"
      pkg_owns "$f"; [ $? -eq 1 ] && { ev 2 UNOWNED; note_unowned "$f   (cron.d · mtime $(mtime_utc "$f"))"; }
      exec_target "$(cron_cmd "$line" 1)"; ev_exec_target; arm_target "$ET_BIN" "cron:$(basename "$f")"
      finish_item cron "$(basename "$f")" "$f" "$line"
      [ "$EV_SCORE" -ge 3 ] && suspect_target "$ET_BIN"
    done < <(grep -vE '^[[:space:]]*#|^[[:space:]]*$|^[A-Z_]+=' "$f" 2>/dev/null)
    # PATH= override that PREPENDS a writable/cwd dir hijacks the job's commands
    # (the standard PATH=/usr/local/sbin:... never matches this).
    grep -E '^[[:space:]]*PATH=' "$f" 2>/dev/null | grep -qiE 'PATH=[[:space:]]*(\.|/tmp|/dev/shm|/var/tmp|/home|::|:\.)' && \
      queue_abs NOTABLE cron "PATH-hijack:$(basename "$f")" "$f" "CRON-PATH-HIJACK (PATH prepends a writable/cwd dir: $(grep -E '^[[:space:]]*PATH=' "$f" 2>/dev/null | head -1))"
  done
  [ -z "$any" ] && inv_none
  # run-parts cadence scripts: trust packaged, scan the unowned (dropped) ones
  for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/periodic/*; do
    [ -d "$d" ] || continue
    for f in "$d"/*; do
      [ -f "$f" ] || continue
      case "$(basename "$f")" in .placeholder|0anacron|*.dpkg-*) continue;; esac
      pkg_owns "$f"; [ $? -eq 0 ] && continue          # packaged + trusted → skip body scan
      ev_reset; ev 2 UNOWNED; note_unowned "$f ($(basename "$d"))"
      scan_cmd "$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | tr '\n' ';')"; mod_recent "$f"
      finish_item cron "$(basename "$d"):$(basename "$f")" "$f" "unowned cadence script"
    done
  done
  # at queue
  inv_head "at (one-shot) jobs"
  local atany=""
  for d in /var/spool/cron/atjobs /var/spool/at; do
    [ -d "$d" ] || continue
    for f in "$d"/*; do
      [ -f "$f" ] || continue
      case "$(basename "$f")" in .SEQ|.lockfile) continue;; esac
      atany=1; inv "at job: $(basename "$f")  ($(mtime_utc "$f"))"
      ev_reset; scan_cmd "$(tr '\n' ';' < "$f" 2>/dev/null)"; mod_recent "$f"
      finish_item at "$(basename "$f")" "$f" "queued at job"
    done
  done
  [ -z "$atany" ] && inv_none
}

module_systemd(){
  [ "$INIT" = systemd ] || return
  [ -n "$SHOW_INV" ] && printf '\n===== CURRENT PERSISTENCE: systemd =====\n'
  local f exec_l d hpany m e o u p md es
  # A) Enabled units — enriched and sorted NEWEST-MODIFIED FIRST. mtime is the triage key:
  #    an implant's unit is newer than the vendor baseline, and floats to the top here.
  inv_head "enabled units — NEWEST-MODIFIED FIRST (mtime UTC · owner · unit → ExecStart)"
  if [ -n "$SHOW_INV" ]; then
    systemctl list-unit-files --state=enabled --no-legend 2>/dev/null | awk '{print $1}' | while read -r u; do
      p=$(resolve_unit "$u"); m=$(mtime_epoch "$p"); [ -z "$m" ] && m=0
      e=$(grep -hE '^[[:space:]]*ExecStart=' "$p" 2>/dev/null | head -1 | sed -E 's/^[[:space:]]*ExecStart=//')
      printf '%s\t%s\t%s\t%s\n' "$m" "$(own_tag "$p")" "$u" "$e"
    done | sort -t"$(printf '\t')" -k1,1rn | while IFS="$(printf '\t')" read -r m o u e; do
      if [ "$m" = 0 ]; then md="unknown         "; else md=$(date -u -d "@$m" '+%Y-%m-%d %H:%M' 2>/dev/null); fi
      printf '   %s  %-9s %-42s %s\n' "$md" "$o" "$u" "${e:+→ $e}"
    done
  fi
  # B) Hand-placed surface: every unit in /etc + /run (full path for remediation). This is where
  #    an attacker plants; vendor units in /usr/lib are covered by the enabled list + --deep integrity.
  inv_head "hand-placed units in /etc & /run (FULL PATH · mtime · owner · Exec*)"
  hpany=""
  for d in /etc/systemd/system /run/systemd/system; do
    [ -d "$d" ] || continue
    for f in "$d"/*.service "$d"/*.timer "$d"/*.socket "$d"/*.path; do
      [ -f "$f" ] || continue; hpany=1
      exec_l=$(grep -hE '^[[:space:]]*(ExecStart|ExecStartPre|ExecStartPost|ExecStop)=' "$f" 2>/dev/null | sed 's/^[[:space:]]*//' | tr '\n' ';')
      case "$d" in /etc/*) inv "$f   (mtime $(mtime_utc "$f") · $(own_tag "$f"))";; *) inv "$f   (mtime $(mtime_utc "$f") · runtime/volatile)";; esac
      [ -n "$exec_l" ] && inv "      $exec_l"
      ev_reset; scan_cmd "$exec_l"
      grep -qiE '^[[:space:]]*Environment=.*LD_(PRELOAD|AUDIT)' "$f" 2>/dev/null && ev 5 UNIT-LD-PRELOAD
      es=$(first_execstart "$f"); exec_target "$es"; ev_exec_target; arm_target "$ET_BIN" "unit:$(basename "$f")"
      case "$d" in /etc/systemd/system) pkg_owns "$f"; [ $? -eq 1 ] && { ev 2 UNOWNED; note_unowned "$f   (systemd unit · mtime $(mtime_utc "$f"))"; };; esac
      mod_recent "$f"; mod_immutable "$f"
      finish_item systemd "$(basename "$f")" "$f" "${exec_l:-<no ExecStart>}"
      [ "$EV_SCORE" -ge 3 ] && suspect_target "$ET_BIN"
    done
    for f in "$d"/*.d/*.conf; do
      [ -f "$f" ] || continue
      exec_l=$(grep -hE '^[[:space:]]*(ExecStart|ExecStartPost|ExecStartPre)=' "$f" 2>/dev/null | tr '\n' ';')
      [ -z "$exec_l" ] && continue; hpany=1
      inv "$f   (drop-in override · mtime $(mtime_utc "$f"))"; inv "      $exec_l"
      ev_reset; scan_cmd "$exec_l"
      es=$(first_execstart "$f"); exec_target "$es"; ev_exec_target; arm_target "$ET_BIN" "dropin:$(basename "$f")"
      case "$d" in /etc/systemd/system) pkg_owns "$f"; [ $? -eq 1 ] && ev 2 UNOWNED;; esac
      mod_recent "$f"
      finish_item systemd "dropin:$(basename "$(dirname "$f")")/$(basename "$f")" "$f" "$exec_l"
      [ "$EV_SCORE" -ge 3 ] && suspect_target "$ET_BIN"
    done
    for f in "$d"-generators/*; do
      [ -f "$f" ] || continue
      case "$d" in /etc/systemd/system) : ;; *) continue;; esac
      pkg_owns "$f"; [ $? -eq 0 ] && continue
      ev_reset; ev 3 UNOWNED-GENERATOR; note_unowned "$f   (generator · mtime $(mtime_utc "$f"))"; mod_recent "$f"
      finish_item systemd "generator:$(basename "$f")" "$f" "unowned generator — runs at every daemon-reload"
    done
  done
  [ -z "$hpany" ] && inv_none
  # C) Timers → schedule → activated unit (the systemd cron-equivalent surface).
  inv_head "active timers → next run → unit (schedule surface)"
  if [ -n "$SHOW_INV" ]; then
    systemctl list-timers --all --no-legend 2>/dev/null | sed 's/^/   /'
  fi
  # per-user units, linger, masked security units — anomaly only on real signal
  local h u
  while IFS= read -r h; do
    for f in "$h"/.config/systemd/user/*.service "$h"/.config/systemd/user/*.timer; do
      [ -f "$f" ] || continue
      exec_l=$(grep -hE '^[[:space:]]*ExecStart' "$f" 2>/dev/null | tr '\n' ';')
      ev_reset; scan_cmd "$exec_l"; mod_recent "$f"
      finish_item systemd "user-unit:$(basename "$h"):$(basename "$f")" "$f" "$exec_l"
    done
  done < <(user_homes)
  local masked
  masked=$(systemctl list-unit-files --state=masked --no-legend 2>/dev/null | awk '{print $1}' | grep -iE 'audit|falco|apparmor|selinux|rsyslog|syslog|journald|ufw|firewalld|fail2ban|osquery|wazuh|clamav')
  while IFS= read -r u; do [ -z "$u" ] && continue
    queue_abs NOTABLE systemd "masked:$u" "systemctl" "MASKED-SECURITY-UNIT (a logging/security unit is disabled — defense evasion)"
  done < <(echo "$masked")
}

module_initscripts(){
  [ -n "$SHOW_INV" ] && printf '\n===== CURRENT PERSISTENCE: legacy init =====\n'
  local f d body any=""
  inv_head "rc.local / init.d / OpenRC / runit"
  for f in /etc/rc.local /etc/rc.d/rc.local; do
    [ -f "$f" ] || continue
    body=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$|^exit 0|^[[:space:]]*:' "$f" 2>/dev/null | tr '\n' ';')
    [ -z "$body" ] && continue; any=1; inv "rc.local: $body"
    ev_reset; scan_cmd "$body"; mod_recent "$f"; mod_immutable "$f"
    finish_item init "rc.local" "$f" "$body"
  done
  for f in /etc/init.d/*; do
    [ -f "$f" ] || continue
    case "$(basename "$f")" in README|skeleton|rc|rcS|.depend.*|functions) continue;; esac
    pkg_owns "$f"; [ $? -eq 0 ] && continue
    any=1
    ev_reset; ev 2 UNOWNED; note_unowned "$f (init.d)"
    scan_cmd "$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | tr '\n' ';')"; mod_recent "$f"
    finish_item init "init.d:$(basename "$f")" "$f" "unowned SysV init script"
  done
  for f in /etc/local.d/*.start; do
    [ -f "$f" ] || continue; any=1
    ev_reset; ev 2 OPENRC-LOCAL; scan_cmd "$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | tr '\n' ';')"; mod_recent "$f"
    finish_item init "openrc-local:$(basename "$f")" "$f" "runs at boot (OpenRC rc.local)"
  done
  for d in /etc/sv/*; do
    [ -d "$d" ] || continue; f="$d/run"; [ -f "$f" ] || continue; any=1
    ev_reset; scan_cmd "$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | tr '\n' ';')"; mod_recent "$f"
    finish_item init "runit:$(basename "$d")" "$f" "runit service run-script"
  done
  [ -z "$any" ] && inv_none
}

module_shell(){
  [ -n "$SHOW_INV" ] && printf '\n===== CURRENT PERSISTENCE: shell init =====\n'
  local h f r body evil sys
  evil='(curl|wget|fetch)[^;&|]*\|[^;&|]*(ba)?sh|/dev/tcp/|/dev/udp/|nc[[:space:]]+[^;|]*-e|bash[[:space:]]+-i|(base64|xxd)[^;|]*(-d|-r)[^;|]*\|[^;|]*sh|history -c|unset HISTFILE|export HISTFILE=/dev/null'
  sys="/etc/profile /etc/bash.bashrc /etc/bashrc /etc/environment"
  inv_head "system-wide shell init present (full path · last-modified UTC · owner)"
  local sany=""
  for f in $sys /etc/profile.d/* /etc/zsh/* ; do
    [ -f "$f" ] || continue; sany=1; inv "$f   (mtime $(mtime_utc "$f") · $(own_tag "$f"))"
    # trust packaged system files unless modified; always scan /etc/profile.d editable drops
    case "$f" in /etc/profile.d/*) : ;; *) pkg_owns "$f"; [ $? -eq 0 ] && continue;; esac
    body=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null | tr '\n' ';')
    ev_reset
    echo "$body" | grep -qiE "$evil" && ev 5 SHELL-PAYLOAD
    echo "$body" | grep -qiE 'LD_PRELOAD|LD_AUDIT' && ev 5 SHELL-LD-PRELOAD
    echo "$body" | grep -qiE '(^|;)[[:space:]]*(BASH_ENV|ENV)=' && ev 3 BASH-ENV
    mod_recent "$f"; mod_immutable "$f"
    finish_item shell "$f" "$f" "system-wide shell init"
  done
  [ -z "$sany" ] && inv_none
  inv_head "per-user shell init present (full path · last-modified UTC)"
  local uany=""
  while IFS= read -r h; do
    for r in .bashrc .bash_profile .bash_login .profile .bash_logout .zshrc .zprofile .zshenv .zlogin .zlogout .kshrc .cshrc .tcshrc .login .logout .config/fish/config.fish; do
      f="$h/$r"; [ -f "$f" ] || continue; uany=1
      inv "$f   (mtime $(mtime_utc "$f"))"
      body=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null | tr '\n' ';')
      [ -z "$body" ] && continue
      ev_reset
      echo "$body" | grep -qiE "$evil" && ev 5 SHELL-PAYLOAD
      echo "$body" | grep -qiE 'LD_PRELOAD|LD_AUDIT' && ev 5 SHELL-LD-PRELOAD
      echo "$body" | grep -qiE '(^|;)[[:space:]]*(BASH_ENV|ENV)=' && ev 3 BASH-ENV
      echo "$body" | grep -qiE '(alias|function)[[:space:]]+(sudo|ssh|ls|ps|ss|netstat)[[:space:]=]' && ev 2 ALIAS-OVERRIDE
      mod_recent "$f"; mod_immutable "$f"
      finish_item shell "$(basename "$h"):$r" "$f" "user shell init"
    done
    f="$h/.ssh/rc"; if [ -f "$f" ]; then
      ev_reset; ev 3 SSH-RC; scan_cmd "$(cat "$f" 2>/dev/null | tr '\n' ';')"; mod_recent "$f"
      finish_item shell "ssh-rc:$(basename "$h")" "$f" "~/.ssh/rc runs on every SSH session"
    fi
  done < <(user_homes)
  [ -z "$uany" ] && inv_none
}

module_ssh(){
  [ -n "$SHOW_INV" ] && printf '\n===== CURRENT PERSISTENCE: SSH =====\n'
  local h f n acct body opt fp
  inv_head "authorized_keys (inbound access)"
  local akany=""
  while IFS= read -r h; do
    acct=$(basename "$h")
    for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do
      [ -f "$f" ] || continue; akany=1
      n=$(grep -cvE '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null)
      inv "$acct: $n key(s)  (modified $(mtime_utc "$f"))"
      if [ -n "$SHOW_INV" ] && command -v ssh-keygen >/dev/null 2>&1; then ssh-keygen -lf "$f" 2>/dev/null | sed 's/^/       /'; fi
      ev_reset
      grep -qE 'command=|no-pty|permitopen=|environment=' "$f" 2>/dev/null && { scan_cmd "$(grep -oE 'command="[^"]*"' "$f" 2>/dev/null)"; ev 2 FORCED-OPTIONS; }
      mod_svcacct "$acct"; mod_recent "$f"; mod_immutable "$f"
      finish_item ssh "authorized_keys:$acct" "$f" "$n keys"
    done
  done < <(user_homes)
  [ -z "$akany" ] && inv_none
  # sshd config — directives
  inv_head "sshd effective directives"
  local rootlogin ak fc akc
  if command -v sshd >/dev/null 2>&1; then
    rootlogin=$(sshd -T 2>/dev/null | awk '/^permitrootlogin/{print $2}')
    [ -n "$rootlogin" ] && inv "PermitRootLogin: $rootlogin"
  fi
  for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*; do
    [ -f "$f" ] || continue
    body=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null)
    ev_reset
    echo "$body" | grep -qiE '^[[:space:]]*ForceCommand' && { scan_cmd "$(echo "$body" | grep -iE '^[[:space:]]*ForceCommand')"; ev 3 SSHD-FORCECOMMAND; }
    echo "$body" | grep -qiE '^[[:space:]]*AuthorizedKeysCommand[[:space:]]' && ev 3 SSHD-AUTHKEYS-COMMAND
    echo "$body" | grep -iE '^[[:space:]]*AuthorizedKeysFile' | grep -qvE '\.ssh/authorized_keys' && ev 3 SSHD-AUTHKEYS-REDIRECT
    mod_recent "$f"
    finish_item ssh "sshd:$(basename "$f")" "$f" "sshd config directive"
  done
}

module_pam(){
  [ -n "$SHOW_INV" ] && printf '\n===== CURRENT PERSISTENCE: PAM =====\n'
  [ "$(id -u)" -ne 0 ] && inv "(not root — some /etc/pam.d files may be unreadable)"
  local f mods m std hv ln
  std='pam_(unix|unix2|deny|permit|env|limits|systemd|securetty|sepermit|nologin|faillock|tally2?|faildelay|pwquality|cracklib|pwhistory|sss|krb5|krb5|winbind|ldap|mkhomedir|loginuid|lastlog2?|motd|mail|keyinit|namespace|selinux|apparmor|umask|tty_audit|access|group|time|listfile|rootok|wheel|xauth|gnome_keyring|kwallet5?|ecryptfs|exec|python|succeed_if|warn|issue|filter|echo|shells|localuser|debug|ftp|userdb|extrausers|gdm|fprintd|u2f|yubico|google_authenticator|oath|cap|cifscreds|rhosts|stress|timestamp)\.so'
  # Show the actual module chains for the crown-jewel stacks — this is where a backdoor line
  # (pam_permit sufficient, pam_exec, a rogue module) hides. mtime dates any tampering.
  inv_head "high-value auth stacks — module chain + mtime (read these top-to-bottom)"
  for hv in common-auth common-account common-password common-session system-auth password-auth sshd sudo su login; do
    f="/etc/pam.d/$hv"; [ -f "$f" ] || continue
    inv "$f   (mtime $(mtime_utc "$f"))"
    while IFS= read -r ln; do inv "      $ln"; done < <(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null)
  done
  inv_head "other PAM services present"
  inv "$(ls /etc/pam.d 2>/dev/null | grep -vE '^(common-auth|common-account|common-password|common-session|system-auth|password-auth|sshd|sudo|su|login)$' | tr '\n' ' ')"
  for f in /etc/pam.d/*; do
    [ -f "$f" ] || continue
    # (a) absolute: pam_permit/succeed_if sufficient in an AUTH stack
    grep -viE '^[[:space:]]*#' "$f" 2>/dev/null | grep -qiE '^[[:space:]]*auth[[:space:]]+(sufficient|\[success=)[^#]*pam_(permit|succeed_if)\.so' && \
      queue_abs HIGH pam "$(basename "$f")" "$f" "PAM-PERMIT-BACKDOOR (auth sufficient pam_permit/succeed_if — any password authenticates)"
    # (b) pam_exec/pam_python running a script
    if grep -viE '^[[:space:]]*#' "$f" 2>/dev/null | grep -qiE 'pam_(exec|python)\.so'; then
      queue_abs NOTABLE pam "$(basename "$f")" "$f" "PAM-EXEC-SCRIPT (pam_exec/pam_python runs a program during auth — read it: $(grep -iE 'pam_(exec|python)' "$f" 2>/dev/null | tr '\n' ';'))"
    fi
    # (c) a referenced module that isn't a standard name
    mods=$(grep -viE '^[[:space:]]*#' "$f" 2>/dev/null | grep -oE 'pam_[A-Za-z0-9_]+\.so' | sort -u)
    while IFS= read -r m; do [ -z "$m" ] && continue
      echo "$m" | grep -qiE "^$std$" || queue_abs HIGH pam "$(basename "$f")" "$f" "PAM-NONSTANDARD-MODULE ($m referenced — not a known module name)"
    done < <(echo "$mods")
  done
  # dropped modules on disk unowned by any package (usrmerge-aware) -> unowned list
  for f in /lib/security/pam_*.so /lib64/security/pam_*.so /usr/lib/security/pam_*.so /usr/lib64/security/pam_*.so /lib/*/security/pam_*.so /usr/lib/*/security/pam_*.so; do
    [ -f "$f" ] || continue
    pkg_owns "$f"; [ $? -eq 1 ] && { note_unowned "$f (PAM module)"; queue_abs NOTABLE pam "module:$(basename "$f")" "$f" "PAM-UNOWNED-MODULE (a pam_*.so owned by no package — dropped module)"; }
  done
}

module_accounts(){
  [ -n "$SHOW_INV" ] && printf '\n===== CURRENT PERSISTENCE: accounts & sudo =====\n'
  [ "$(id -u)" -ne 0 ] && inv "(not root — /etc/shadow empty-password check skipped)"
  local u x uid gid gecos home shell f body grants
  inv_head "interactive accounts (login shell)"
  while IFS=: read -r u x uid gid gecos home shell; do
    case "$uid" in ''|*[!0-9]*) continue;; esac
    [ "$uid" = 0 ] && [ "$u" != root ] && queue_abs HIGH accounts "$u" "/etc/passwd" "UID0-NONROOT (a non-root account with uid 0 — hidden superuser)"
    case "$shell" in */nologin|*/false|/dev/null|/bin/sync|'') continue;; esac
    inv "$u  uid=$uid  gid=$gid  $shell  $home"
    if [ "$uid" -lt 1000 ] && [ "$uid" -ne 0 ] && echo "$u" | grep -qE "^($SVC_ACCTS)$"; then
      queue_abs NOTABLE accounts "$u" "/etc/passwd" "SVC-ACCT-SHELL (service account uid=$uid has interactive shell $shell — account hiding)"
    fi
  done < <({ getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null; })
  if [ -r /etc/shadow ]; then
    while IFS=: read -r u body x; do [ -z "$u" ] && continue
      [ -z "$body" ] && queue_abs HIGH accounts "$u" "/etc/shadow" "EMPTY-PASSWORD (account has no password — passwordless login)"
    done < /etc/shadow
  fi
  # sudo — inventory as privileged-access context; anomaly only for service-acct grant / unowned+payload
  inv_head "sudo grants"
  local sany=""
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    case "$(basename "$f")" in README|*.dpkg-*) continue;; esac
    body=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$|^[[:space:]]*Defaults' "$f" 2>/dev/null)
    [ -z "$body" ] && continue; sany=1
    echo "$body" | while IFS= read -r line; do [ -n "$line" ] && inv "[$(basename "$f")] $line"; done
    # NOPASSWD for a human admin is on nearly every cloud/workstation box → inventory, not an
    # anomaly. The real signal is a SERVICE account granted sudo (it never should be).
    grants=$(echo "$body" | grep -E '^[A-Za-z_][A-Za-z0-9_.-]*[[:space:]].*=' | awk '{print $1}')
    while IFS= read -r g; do [ -z "$g" ] && continue
      echo "$g" | grep -qE "^($SVC_ACCTS)$" && queue_abs NOTABLE accounts "sudo:$g" "$f" "SVC-ACCT-SUDO (service account $g granted sudo — unexpected)"
    done < <(echo "$grants")
  done
  [ -z "$sany" ] && inv_none
}

module_preload(){
  local f p line u
  # 1. ld.so.preload populated — absolute
  if [ -s /etc/ld.so.preload ]; then
    queue_abs HIGH preload "ld.so.preload" "/etc/ld.so.preload" "LD-SO-PRELOAD (loads a .so into every dynamically-linked process: $(tr '\n' ';' < /etc/ld.so.preload 2>/dev/null))"
  fi
  # 2. LD_PRELOAD / LD_AUDIT in config / profile / pam_env — absolute
  for f in /etc/environment /etc/profile /etc/profile.d/* /etc/security/pam_env.conf /etc/ld.so.conf /etc/ld.so.conf.d/*; do
    [ -f "$f" ] || continue
    grep -qiE '^[[:space:]]*(export[[:space:]]+)?(LD_PRELOAD|LD_AUDIT)=' "$f" 2>/dev/null || continue
    queue_abs HIGH preload "$(basename "$f")" "$f" "LD-PRELOAD-CONFIG ($(grep -iE 'LD_PRELOAD|LD_AUDIT' "$f" 2>/dev/null | tr '\n' ';'))"
  done
  # 3. live processes carrying LD_PRELOAD/LD_AUDIT (read-only /proc)
  if [ -r /proc/1/environ ] || [ "$(id -u)" -eq 0 ]; then
    for p in /proc/[0-9]*; do
      [ -r "$p/environ" ] || continue
      line=$(tr '\0' '\n' 2>/dev/null < "$p/environ" | grep -E '^LD_PRELOAD=|^LD_AUDIT=')
      [ -z "$line" ] && continue
      queue_abs HIGH preload "pid $(basename "$p") ($(tr -d '\0' 2>/dev/null < "$p/comm"))" "$p/environ" "LD-PRELOAD-LIVE ($(echo "$line" | tr '\n' ';'))"
    done
  fi
}

module_kmod(){
  local f v_lsmod v_proc diff1
  # hidden module — in /proc/modules but not lsmod (self-hiding LKM). Absolute.
  v_lsmod=$(lsmod 2>/dev/null | awk 'NR>1{print $1}' | sort -u)
  v_proc=$(awk '{print $1}' /proc/modules 2>/dev/null | sort -u)
  if [ -n "$v_proc" ]; then
    diff1=$(comm -13 <(echo "$v_lsmod") <(echo "$v_proc") 2>/dev/null)
    [ -n "$diff1" ] && queue_abs HIGH kmod "hidden-module" "/proc/modules vs lsmod" "HIDDEN-MODULE (in /proc/modules but not lsmod: $(echo "$diff1" | tr '\n' ' '))"
  fi
  # modprobe install/alias running a shell — absolute
  for f in /etc/modprobe.d/* /lib/modprobe.d/* /run/modprobe.d/* /usr/lib/modprobe.d/*; do
    [ -f "$f" ] || continue
    local hit; hit=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -E '^[[:space:]]*(install|alias)[[:space:]]' | grep -E '/bin/sh|/bin/bash|(^|[[:space:]])sh[[:space:]]|/tmp/|curl|wget|nc ')
    [ -z "$hit" ] && continue
    queue_abs HIGH kmod "modprobe:$(basename "$f")" "$f" "MODPROBE-INSTALL (runs a command on module load: $(echo "$hit" | tr '\n' ';'))"
  done
  # unowned .ko in the running kernel tree (deep) -> unowned list
  if [ -n "$DEEP" ] && { [ "$PKGMGR" = dpkg ] || [ "$PKGMGR" = rpm ]; }; then
    local kdir="/lib/modules/$(uname -r)"
    [ -d "$kdir" ] && while IFS= read -r f; do
      [ -f "$f" ] || continue; pkg_owns "$f"; [ $? -eq 1 ] && { note_unowned "$f (kernel module)"; queue_abs NOTABLE kmod "ko:$(basename "$f")" "$f" "UNOWNED-KO (kernel module owned by no package)"; }
    done < <(find "$kdir" \( -name '*.ko' -o -name '*.ko.*' \) 2>/dev/null)
  fi
}

module_procscan(){
  [ -d /proc/1 ] || return
  [ -n "$SHOW_INV" ] && printf '\n===== CURRENT PERSISTENCE: running processes (armed & live / fileless) =====\n'
  [ "$(id -u)" -ne 0 ] && inv "(not root — most /proc/*/exe and maps are unreadable; running-process coverage is partial)"
  local p pid exe real comm surf
  # C2: which resolved persistence targets (from cron/systemd above) are running RIGHT NOW.
  inv_head "persistence targets currently RUNNING (armed & live)"
  local liveany=""
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    [ -z "$exe" ] && continue
    comm=$(tr -d '\0' 2>/dev/null <"$p/comm")
    real=${exe% (deleted)}
    # correlation: this process is running a binary that a cron/unit above is armed to launch
    case "$ARMED_TARGETS" in
      *"
$real	"*)
        surf=$(printf '%s' "$ARMED_TARGETS" | awk -F'\t' -v b="$real" '$1==b{print $2; exit}')
        inv "pid $pid ($comm) → $real   [$surf]"; liveany=1
        # armed AND live AND the persistence item itself was flagged suspicious = confirmed active
        case "$SUSPECT_TARGETS" in *"
$real"*) queue_abs HIGH proc "pid $pid ($comm)" "$real" "CONFIRMED-ACTIVE (a persistence item flagged suspicious is running now — armed AND live: $real)";; esac;;
    esac
    # C1: the backing executable itself — fileless / suspicious provenance
    case "$exe" in
      *memfd:*) queue_abs HIGH proc "pid $pid ($comm)" "$p/exe" "PROC-MEMFD-EXE (executing from an anonymous memory fd — fileless: $exe)"; continue;;
    esac
    case "$real" in
      /tmp/*|/dev/shm/*|/var/tmp/*|/run/shm/*)
        queue_abs HIGH proc "pid $pid ($comm)" "$p/exe" "PROC-VOLATILE-EXE (running from a world-writable/volatile path: $exe)";;
      */.[!/]*)
        queue_abs HIGH proc "pid $pid ($comm)" "$p/exe" "PROC-HIDDEN-EXE (backing binary sits in a hidden path: $exe)";;
      *)
        if [ "$exe" != "$real" ]; then           # deleted backing file
          case "$real" in
            /usr/*|/bin/*|/sbin/*|/lib*|/opt/*)
              if [ -e "$real" ]; then
                inv "note: pid $pid ($comm) runs a deleted copy of $real (file still on disk — likely a pending restart after a package upgrade)"
              else
                queue_abs NOTABLE proc "pid $pid ($comm)" "$real" "PROC-DELETED-EXE (running a deleted system binary whose on-disk path is now gone: $real)"
              fi;;
            /home/*)
              queue_abs NOTABLE proc "pid $pid ($comm)" "$real" "PROC-DELETED-HOME-EXE (running a deleted binary from a home dir: $real)";;
          esac
        elif [ -n "$PKGMGR" ] && [ -n "$WINDOW_SET" ]; then   # present, unowned system binary
          # gated to incident-window runs: an unpackaged running binary (node/python from
          # /opt·/usr/local) is common & benign on app servers → context, not a routine finding.
          case "$real" in
            /usr/*|/bin/*|/sbin/*|/lib*|/opt/*) pkg_owns "$real"; [ $? -eq 1 ] && \
              queue_abs NOTABLE proc "pid $pid ($comm)" "$real" "PROC-UNOWNED-EXE (running a binary owned by no package: $real)";;
          esac
        fi;;
    esac
  done
  [ -z "$liveany" ] && inv "(no scanned persistence target is currently running)"
  procscan_maps
}
# C3: rogue shared objects mapped into live processes (deduped across all PIDs).
procscan_maps(){
  [ -n "$SHOW_INV" ] && inv_head "rogue shared objects mapped into live processes (deleted / tmpfs / memfd / unowned)"
  local p lib seen="" tag mapany=""
  for p in /proc/[0-9]*; do
    [ -r "$p/maps" ] || continue
    while IFS= read -r lib; do
      [ -z "$lib" ] && continue
      case "
$seen
" in *"
$lib
"*) continue;; esac      # already reported this path
      seen="$seen
$lib"
      case "$lib" in
        *memfd:*)                                 tag="mapped from an anonymous memory fd (fileless injection)";;
        *" (deleted)")                            tag="the mapped .so was deleted from disk (injected then unlinked)";;
        /tmp/*|/dev/shm/*|/var/tmp/*|/run/shm/*)  tag="mapped .so lives in a world-writable/volatile path";;
        */.[!/]*)                                 tag="mapped .so is in a hidden path";;
        *) tag="";;
      esac
      if [ -n "$tag" ]; then
        queue_abs HIGH proc "mapped $lib" "$lib" "PROC-ROGUE-LIB ($tag: $lib)"; mapany=1; continue
      fi
      # otherwise a .so from a NON-standard system location → pkg-check. Incident-window only:
      # unowned .so are common & benign (pip/npm/-local builds), so this broader net is opt-in via
      # --since/--days; the huge standard lib dirs are skipped to bound the dpkg/rpm calls.
      [ -n "$WINDOW_SET" ] && case "$lib" in
        /usr/lib/*|/lib/*|/usr/lib64/*|/lib64/*|/snap/*) : ;;
        /*) if [ -n "$PKGMGR" ]; then pkg_owns "$lib"; [ $? -eq 1 ] && { queue_abs NOTABLE proc "mapped $lib" "$lib" "PROC-UNOWNED-LIB (a .so owned by no package is mapped into a live process: $lib)"; mapany=1; }; fi;;
      esac
    done < <(awk '$6 ~ /^\/([^ ]*\.so[^ ]*|memfd:[^ ]*)$/ {
                    path=$6; if ($7=="(deleted)") path=path" (deleted)"
                    if (path ~ /\/memfd:/) { if ($2 ~ /x/) print path }  # only an EXECUTABLE memfd = fileless code; benign rw-p memfd data (PulseAudio/xshmfence/Mesa) is skipped
                    else print path
                  }' "$p/maps" 2>/dev/null)
  done
  [ -n "$SHOW_INV" ] && [ -z "$mapany" ] && inv "(none — no deleted/tmpfs/memfd/unowned .so mapped in)"
}

module_triggers(){
  [ -n "$SHOW_INV" ] && printf '\n===== CURRENT PERSISTENCE: event/login triggers =====\n'
  local f d body hit u n cp mp
  # udev RUN+= : inventory count; anomaly only on payload or unowned+/etc
  n=0
  for d in /etc/udev/rules.d /lib/udev/rules.d /run/udev/rules.d /usr/lib/udev/rules.d; do
    [ -d "$d" ] || continue
    for f in "$d"/*.rules; do
      [ -f "$f" ] || continue
      grep -qE 'RUN\+?=|PROGRAM=' "$f" 2>/dev/null || continue; n=$((n+1))
      ev_reset; scan_cmd "$(grep -E 'RUN\+?=|PROGRAM=' "$f" 2>/dev/null | tr '\n' ';')"
      case "$d" in /etc/udev/rules.d) pkg_owns "$f"; [ $? -eq 1 ] && { ev 2 UNOWNED; note_unowned "$f (udev)"; };; esac
      mod_recent "$f"
      finish_item udev "$(basename "$f")" "$f" "$(grep -E 'RUN\+?=|PROGRAM=' "$f" 2>/dev/null | head -1)"
    done
  done
  inv_head "udev rules with RUN+=/PROGRAM"; inv "$n rule file(s) (payload/unowned ones flagged below)"
  # XDG autostart : anomaly only on payload/temp; inventory = count
  n=0
  for f in /etc/xdg/autostart/*.desktop; do [ -f "$f" ] || continue; n=$((n+1))
    ev_reset; scan_cmd "$(grep -E '^Exec=' "$f" 2>/dev/null)"; mod_recent "$f"
    finish_item autostart "$(basename "$f")" "$f" "$(grep -E '^Exec=' "$f" 2>/dev/null | head -1)"
  done
  local uany=0
  while IFS= read -r u; do
    for f in "$u"/.config/autostart/*.desktop; do [ -f "$f" ] || continue; uany=$((uany+1))
      ev_reset; scan_cmd "$(grep -E '^Exec=' "$f" 2>/dev/null)"; mod_recent "$f"
      finish_item autostart "$(basename "$u"):$(basename "$f")" "$f" "$(grep -E '^Exec=' "$f" 2>/dev/null | head -1)"
    done
  done < <(user_homes)
  inv_head "XDG autostart entries"; inv "$n system + $uany user (payload/temp ones flagged below)"
  # update-motd.d : trust packaged; scan unowned
  for f in /etc/update-motd.d/*; do [ -f "$f" ] || continue
    pkg_owns "$f"; [ $? -eq 0 ] && continue
    ev_reset; ev 2 UNOWNED; note_unowned "$f (update-motd.d)"; scan_cmd "$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | tr '\n' ';')"; mod_recent "$f"
    finish_item motd "$(basename "$f")" "$f" "unowned motd script (runs as root on login)"
  done
  # NetworkManager dispatcher : trust packaged; scan unowned
  for f in /etc/NetworkManager/dispatcher.d/* /etc/NetworkManager/dispatcher.d/*/*; do [ -f "$f" ] || continue
    pkg_owns "$f"; [ $? -eq 0 ] && continue
    ev_reset; ev 2 UNOWNED; scan_cmd "$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | tr '\n' ';')"; mod_recent "$f"
    finish_item nm-dispatcher "$(basename "$f")" "$f" "unowned dispatcher script"
  done
  # core_pattern piping to a NON-default handler (apport/systemd-coredump are legit) — absolute
  cp=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
  inv_head "core_pattern (the kernel runs this on ANY process crash; a leading '|prog' pipes the core to prog as ROOT)"
  case "$cp" in
    \|*apport*|\|*systemd-coredump*) inv "$cp"; inv "→ distro default crash handler (apport / systemd-coredump) — expected";;
    \|*) inv "$cp   <== NON-default program"; queue_abs HIGH triggers "core_pattern" "/proc/sys/kernel/core_pattern" "CORE-PATTERN-PIPE (pipes to a non-default handler, runs as root on any crash: $cp)";;
    *) inv "${cp:-unset}"; inv "→ writes a plain core file (no program executed) — benign";;
  esac
  # kernel.modprobe repointed — absolute
  mp=$(cat /proc/sys/kernel/modprobe 2>/dev/null)
  case "$mp" in ''|/sbin/modprobe|/usr/sbin/modprobe|/bin/modprobe) : ;;
    *) queue_abs HIGH triggers "kernel.modprobe" "/proc/sys/kernel/modprobe" "KERNEL-MODPROBE-REPOINT (points at $mp)";; esac
  # binfmt_misc : inventory list; anomaly only if interpreter in tmp/home
  inv_head "binfmt_misc handlers"
  local bany=""
  if [ -d /proc/sys/fs/binfmt_misc ]; then
    for f in /proc/sys/fs/binfmt_misc/*; do [ -f "$f" ] || continue
      case "$(basename "$f")" in register|status) continue;; esac
      local interp; interp=$(grep -E '^interpreter' "$f" 2>/dev/null | awk '{print $2}'); bany=1
      inv "$(basename "$f") -> $interp"
      echo "$interp" | grep -qiE '/tmp/|/dev/shm/|/home/|/var/tmp/' && queue_abs HIGH triggers "binfmt:$(basename "$f")" "$f" "BINFMT-SUSPECT (interpreter in a writable path: $interp)"
    done
  fi
  [ -z "$bany" ] && inv_none
  # inetd / xinetd : anomaly if spawns a shell
  for f in /etc/inetd.conf; do [ -f "$f" ] || continue
    body=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null)
    [ -z "$body" ] && continue
    ev_reset; scan_cmd "$body"; echo "$body" | grep -qiE '/bin/sh|/bin/bash' && ev 3 INETD-SHELL
    finish_item inetd "inetd.conf" "$f" "$(echo "$body" | tr '\n' ';')"
  done
  for f in /etc/xinetd.d/*; do [ -f "$f" ] || continue
    ev_reset; scan_cmd "$(grep -iE 'server|server_args' "$f" 2>/dev/null | tr '\n' ';')"
    finish_item xinetd "$(basename "$f")" "$f" "$(grep -iE '^[[:space:]]*server' "$f" 2>/dev/null | tr '\n' ';')"
  done
  # apt hooks : trust packaged config; anomaly only on payload
  for f in /etc/apt/apt.conf.d/*; do [ -f "$f" ] || continue
    hit=$(grep -iE 'Post-Invoke|Pre-Invoke|DPkg::' "$f" 2>/dev/null)
    [ -z "$hit" ] && continue
    ev_reset; scan_cmd "$hit"; case "$f" in *) pkg_owns "$f"; [ $? -eq 1 ] && ev 2 UNOWNED;; esac; mod_recent "$f"
    finish_item apt-hook "$(basename "$f")" "$f" "$(echo "$hit" | tr '\n' ';' | cut -c1-160)"
  done
  # git hooksPath + mail .forward : anomaly on payload
  while IFS= read -r u; do
    f="$u/.gitconfig"; [ -f "$f" ] && grep -qi 'hooksPath' "$f" 2>/dev/null && {
      ev_reset; ev 2 GIT-HOOKSPATH; scan_cmd "$(grep -i hooksPath "$f" 2>/dev/null)"
      finish_item git "$(basename "$u")" "$f" "$(grep -i hooksPath "$f" 2>/dev/null | tr '\n' ';')"; }
    for f in "$u/.forward" "$u/.procmailrc"; do [ -f "$f" ] || continue
      body=$(cat "$f" 2>/dev/null); echo "$body" | grep -qE '^\||bash|sh|/' || continue
      ev_reset; scan_cmd "$body"; echo "$body" | grep -q '^|' && ev 2 MAIL-PIPE
      finish_item mail "$(basename "$u"):$(basename "$f")" "$f" "$(echo "$body" | tr '\n' ';')"
    done
  done < <(user_homes)
}

module_integrity(){
  [ -n "$DEEP" ] || { [ -n "$SHOW_INV" ] && printf '\n===== integrity (skipped — use --deep) =====\n'; return; }
  printf '\n===== integrity scan (--deep; this can take minutes) =====\n'
  local out line p
  if [ "$PKGMGR" = rpm ]; then
    out=$(rpm -Va 2>/dev/null | grep -E '^..5' | grep -E '/s?bin/|/lib')
  elif [ "$PKGMGR" = dpkg ] && command -v debsums >/dev/null 2>&1; then
    out=$(debsums -c 2>/dev/null)
  else
    printf '   integrity verification unavailable (need rpm, or dpkg + debsums)\n'
  fi
  while IFS= read -r line; do [ -z "$line" ] && continue
    p=$(echo "$line" | awk '{print $NF}')
    queue_abs HIGH integrity "$p" "$p" "INTEGRITY-FAIL (packaged file modified vs its package)"
  done < <(echo "$out")
  # dangerous caps + recent SUID — prune containers, trust packaged
  if command -v getcap >/dev/null 2>&1; then
    while IFS= read -r line; do [ -z "$line" ] && continue
      echo "$line" | grep -qiE 'cap_setuid|cap_dac_override|cap_dac_read_search|cap_sys_module|cap_sys_admin|cap_sys_ptrace' || continue
      local cf; cf=$(echo "$line" | awk '{print $1}')
      for pp in $PRUNE; do case "$cf" in "$pp"/*) continue 2;; esac; done   # getcap -r has no --prune; match find_real's container/virtual exclusions
      pkg_owns "$cf"; [ $? -eq 0 ] && continue          # packaged binary with caps = trusted
      queue_abs NOTABLE integrity "cap:$cf" "$cf" "CAP-DANGEROUS on an unowned binary ($line)"
    done < <(getcap -r / 2>/dev/null)
  fi
  if [ -n "$WINDOW_SET" ]; then
    while IFS= read -r line; do [ -z "$line" ] && continue
      queue_abs NOTABLE integrity "suid:$line" "$line" "SUID-RECENT (SUID-root binary created inside the window)"
    done < <(find_real / -type f -perm -4000 -user root -newermt "@${SINCE_EPOCH:-$((NOW-${RECENT_DAYS:-14}*86400))}" -print)
  fi
  printf '   integrity scan complete.\n'
}

# ================= footer =================
recent_logins(){
  [ -n "$SHOW_INV" ] || return
  printf '\n-- recent logins (last 8) --\n'
  local out; out=$(last -F -w -n 8 2>/dev/null | grep -vE '^wtmp|^$|^reboot' || last -n 8 2>/dev/null | grep -vE '^wtmp|^$|^reboot')
  [ -n "$out" ] && echo "$out" | sed 's/^/   /' || printf '   (none)\n'
}

# ================= arg parsing =================
while [ $# -gt 0 ]; do
  case "$1" in
    --since) SINCE_EPOCH=$(date -d "$2" +%s 2>/dev/null); WINDOW_SET=1; [ -z "$SINCE_EPOCH" ] && { echo "bad --since (YYYY-MM-DD)" >&2; exit 2; }; shift;;
    --days) RECENT_DAYS="$2"; WINDOW_SET=1; shift;;
    --deep) DEEP=1;;
    --modules) MODULES="$2"; shift;;
    --min-severity) case "$2" in high|HIGH) MIN_SEV=3;; notable|NOTABLE) MIN_SEV=2;; *) echo "bad --min-severity (high|notable)" >&2; exit 2;; esac; shift;;
    --inventory-only) SHOW_ANOM="";;
    --anomalies-only) SHOW_INV="";;
    -h|--help) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 2;;
  esac
  shift
done

all_mods="cron systemd initscripts shell ssh pam accounts preload kmod procscan triggers integrity"
[ -n "$MODULES" ] && run="${MODULES//,/ }" || run="$all_mods"

# ================= run =================
detect_env
echo "hunt_persistence.sh  v${VERSION}    author: ${AUTHOR}"
echo "Ran at   : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "Command  : hunt_persistence.sh ${RAW_ARGS:-<none>}"
[ "$(id -u)" -ne 0 ] && printf '!! not root — per-user cron spools, /etc/shadow, other users, /proc/*/environ may be incomplete. Re-run with sudo.\n'

triage
[ -n "$SHOW_INV" ] && module_recency

for m in $run; do
  [ -z "$SHOW_INV" ] && [ -z "$SHOW_ANOM" ] && break
  case "$m" in
    cron) module_cron;;
    systemd) module_systemd;;
    initscripts) module_initscripts;;
    shell) module_shell;;
    ssh) module_ssh;;
    pam) module_pam;;
    accounts) module_accounts;;
    preload) module_preload;;
    kmod) module_kmod;;
    procscan) module_procscan;;
    triggers) module_triggers;;
    integrity) module_integrity;;
    *) echo "unknown module: $m" >&2;;
  esac
done

recent_logins

if [ -n "$SHOW_ANOM" ]; then
  printf '\n===== ANOMALIES (evidence-backed queue) =====\n'
  if [ -z "$ANOM_HIGH$ANOM_NOTABLE" ]; then
    printf '   none — no payload / integrity / absolute signals fired.\n'
  else
    [ -n "$ANOM_HIGH" ] && printf '%s\n' "$ANOM_HIGH"
    [ "$MIN_SEV" -le 2 ] && [ -n "$ANOM_NOTABLE" ] && printf '%s\n' "$ANOM_NOTABLE"
  fi
  if [ -n "$UNOWNED_LIST" ]; then
    printf '\n-- UNOWNED files in system persistence dirs (context, NOT a verdict) --\n'
    printf '   No package installed these — they were added by an admin, a package postinstall script,\n'
    printf '   or an attacker. Cross-check each against your known changes; an unexplained one is a lead.\n'
    printf '   (path · location type · mtime)%s\n' "$UNOWNED_LIST"
  fi
  printf '\n==== %s HIGH · %s NOTABLE  (evidence-backed; unowned list is context) ====\n' "$HI" "$NO"
  printf 'Basis for a finding: behavioral payload, integrity break, hard absolute, or (with --since/--days) incident-window recency. Mechanisms alone are NOT flagged.\n'
fi
