#!/bin/bash
# hunt_intrusion.sh — read-only Linux active-intrusion / anomaly triage.  (v1.1)  author: Suvas Patel
#
# The companion to hunt_persistence.sh. That script answers "what persists on disk";
# THIS one answers "is an intruder active right now, and is the box lying to me about it?"
# It hunts behaviour and relationships — process lineage, network-backed shells, masquerade,
# self-hiding, timestomping, log gaps — rather than persistence mechanisms.
#
# Same doctrine as the persistence hunter: FLAG ON EVIDENCE, ENUMERATE EVERYTHING ELSE.
# A mechanism existing is never the signal; a behavioural payload / hard tell is.
#
# Modules:
#   lineage    process tree — impossible parentage (web/db → shell = webshell/RCE, cron → payload)
#   netshell   a shell/interpreter whose stdio is a socket (reverse/bind shell) + rogue listeners
#   masquerade fake kernel threads, non-ASCII/space process names, fileless (memfd/tmpfs/deleted) exe
#   argv       payloads in LIVE command lines (/proc/*/cmdline) — inline interp, GTFObins, download-exec
#   hidden     cross-view diffs — hidden PIDs (/proc vs ps), hidden ports (/proc/net vs ss), hidden modules
#   ebpf       loaded BPF hooking programs with no known observability agent; kprobe/ftrace hooks
#   nsmask     a filesystem bind-mounted over a system file (hide-a-file); best-effort namespace notes
#   timestomp  birth-after-mtime, zeroed-nanosecond mtimes on UNOWNED files (planted then time-faked)
#   clustering an "install event" — many files across surfaces sharing a tight mtime window (needs a window)
#   loggaps    audit/log evasion — auditd stopped, wiped wtmp/btmp, HISTFILE=/dev/null, no-persist journald
#   elf        setuid interpreters + ELF anomalies (packed / RWX segment / static) on unowned binaries
#
# READ-ONLY / NON-DESTRUCTIVE. Console-only (or --json NDJSON for fleet rarity stacking). Root for full coverage.
#
# Usage:  bash hunt_intrusion.sh [options]
#   --since YYYY-MM-DD   incident window: promote items changed on/after this date (enables clustering)
#   --days N             incident window: promote items changed in the last N days
#   --deep               widen the slow sweeps (timestomp + elf over system bin dirs, larger clustering scope)
#   --modules a,b,c      limit to: lineage netshell masquerade argv hidden ebpf nsmask timestomp clustering loggaps elf
#   --min-severity T     anomaly filter: high | notable  (default: show both)
#   --inventory-only     triage + inventory, skip the anomaly scan
#   --anomalies-only     skip the inventory listing
#   --json               emit findings + key facts as NDJSON (one object per line) for fleet aggregation
#   -h | --help
#
# Part of the Linux DFIR Field Reference — see "10 - Live Response and Volatile Data" and
# "10b - Process Trees and Execution Lineage".

VERSION="1.1"; AUTHOR="Suvas Patel"
RAW_ARGS="$*"
NOW=$(date +%s)
WINDOW_SET=""; SINCE_EPOCH=""; RECENT_DAYS=""
DEEP=""; MODULES=""; MIN_SEV=2; SHOW_INV=1; SHOW_ANOM=1; JSON=""
PKGMGR=""; INIT=""; DISTRO=""
HI=0; NO=0

# Process-class vocabularies (behavioural, not host-specific).
SHELLS='sh|bash|dash|zsh|ksh|tcsh|csh|fish|ash'
INTERP='python[0-9.]*|perl|ruby|php[0-9.]*|php|node|nodejs|lua[0-9.]*|tclsh'
NETTOOLS='nc|nc\.traditional|ncat|netcat|socat|telnet'
# network-facing / data services that should NEVER be the parent of an interactive shell
WEBDB='nginx|apache2|httpd|php-fpm[0-9.]*|php-fpm|lighttpd|caddy|haproxy|varnishd|tomcat|catalina|gunicorn|uwsgi|mysqld|mariadbd|postgres|postmaster|mongod|redis-server|memcached|vsftpd|proftpd|pure-ftpd|smbd|dovecot|exim4|exim|master|sshd'
# kernel-thread name prefixes (real kthreads have NO exe and NO cmdline)
KTHREAD='kworker|ksoftirqd|migration|rcu_|rcuo|kthreadd|kswapd|kcompactd|kdevtmpfs|watchdogd?|kauditd|khugepaged|kintegrityd|kblockd|scsi_|jbd2|ext4-|xfs-|kdmflush|irq/|cpuhp|netns|kstrp|oom_reaper|writeback|ksmd|khungtaskd|acpi_|ipv6_addrconf|kthrotld|kmpath|kaluad|nvme-|mld|ipv6_'
# service accounts (mirrors the persistence hunter)
SVC_ACCTS="www-data|nobody|postgres|apache|nginx|mysql|mariadb|daemon|bin|sys|games|mail|news|uucp|proxy|list|irc|gnats|ftp|redis|memcached|mongodb|rabbitmq|elasticsearch|tomcat|jenkins|zabbix|prometheus|grafana|haproxy|varnish|sshd|_apt|systemd-network|systemd-resolve|messagebus|syslog|tss|landscape|pollinate"
PRUNE="/proc /sys /run /dev /var/lib/docker /var/lib/containers /var/lib/lxc /var/lib/lxd /var/lib/snapd /snap"

usage(){ sed -n '2,44p' "$0" | sed 's/^# \{0,1\}//'; }

# ================= output plumbing =================
ANOM_HIGH=""; ANOM_NOTABLE=""
inv_head(){ [ -z "$JSON" ] && [ -n "$SHOW_INV" ] && printf '\n-- %s --\n' "$1"; }
inv(){ [ -z "$JSON" ] && [ -n "$SHOW_INV" ] && printf '   %s\n' "$1"; }
inv_none(){ [ -z "$JSON" ] && [ -n "$SHOW_INV" ] && printf '   (none)\n'; }
sect(){ [ -z "$JSON" ] && printf '\n===== %s =====\n' "$1"; }

# ---- NDJSON (fleet rarity stacking) ----
JHOST=$(hostname 2>/dev/null); JTS=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
jesc(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n\t' '  '; }
jrec(){ [ -n "$JSON" ] || return
  printf '{"type":"%s","host":"%s","ts":"%s","module":"%s","tier":"%s","label":"%s","where":"%s","why":"%s"}\n' \
    "$1" "$(jesc "$JHOST")" "$JTS" "$2" "$3" "$(jesc "$4")" "$(jesc "$5")" "$(jesc "$6")"; }

# ================= scoring engine (shared with hunt_persistence.sh) =================
EV_SCORE=0; EV_REASONS=""
ev_reset(){ EV_SCORE=0; EV_REASONS=""; }
ev(){ EV_SCORE=$((EV_SCORE+$1)); case " $EV_REASONS " in *" $2 "*) ;; *) EV_REASONS="$EV_REASONS $2";; esac; }
ev_tier(){ if [ "$EV_SCORE" -ge 5 ]; then echo HIGH; elif [ "$EV_SCORE" -ge 3 ]; then echo NOTABLE; else echo LOW; fi; }

# scan_cmd COMMAND — add payload evidence (identical patterns to the persistence hunter).
scan_cmd(){
  local c="$1"
  echo "$c" | grep -qiE '/dev/tcp/|/dev/udp/|nc[[:space:]]+[^;|]*-e|ncat[[:space:]]+[^;|]*-e|bash[[:space:]]+-i|(^|[[:space:]])sh[[:space:]]+-i|socat[[:space:]]+[^;|]*exec' && ev 5 REVERSE-SHELL
  echo "$c" | grep -qiE '(curl|wget|fetch)[^;&|]*\|[^;&|]*(ba)?sh|(curl|wget|fetch)[^;&|]*\|[^;&|]*(python|perl|php|ruby)' && ev 5 DOWNLOAD-EXEC
  echo "$c" | grep -qiE '(base64|xxd|openssl[[:space:]]+enc)[^;&|]*(-d|-D|-r)[^;&|]*\|[^;&|]*(ba)?sh' && ev 5 DECODE-EXEC
  echo "$c" | grep -qiE '(python[0-9]?|perl|ruby|php)[[:space:]]+-[ce][^;]*(socket|subprocess|exec|/dev/tcp|os\.system)' && ev 5 SCRIPT-SHELL
  echo "$c" | grep -qiE '/tmp/|/dev/shm/|/var/tmp/|/run/shm/' && ev 4 TEMP-PATH
  echo "$c" | grep -qiE '/(usr|opt|etc|var|srv|boot|root|lib|lib64)/[^;:[:space:]]*/\.[A-Za-z0-9]' && ev 2 HIDDEN-SYSPATH
  echo "$c" | grep -qiE 'eval[[:space:]]+["'\''`]?\$\(|eval[[:space:]]+["'\''`]?base64' && ev 3 EVAL-OBFUSCATED
}

# finish_item MODULE LABEL WHERE WHAT — queue as an anomaly iff evidence reached NOTABLE+.
finish_item(){
  [ "$EV_SCORE" -lt 3 ] && return
  local t; t=$(ev_tier)
  local block; block=$(printf '\n[%s] %s: %s\n   where: %s\n   what : %s\n   why  :%s\n' "$t" "$1" "$2" "$3" "$4" "$EV_REASONS")
  case "$t" in HIGH) ANOM_HIGH="$ANOM_HIGH$block"; HI=$((HI+1));; NOTABLE) ANOM_NOTABLE="$ANOM_NOTABLE$block"; NO=$((NO+1));; esac
  jrec finding "$1" "$t" "$2" "$3" "$EV_REASONS"
}
# queue_abs TIER MODULE LABEL WHERE WHY — hard tell, bypasses evidence stacking.
queue_abs(){
  local block; block=$(printf '\n[%s] %s: %s\n   where: %s\n   what : %s\n' "$1" "$2" "$3" "$4" "$5")
  case "$1" in HIGH) ANOM_HIGH="$ANOM_HIGH$block"; HI=$((HI+1));; NOTABLE) ANOM_NOTABLE="$ANOM_NOTABLE$block"; NO=$((NO+1));; esac
  jrec finding "$2" "$1" "$3" "$4" "$5"
}

# ================= timestamps & provenance (shared) =================
mtime_epoch(){ stat -c %Y "$1" 2>/dev/null; }
is_recent(){ local m; m=$(mtime_epoch "$1"); [ -z "$m" ] && return 1
  if [ -n "$SINCE_EPOCH" ]; then [ "$m" -ge "$SINCE_EPOCH" ]; else [ $(((NOW-m)/86400)) -lt "${RECENT_DAYS:-14}" ]; fi; }
pkg_owns(){
  local f="$1"; { [ -e "$f" ] && [ ! -L "$f" ]; } || return 2
  case "$PKGMGR" in
    dpkg) dpkg -S "$f" >/dev/null 2>&1 && return 0
      case "$f" in
        /usr/lib/*|/usr/bin/*|/usr/sbin/*) dpkg -S "${f#/usr}" >/dev/null 2>&1 && return 0;;
        /lib/*|/lib64/*|/bin/*|/sbin/*)    dpkg -S "/usr$f"    >/dev/null 2>&1 && return 0;;
      esac; return 1;;
    rpm)    rpm -qf "$f"    >/dev/null 2>&1 && return 0 || return 1;;
    pacman) pacman -Qo "$f" >/dev/null 2>&1 && return 0 || return 1;;
    apk)    apk info -W "$f" >/dev/null 2>&1 && return 0 || return 1;;
    *) return 2;;
  esac
}
user_homes(){
  { getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null; } | awk -F: '{print $6}' | sort -u | while IFS= read -r h; do
    case "$h" in ''|/|/nonexistent|/dev/null|/proc/*|/bin|/sbin|/usr/sbin|/run/*) continue;; esac
    [ -d "$h" ] && echo "$h"
  done
}
find_real(){ local p args=(); for p in $PRUNE; do args+=(-path "$p" -o); done; find "$1" -xdev \( "${args[@]}" -false \) -prune -o "${@:2}" 2>/dev/null; }

# ================= /proc helpers =================
p_comm(){ tr -d '\0' 2>/dev/null < "/proc/$1/comm"; }        # 2>/dev/null BEFORE < : a PID that exits mid-scan makes the open fail; redirected fd2 swallows it
p_exe(){ readlink "/proc/$1/exe" 2>/dev/null; }
p_cmdline(){ tr '\0' ' ' 2>/dev/null < "/proc/$1/cmdline" | sed 's/[[:space:]]*$//'; }
p_ppid(){ awk '/^PPid:/{print $2; exit}' "/proc/$1/status" 2>/dev/null; }

# susp_exe EXE  -> a reason string if the backing binary is suspicious, else empty.
# (deleted SYSTEM binaries whose path still exists = benign pending-upgrade, per the persistence hunter.)
susp_exe(){
  local e="$1" real; [ -z "$e" ] && return
  case "$e" in *memfd:*) printf 'runs from an anonymous memory fd (fileless)'; return;; esac
  real=${e% (deleted)}
  case "$real" in
    /tmp/*|/dev/shm/*|/var/tmp/*|/run/shm/*) printf 'runs from a world-writable/volatile path'; return;;
    */.[!/]*)                                printf 'runs from a hidden path'; return;;
  esac
  if [ "$e" != "$real" ]; then
    case "$real" in
      /usr/*|/bin/*|/sbin/*|/lib*|/opt/*) [ -e "$real" ] || { printf 'runs a deleted binary whose on-disk path is gone'; return; };;
      /home/*) printf 'runs a deleted binary from a home dir'; return;;
    esac
  elif [ -n "$PKGMGR" ] && [ -n "$WINDOW_SET" ]; then
    case "$real" in /usr/*|/bin/*|/sbin/*|/lib*|/opt/*) pkg_owns "$real"; [ $? -eq 1 ] && { printf 'runs a binary owned by no package'; return; };; esac
  fi
}
# sock_remote INODE -> "ip:port" of the remote peer (IPv4 resolved; IPv6 shown raw)
sock_remote(){
  local inode="$1" f rem hip hpt
  for f in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
    [ -r "$f" ] || continue
    rem=$(awk -v i="$inode" 'NR>1 && $10==i{print $3; exit}' "$f" 2>/dev/null)
    [ -n "$rem" ] && break
  done
  [ -z "$rem" ] && return
  hip=${rem%:*}; hpt=${rem#*:}
  if [ ${#hip} -eq 8 ]; then
    printf '%d.%d.%d.%d:%d' "0x${hip:6:2}" "0x${hip:4:2}" "0x${hip:2:2}" "0x${hip:0:2}" "0x$hpt"
  else
    printf '[v6:%s]:%d' "$hip" "0x$hpt"
  fi
}

# ================= host triage (lite) =================
detect_env(){
  if   command -v dpkg   >/dev/null 2>&1; then PKGMGR=dpkg
  elif command -v rpm    >/dev/null 2>&1; then PKGMGR=rpm
  elif command -v pacman >/dev/null 2>&1; then PKGMGR=pacman
  elif command -v apk    >/dev/null 2>&1; then PKGMGR=apk; fi
  if   [ -d /run/systemd/system ] || command -v systemctl >/dev/null 2>&1; then INIT=systemd; else INIT=other; fi
  DISTRO=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")
}
triage(){
  [ -n "$JSON" ] && return
  printf '\n===== HOST TRIAGE =====\n'
  printf '  Hostname   : %s\n' "$(hostname 2>/dev/null)"
  printf '  Distro     : %s\n' "$DISTRO"
  printf '  Kernel     : %s\n' "$(uname -r 2>/dev/null)"
  command -v systemd-detect-virt >/dev/null 2>&1 && printf '  Virt       : %s\n' "$(systemd-detect-virt 2>/dev/null)"
  printf '  Booted     : %s\n' "$(uptime -s 2>/dev/null || echo unknown)"
  printf '  Pkg mgr    : %s\n' "${PKGMGR:-none (provenance checks disabled)}"
  printf '  Processes  : %s live PIDs\n' "$(ls -d /proc/[0-9]* 2>/dev/null | wc -l | tr -d ' ')"
  printf '  Window     : %s\n' "$([ -n "$WINDOW_SET" ] && echo "incident — recency/clustering enabled, unowned nets widened" || echo "none (use --since/--days for IR)")"
}

# ================= modules =================

module_lineage(){
  sect "PROCESS LINEAGE — impossible parentage"
  local p pid comm ppid pcomm cmd
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    comm=$(p_comm "$pid"); [ -z "$comm" ] && continue
    echo "$comm" | grep -qE "^($SHELLS|$INTERP|$NETTOOLS)$" || continue
    ppid=$(p_ppid "$pid"); [ -z "$ppid" ] && continue
    pcomm=$(p_comm "$ppid"); cmd=$(p_cmdline "$pid")
    [ -n "$JSON" ] && jrec inventory lineage - "$pcomm->$comm" "pid $pid ppid $ppid" "$cmd"
    ev_reset
    # a network/data service is the parent of a shell/interpreter → webshell / RCE
    if echo "$pcomm" | grep -qE "^($WEBDB)$"; then
      ev 4 SVC-SPAWNED-SHELL; scan_cmd "$cmd"
      susp=$(susp_exe "$(p_exe "$pid")"); [ -n "$susp" ] && ev 3 SUSPECT-EXE
      finish_item lineage "$pcomm -> $comm" "pid $pid (ppid $ppid $pcomm)" "$cmd"
      continue
    fi
    # cron/atd running a payload (cron→shell is normal; the payload is the tell)
    if echo "$pcomm" | grep -qE '^(cron|crond|atd|anacron)$'; then
      scan_cmd "$cmd"; [ "$EV_SCORE" -ge 3 ] && finish_item lineage "$pcomm -> $comm" "pid $pid (ppid $ppid)" "cron-spawned: $cmd"
      continue
    fi
    # a live netcat/socat/ncat as any child = interactive networking tool running now
    if echo "$comm" | grep -qE "^($NETTOOLS)$"; then
      ev 3 LIVE-NETTOOL; scan_cmd "$cmd"
      finish_item lineage "$pcomm -> $comm" "pid $pid (ppid $ppid)" "$cmd"
    fi
  done
}

module_netshell(){
  sect "NETWORK-BACKED SHELLS (stdio→socket) + rogue listeners"
  local p pid comm exe fd tgt sock inode rem reason susp
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    comm=$(p_comm "$pid"); [ -z "$comm" ] && continue
    sock=""
    for fd in 0 1 2; do
      tgt=$(readlink "$p/fd/$fd" 2>/dev/null)
      case "$tgt" in socket:\[*\]) inode=${tgt#socket:[}; sock="$sock ${inode%]}";; esac
    done
    [ -z "$sock" ] && continue
    exe=$(p_exe "$pid")
    # FP guard: socket-activated / inetd services are packaged daemons, not shells.
    reason=""
    if echo "$comm" | grep -qE "^($SHELLS|$INTERP|$NETTOOLS)$"; then
      reason="a shell/interpreter with its stdio wired to a socket (classic reverse/bind shell)"
    else
      susp=$(susp_exe "$exe"); [ -n "$susp" ] && reason="a process whose stdio is a socket and which $susp"
    fi
    [ -z "$reason" ] && continue
    inode=$(echo $sock | awk '{print $1}'); rem=$(sock_remote "$inode")
    queue_abs HIGH netshell "pid $pid ($comm)" "/proc/$pid/fd → socket:[$inode]" "REVERSE-SHELL — $reason${rem:+ ; peer $rem} ; exe=${exe:-?}"
  done
  # rogue listeners: a listening socket whose backing binary is suspicious
  if command -v ss >/dev/null 2>&1; then
    inv_head "listening sockets → backing process"
    local line lpid lexe la lproto
    while IFS= read -r line; do
      lpid=$(echo "$line" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
      [ -z "$lpid" ] && continue
      lproto=$(echo "$line" | awk '{print $1}'); la=$(echo "$line" | awk '{print $5}'); lexe=$(p_exe "$lpid")
      inv "$lproto $la  pid $lpid ($(p_comm "$lpid"))  ${lexe:-?}"
      [ -n "$JSON" ] && jrec inventory netshell - "listener $lproto $la" "pid $lpid" "${lexe:-?}"
      susp=$(susp_exe "$lexe"); [ -n "$susp" ] && \
        queue_abs HIGH netshell "listener $lproto $la (pid $lpid $(p_comm "$lpid"))" "${lexe:-?}" "ROGUE-LISTENER — the process bound to $lproto $la $susp"
    done < <(ss -tulpnH 2>/dev/null)
  fi
}

module_masquerade(){
  sect "PROCESS MASQUERADE / FAKE KERNEL THREADS"
  local p pid comm exe cmd susp
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    comm=$(p_comm "$pid"); [ -z "$comm" ] && continue
    exe=$(p_exe "$pid"); cmd=$(p_cmdline "$pid")
    # real kernel threads have NO exe and NO cmdline; a kthread-named process that has either is fake
    if echo "$comm" | grep -qE "^($KTHREAD)"; then
      { [ -n "$exe" ] || [ -n "$cmd" ]; } && \
        queue_abs HIGH masquerade "pid $pid ($comm)" "${exe:-<no exe>}" "FAKE-KTHREAD — a kernel-thread name but it has a userland exe/cmdline (impersonation): exe=${exe:-?} cmd=${cmd:-?}"
      continue
    fi
    # ps-hiding tricks in the process name
    case "$comm" in *' ') queue_abs NOTABLE masquerade "pid $pid" "${exe:-?}" "COMM-TRAILING-SPACE — process name ends in whitespace (ps-hiding): '$comm'";; esac
    printf '%s' "$comm" | LC_ALL=C grep -q '[^ -~]' && \
      queue_abs NOTABLE masquerade "pid $pid" "${exe:-?}" "COMM-NONPRINTABLE — non-ASCII/control char in process name (hiding): '$comm'"
    # fileless / suspicious backing binary
    susp=$(susp_exe "$exe"); [ -n "$susp" ] && \
      queue_abs HIGH masquerade "pid $pid ($comm)" "$exe" "SUSPECT-EXE — $susp: $exe"
  done
}

module_argv(){
  sect "LIVE COMMAND-LINE PAYLOADS (/proc/*/cmdline)"
  local p pid comm cmd a0 xe et
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    cmd=$(p_cmdline "$pid"); [ -z "$cmd" ] && continue
    comm=$(p_comm "$pid")
    ev_reset
    scan_cmd "$cmd"
    # scan_cmd's TEMP-PATH matches /tmp anywhere in argv; in a LIVE cmdline that is usually a data/tmpdir
    # option value (e.g. -Djava.io.tmpdir=/tmp/...), not execution FROM temp. Keep it only when the
    # executable itself (argv[0] or the real /proc/PID/exe target) lives in a volatile path.
    case " $EV_REASONS " in *" TEMP-PATH "*)
      a0=${cmd%% *}; xe=$(readlink "/proc/$pid/exe" 2>/dev/null); et=""
      case "$a0" in /tmp/*|/dev/shm/*|/var/tmp/*|/run/shm/*) et=1;; esac
      case "$xe" in /tmp/*|/dev/shm/*|/var/tmp/*|/run/shm/*) et=1;; esac
      [ -z "$et" ] && { EV_SCORE=$((EV_SCORE-4)); EV_REASONS="${EV_REASONS/ TEMP-PATH/}"; }
    ;; esac
    # inline interpreter code is COMMON (cloud-init, ansible) → context only, promotes with a payload
    echo "$cmd" | grep -qiE "(^|/)($INTERP)[[:space:]]+-[ceE]([[:space:]]|')" && ev 2 INLINE-INTERP
    # GTFObins-style live shell escapes
    echo "$cmd" | grep -qiE 'find[[:space:]].*-exec[[:space:]]+(/bin/)?(ba|da)?sh|awk[[:space:]].*BEGIN[[:space:]]*\{[^}]*system|tar[[:space:]].*--checkpoint-action|xargs[[:space:]][^|]*(ba)?sh[[:space:]]*$|vim?[[:space:]].*-c[[:space:]]*.?:!' && ev 3 GTFOBIN-ESCAPE
    finish_item argv "pid $pid ($comm)" "/proc/$pid/cmdline" "$cmd"
  done
}

module_hidden(){
  sect "HIDDEN ARTIFACTS — cross-view diffs (the box lying to itself)"
  local d diff
  # 1. hidden PIDs: present in /proc but absent from ps
  if command -v ps >/dev/null 2>&1; then
    diff=$(comm -23 \
      <(for d in /proc/[0-9]*; do echo "${d#/proc/}"; done | sort) \
      <(ps -e -o pid= 2>/dev/null | tr -d ' ' | sort) 2>/dev/null)
    while IFS= read -r d; do [ -z "$d" ] && continue
      [ -d "/proc/$d" ] || continue
      queue_abs NOTABLE hidden "pid $d ($(p_comm "$d"))" "/proc/$d vs ps" "HIDDEN-PID — in /proc but not in ps (process hiding; re-run to rule out a start/exit race)"
    done < <(printf '%s\n' "$diff")
  fi
  # 2. hidden listening ports: in /proc/net but not reported by ss
  if command -v ss >/dev/null 2>&1; then
    diff=$(comm -23 \
      <(awk 'NR>1 && $4=="0A"{split($2,a,":"); print a[2]}' /proc/net/tcp /proc/net/tcp6 2>/dev/null | while read -r hp; do printf '%d\n' "0x$hp" 2>/dev/null; done | sort -u) \
      <(ss -tlnH 2>/dev/null | awk '{n=split($4,a,":"); print a[n]}' | sort -u) 2>/dev/null)
    while IFS= read -r d; do [ -z "$d" ] && continue
      queue_abs NOTABLE hidden "tcp port $d" "/proc/net/tcp vs ss" "HIDDEN-PORT — a listening port in /proc/net that ss does not report (ss/rootkit hook; verify manually)"
    done < <(printf '%s\n' "$diff")
  fi
  # 3. hidden kernel modules: in /proc/modules but not lsmod
  if command -v lsmod >/dev/null 2>&1; then
    diff=$(comm -13 \
      <(lsmod 2>/dev/null | awk 'NR>1{print $1}' | sort -u) \
      <(awk '{print $1}' /proc/modules 2>/dev/null | sort -u) 2>/dev/null)
    [ -n "$diff" ] && queue_abs HIGH hidden "modules" "/proc/modules vs lsmod" "HIDDEN-MODULE — loaded module(s) absent from lsmod (self-hiding LKM): $(echo "$diff" | tr '\n' ' ')"
  fi
}

module_ebpf(){
  sect "eBPF / TRACING HOOKS"
  local progs hookn known f n
  if command -v bpftool >/dev/null 2>&1; then
    progs=$(bpftool prog show 2>/dev/null)
    hookn=$(printf '%s\n' "$progs" | grep -icE 'kprobe|kretprobe|fentry|fexit|lsm|raw_tracepoint|tracepoint')
    inv_head "loaded BPF programs"
    inv "$(printf '%s\n' "$progs" | grep -cE '^[0-9]+:') program(s); $hookn use kernel-hooking attach types"
    if [ "${hookn:-0}" -gt 0 ]; then
      known=""
      if command -v pgrep >/dev/null 2>&1; then known=$(pgrep -x 'falco|cilium-agent|datadog-agent|bpftrace|tetragon|sysdig|kubearmor|pixie-agent' 2>/dev/null); fi
      [ -z "$known" ] && queue_abs NOTABLE ebpf "bpf-hooking" "bpftool prog show" "BPF-HOOKING-NO-AGENT — $hookn kprobe/fentry/lsm BPF program(s) loaded but no known BPF security/observability agent is running (identify the loader)"
    fi
  else
    inv "(bpftool not present — install linux-tools/bpftool for BPF visibility)"
  fi
  # registered kprobes / dynamic ftrace hooks
  for f in /sys/kernel/debug/kprobes/list /sys/kernel/debug/tracing/kprobe_events /sys/kernel/tracing/kprobe_events; do
    [ -r "$f" ] || continue
    n=$(grep -c . "$f" 2>/dev/null); [ "${n:-0}" -gt 0 ] && inv "$f: $n active hook(s)"
  done
}

module_nsmask(){
  sect "NAMESPACE / BIND-MOUNT MASKING"
  local line mp src allow any=""
  allow='^(/etc/hostname|/etc/hosts|/etc/resolv.conf|/etc/machine-id|/etc/localtime|/etc/timezone|/etc/nsswitch.conf|/etc/hostid)$'
  # a filesystem mounted OVER an individual system FILE = classic hide-a-file (bind-mount masking)
  if [ -r /proc/1/mountinfo ]; then
    while IFS= read -r line; do
      mp=$(echo "$line" | awk '{print $5}'); src=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="-"){print $(i+2); exit}}')
      case "$mp" in
        /usr/*|/bin/*|/sbin/*|/lib*|/etc/*|/opt/*|/boot/*)
          echo "$mp" | grep -qE "$allow" && continue
          [ -f "$mp" ] && { any=1; queue_abs HIGH nsmask "mount over $mp" "$mp" "BIND-OVER-FILE — a filesystem (${src:-?}) is mounted over the system file $mp (hide-a-file / binary-swap masking)"; };;
      esac
    done < /proc/1/mountinfo
  fi
  [ -z "$any" ] && inv_head "bind-mounts over system files" && inv_none
}

module_timestomp(){
  sect "TIMESTOMP INDICATORS (unowned files)"
  local dirs d f m b ns hit s yts any=""
  dirs="/tmp /var/tmp /dev/shm /var/www /srv/www /srv/http /root"
  [ -n "$DEEP" ] && dirs="$dirs /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin /etc"
  for d in $dirs; do
    [ -d "$d" ] || continue
    while IFS= read -r f; do
      [ -f "$f" ] || continue
      # ONE stat per file (birth · mtime · mtime-with-ns) instead of three forks.
      s=$(stat -c '%W|%Y|%y' "$f" 2>/dev/null) || continue
      b=${s%%|*}; s=${s#*|}; m=${s%%|*}; yts=${s#*|}
      ns=$(printf '%s' "$yts" | sed -nE 's/.*\.([0-9]+).*/\1/p')
      case "$b" in ''|*[!0-9]*) b=0;; esac
      # Decide the cheap stat-only signal FIRST. A file is a finding iff (unowned AND signal), so testing
      # the signal before ownership does not change the result — but it keeps the expensive per-file
      # `dpkg -S` off the thousands of clean files in /usr/bin, /etc, … (the old owned-first order turned
      # --deep into an hours-long dpkg storm). We query ownership ONLY for files that already trip a signal.
      hit=""
      if   [ "$b" -gt 0 ] && [ -n "$m" ] && [ "$b" -gt "$m" ]; then hit=birth
      elif [ "$ns" = "000000000" ];                             then hit=zerons
      fi
      [ -z "$hit" ] && continue
      if [ -n "$PKGMGR" ]; then pkg_owns "$f" && continue; fi   # packaged files carry preserved/backdated or tar-zeroed-ns mtimes
      if [ "$hit" = birth ]; then
        any=1; queue_abs NOTABLE timestomp "$f" "$f" "BIRTH-AFTER-MTIME — created $(date -u -d "@$b" '+%F %T' 2>/dev/null) but mtime is older $(date -u -d "@$m" '+%F %T' 2>/dev/null) (mtime was set backwards)"
      else
        ev_reset; ev 2 ZERO-NS-MTIME; is_recent "$f" && ev 2 RECENT
        finish_item timestomp "$f" "$f" "unowned file with a zeroed-nanosecond mtime (touch -d signature)"; any=1
      fi
    done < <(find "$d" -xdev -type f 2>/dev/null)
  done
  [ -z "$any" ] && inv_head "timestomp" && inv "(none — no birth-after-mtime or zeroed-ns unowned files in scope)"
}

module_clustering(){
  if [ -z "$WINDOW_SET" ]; then
    sect "INSTALL-EVENT CLUSTERING (skipped — needs --since/--days)"; return
  fi
  sect "INSTALL-EVENT CLUSTERING — many files sharing a tight mtime window"
  local since dirs d
  since=${SINCE_EPOCH:-$((NOW-${RECENT_DAYS:-14}*86400))}
  dirs="/etc /usr/local /opt /var/www /srv /root /home /tmp /var/tmp /usr/bin /usr/sbin"
  [ -n "$DEEP" ] && dirs="$dirs /usr/lib /lib"
  # bucket window-modified files into 5-minute bins; a bin with many files across >=2 top dirs = an install.
  # mawk-safe (no strftime / no sub() backrefs); the bucket time is formatted by the shell below.
  { for d in $dirs; do [ -d "$d" ] && find "$d" -xdev -type f -newermt "@$since" -printf '%T@ %p\n' 2>/dev/null; done; } \
    | awk '
        { b=int($1/300); n=split($2,pp,"/"); td="/" pp[2]; if(n>=3) td=td "/" pp[3];
          cnt[b]++; key=b SUBSEP td; if(!(key in seen)){seen[key]=1; nd[b]++};
          if(cnt[b]<=3) ex[b]=ex[b] "\n     " $2 }
        END{ for(b in cnt) if(cnt[b]>=4 && nd[b]>=2) printf "%d\t%d\t%d\t%s\n", b*300, cnt[b], nd[b], ex[b] }' \
    | sort -rn | while IFS="$(printf '\t')" read -r t c nd ex; do
        queue_abs NOTABLE clustering "install-event @ $(date -u -d "@$t" '+%F %H:%M' 2>/dev/null)" "$c files across $nd dirs in one 5-min window" "INSTALL-EVENT — $c files modified together across $nd directories (automated drop, not a human edit); sample:${ex}"
      done
}

module_loggaps(){
  sect "LOG / AUDIT GAP ANALYSIS (defense evasion)"
  local h f
  # auditd installed but not running = audit trail gap
  if command -v auditctl >/dev/null 2>&1 && ! { pidof auditd >/dev/null 2>&1 || pgrep -x auditd >/dev/null 2>&1; }; then
    queue_abs NOTABLE loggaps "auditd" "systemd/service state" "AUDITD-STOPPED — auditd is installed but not running (audit trail gap during the incident)"
  fi
  # wiped/zeroed login + system logs while the box has uptime
  for f in /var/log/wtmp /var/log/btmp /var/log/lastlog /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages; do
    [ -e "$f" ] || continue
    if [ -L "$f" ]; then
      queue_abs NOTABLE loggaps "$(basename "$f")" "$f" "LOG-SYMLINK — $f is a symlink (→ $(readlink "$f")) — redirected/void logging"; continue
    fi
    # btmp records ONLY failed logins → empty is the normal quiet-host state (not evidence on its own).
    # So flag empty btmp only inside an incident window (analyst investigating a timeframe wants to know
    # it was truncated). wtmp/lastlog/auth/secure/syslog/messages ARE continuously written on a live host,
    # so an empty one there = wiped, always worth flagging.
    [ "$(basename "$f")" = btmp ] && [ -z "$WINDOW_SET" ] && continue
    [ -s "$f" ] || queue_abs NOTABLE loggaps "$(basename "$f")" "$f" "ZEROED-LOG — $f exists but is empty on a running host (log wiping / truncation)"
  done
  # journald not persisting
  if [ -d /etc/systemd/journald.conf.d ] || [ -f /etc/systemd/journald.conf ]; then
    grep -rhiE '^[[:space:]]*Storage[[:space:]]*=[[:space:]]*(none|volatile)' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null | grep -qi . && \
      queue_abs NOTABLE loggaps "journald" "/etc/systemd/journald.conf" "JOURNALD-NOT-PERSISTENT — Storage=none/volatile (journal is not written to disk — evidence loss)"
  fi
  # per-user history evasion
  inv_head "per-user history state"
  while IFS= read -r h; do
    for f in "$h/.bashrc" "$h/.bash_profile" "$h/.profile" "$h/.zshrc" "$h/.zshenv"; do
      [ -f "$f" ] || continue
      grep -qiE 'HISTFILE=/dev/null|unset[[:space:]]+HISTFILE|HISTSIZE=0|HISTFILESIZE=0|history[[:space:]]+-c|set[[:space:]]+\+o[[:space:]]+history' "$f" 2>/dev/null && \
        queue_abs NOTABLE loggaps "$(basename "$h"):$(basename "$f")" "$f" "HISTORY-EVASION — shell init disables command history ($(grep -iE 'HISTFILE|HISTSIZE|history -c|\+o history' "$f" 2>/dev/null | head -1 | sed 's/^[[:space:]]*//'))"
    done
    f="$h/.bash_history"
    if [ -L "$f" ]; then queue_abs NOTABLE loggaps "$(basename "$h"):.bash_history" "$f" "HISTORY-SINK — ~/.bash_history is a symlink → $(readlink "$f") (history discarded)"
    elif [ -f "$f" ] && [ ! -s "$f" ]; then inv "$(basename "$h"): empty ~/.bash_history"; fi
  done < <(user_homes)
}

module_elf(){
  sect "ELF ANOMALIES — setuid interpreters + packed/RWX/static (unowned)"
  local d f base rl reason seen=""
  # setuid interpreters/shells anywhere on the root fs = a privilege-escalation backdoor
  for d in /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin /tmp /var/tmp /dev/shm /home /opt; do
    [ -d "$d" ] || continue
    while IFS= read -r f; do
      [ -f "$f" ] || continue; base=$(basename "$f")
      echo "$base" | grep -qE "^($SHELLS|$INTERP|nc|ncat|socat|awk|find|env|vim?|tclsh|expect)$" && \
        queue_abs HIGH elf "setuid $f" "$f" "SETUID-INTERP — a setuid-root interpreter/shell ($base) = instant privilege-escalation backdoor"
    done < <(find "$d" -xdev -type f -perm -4000 2>/dev/null)
  done
  # ELF content anomalies on UNOWNED running binaries (bounded, deduped)
  command -v readelf >/dev/null 2>&1 || { inv "(readelf not present — ELF content checks skipped)"; return; }
  local p pid exe real
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}; exe=$(p_exe "$pid"); [ -z "$exe" ] && continue
    real=${exe% (deleted)}
    case "$real" in /*) : ;; *) continue;; esac
    [ -f "$real" ] || continue        # must be a regular file — a namespaced/container proc whose exe resolves to '/' (a dir) must NOT reach the readelf checks below
    case "
$seen
" in *"
$real
"*) continue;; esac
    seen="$seen
$real"
    # only judge unowned binaries — packaged Go/static daemons are legit and would flood otherwise
    if [ -n "$PKGMGR" ]; then pkg_owns "$real"; [ $? -eq 0 ] && continue; fi
    case "$real" in /usr/lib/*|/lib/*|/usr/lib64/*|/lib64/*|/snap/*) continue;; esac
    # must be a parseable ELF — otherwise a readelf FAILURE below would masquerade as "static-linked".
    readelf -hW "$real" 2>/dev/null | grep -q 'Class:' || continue
    reason=""
    grep -qa 'UPX!' "$real" 2>/dev/null && reason="$reason packed(UPX)"
    readelf -lW "$real" 2>/dev/null | grep -E 'LOAD' | grep -qE 'RWE' && reason="$reason RWX-segment"
    rl=$(readelf -lW "$real" 2>/dev/null | sed -nE 's/.*interpreter:[[:space:]]*([^]]*)\]/\1/p')
    case "$rl" in */ld-musl*) reason="$reason musl-interp";; esac
    readelf -dW "$real" 2>/dev/null | grep -q 'NEEDED' || reason="$reason static-linked"
    [ -n "$reason" ] && queue_abs NOTABLE elf "$real (pid $pid)" "$real" "ELF-ANOMALY — unowned running binary:$reason"
  done
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
    --json) JSON=1;;
    -h|--help) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 2;;
  esac
  shift
done

all_mods="lineage netshell masquerade argv hidden ebpf nsmask timestomp clustering loggaps elf"
[ -n "$MODULES" ] && run="${MODULES//,/ }" || run="$all_mods"

# ================= run =================
detect_env
if [ -z "$JSON" ]; then
  echo "hunt_intrusion.sh  v${VERSION}    author: ${AUTHOR}"
  echo "Ran at   : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "Command  : hunt_intrusion.sh ${RAW_ARGS:-<none>}"
  [ "$(id -u)" -ne 0 ] && printf '!! not root — most /proc/*/exe, /proc/*/fd, maps, mountinfo and other users are unreadable. Re-run with sudo.\n'
fi

triage

for m in $run; do
  case "$m" in
    lineage) module_lineage;;
    netshell) module_netshell;;
    masquerade) module_masquerade;;
    argv) module_argv;;
    hidden) module_hidden;;
    ebpf) module_ebpf;;
    nsmask) module_nsmask;;
    timestomp) module_timestomp;;
    clustering) module_clustering;;
    loggaps) module_loggaps;;
    elf) module_elf;;
    *) echo "unknown module: $m" >&2;;
  esac
done

if [ -z "$JSON" ] && [ -n "$SHOW_ANOM" ]; then
  printf '\n===== ANOMALIES (evidence-backed queue) =====\n'
  if [ -z "$ANOM_HIGH$ANOM_NOTABLE" ]; then
    printf '   none — no live-intrusion / hiding / evasion signals fired.\n'
  else
    [ -n "$ANOM_HIGH" ] && printf '%s\n' "$ANOM_HIGH"
    [ "$MIN_SEV" -le 2 ] && [ -n "$ANOM_NOTABLE" ] && printf '%s\n' "$ANOM_NOTABLE"
  fi
  printf '\n==== %s HIGH · %s NOTABLE  (evidence-backed; behaviour & hard tells, not mechanisms) ====\n' "$HI" "$NO"
  [ "$(id -u)" -ne 0 ] && printf '   NOTE: ran without root — coverage was PARTIAL (/proc exe/fd/maps/mountinfo unreadable). A low count here is NOT a clean bill of health; re-run with sudo.\n'
fi
