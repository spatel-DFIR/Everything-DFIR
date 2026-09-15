# Metasploit — msfconsole — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Network-Layer Hunting](#network-layer-hunting)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

msfconsole doesn't expose evasion flags the way a single-purpose tool like `psexec.py` does (no equivalent of `-file` or `-service-name`); what it exposes instead is **operator OPSEC discipline** — whether logging was left off (the default), whether the history file was relocated (`-H`), whether the database was disabled (`-n`), and which payload transport was chosen. Rank hunts by what survives those choices, strongest first:

| Rank | Signal | Survives default (no) logging? | Survives `-H` (relocated history)? | Survives `-n` (no database)? |
|---|---|---|---|---|
| 1 (strongest) | Target-side network flow to the handler (NetFlow/Zeek `conn.log`) | ✅ Yes — independent of anything on the operator box | ✅ Yes | ✅ Yes |
| 2 | OS-level `auditd` execve records for `msfconsole`/`ruby` on the operator box | ✅ Yes — kernel-level, independent of application logging | ✅ Yes | ✅ Yes |
| 3 | `~/.msf4/msfconsole.rc` / other resource scripts on disk | ✅ Yes — a file the operator saved deliberately, not a log | ✅ Yes — unrelated to the history-file path | ✅ Yes |
| 4 | `~/.msf4/config` (from `save`) | ✅ Yes, if `save` was ever run | ✅ Yes | ✅ Yes |
| 5 | `~/.msf4/history` | ❌ N/A — always written unless leading-space-prefixed per line | ❌ **No** — `-H` redirects it entirely | ✅ Yes — history is independent of the database connection |
| 6 (weakest) | Framework database (`hosts`/`services`/`creds`/`loot`/`vulns`/`sessions -l`) | ✅ Yes, if connected | ✅ Yes | ❌ **No** — `-n` disables it outright for the whole session |

**Build hunts on ranks 1-2 as primary detections — they're rooted in mechanics the operator can't suppress without abandoning the tool's core function (a listener must still receive a network connection; a process must still execute). Treat ranks 3-6 as high-confidence enrichment once a candidate operator box or target host is already identified, not sole detection logic — a disciplined operator can leave very little in `~/.msf4/` at all.**

## Hunting on Source

Operator-side hunting only applies in an insider-threat/compromised-infrastructure scenario — legitimate access to the box `msfconsole` ran from.

```bash
# Framework command history — the richest single artifact if present and at the default path
cat ~/.msf4/history 2>/dev/null | grep -iE "use exploit|use auxiliary|use post|multi/handler|set PAYLOAD|set LHOST"

# Auto-run startup script and any saved datastore snapshot
cat ~/.msf4/msfconsole.rc 2>/dev/null
cat ~/.msf4/config 2>/dev/null

# Resource scripts and persisted-job records anywhere on disk
find / -iname "*.rc" -newer /etc/hostname 2>/dev/null | xargs grep -l "msfconsole\|exploit\|payload" 2>/dev/null
cat ~/.msf4/persist 2>/dev/null

# Live handler / session state
ps aux | grep -iE "msfconsole|msfrpcd"
ss -tlnp | grep -E ':4444|:8443'    # verify against configured LPORT, don't assume defaults
ss -tnp  | grep ESTAB

# Loot directory — direct manifest of what was harvested and when
ls -la ~/.msf4/loot/ 2>/dev/null

# Database query, if PostgreSQL is reachable/imaged
# (run from a psql shell against the imaged ~/.msf4/db/ data directory)
#   SELECT * FROM workspaces; SELECT * FROM hosts; SELECT * FROM creds; SELECT * FROM sessions;

# auditd — survives history-file deletion or relocation, since it's kernel-level
ausearch -x msfconsole 2>/dev/null
ausearch -x ruby 2>/dev/null

# Shell history for the outer invocation — especially valuable if -x was used,
# since the entire attack chain may be visible in one line
grep -iE "msfconsole" ~/.bash_history ~/.zsh_history 2>/dev/null
```
If `~/.msf4/history` is missing or empty but `~/.msf4/config`, `~/.msf4/loot/`, or the database still show activity, suspect `-H` (relocated history file) or a deliberate `history -c` before rank-1/2 signals rule out a wholesale wipe — check the database and loot directory first, since they're harder for an operator to selectively edit than a single text file.

## Hunting on Target

PowerShell-first, per this module's convention — with the caveat that msfconsole itself has no consistent target-side host artifact (see `04 - Target Evidence.md`). What's huntable *on the target* is the handler's network behavior and whatever the delivered payload's own signature is.

```powershell
# 1. Outbound connections matching a reverse_tcp long-hold pattern or a
#    reverse_http(s) periodic-polling pattern — coarse without a known
#    LPORT, tune to the environment's baseline
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} |
  Where-Object { $_.Message -match 'DestinationPort: (4444|8443|443|80)\b' }

# 2. If the delivered payload was Meterpreter, the full memory/process/pipe
#    hunt set lives in ../Meterpreter/05 - Detection and Hunting.md — not
#    re-derived here. Pivot there once a candidate session is suspected.

# 3. If delivery was via an exploit module, pivot to that module category's
#    own hunt guidance:
#      ../Exploit Modules/05 - Detection and Hunting.md
#      ../Metasploit PsExec (exploit-windows-smb-psexec)/05 - Detection and Hunting.md
```
There is deliberately no msfconsole-specific Event ID or Sysmon signature table here — unlike `psexec.py`'s Event 7045/named-pipe fingerprint, msfconsole's target-side identity is entirely a function of which of thousands of modules ran, and duplicating every module category's hunt guidance on this page would drift out of sync with those pages. Start with the network-layer signal above, then pivot to the payload-specific or module-category-specific page once a candidate host is identified.

## Fleet-Wide Sweep

```powershell
# Run from a hunting workstation with rights across the estate — catches a
# coordinated multi-target handler-catch pattern (see 02 - Hands-On Use Cases.md's
# "Fleet-Wide Targeting" scenario), where the real signal is many hosts making
# similar outbound connections in a tight time window
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'DestinationPort: (4444|8443|443)\b' } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated
} -ErrorAction SilentlyContinue

# Group by destination/time window to spot a coordinated callback burst
# vs. isolated single-host activity
$results | Group-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') } |
  Sort-Object Count -Descending | Select-Object -First 10 Count, Name

$results | Export-Csv -Path .\msfconsole_handler_sweep.csv -NoTypeInformation
```
For the payload-residency half of a fleet sweep (confirming what's actually running once a candidate host is found), pair this with `../Meterpreter/05 - Detection and Hunting.md`'s fleet-wide guidance rather than duplicating it — this page's contribution is spotting the callback pattern across many hosts, not confirming payload identity on any single one.

## Network-Layer Hunting

For environments with a network sensor (Zeek, Suricata, etc.) — the most reliable visibility into `multi/handler` activity precisely because it requires no host-based logging on either side:

```
# Zeek: long-duration single connections consistent with reverse_tcp,
# to an external or otherwise-unexpected destination
zeek-cut ts id.orig_h id.resp_h id.resp_p duration < conn.log |
  awk '$5 > 300 { print }'   # tune the duration threshold to the environment

# Zeek: repeated short HTTP(S) requests to the same destination at a
# roughly consistent interval, consistent with reverse_http/reverse_https polling
zeek-cut ts id.orig_h id.resp_h host uri < http.log | sort | uniq -c | sort -rn

# Zeek: TLS handshakes with a self-signed or default Metasploit certificate
# fingerprint on reverse_https (weakest signal in this note — trivially
# defeated by a custom HandlerSSLCert, treat as enrichment only)
zeek-cut ts id.orig_h id.resp_h subject issuer < ssl.log | grep -i "metasploit\|localhost"
```

## Remediation

**Capture evidence first** — export the NetFlow/Zeek records for the handler's connection and, if a session is still live, image or dump the payload's process memory before touching anything on the target. If the payload was Meterpreter, follow `../Meterpreter/05 - Detection and Hunting.md`'s remediation guidance (identify the *current* host process via the migrate trail before killing anything).

```powershell
# On the target: identify and terminate the process the payload is running in —
# confirm which process first, per the payload-specific hunting guidance above
Stop-Process -Id <CurrentHostPID> -Force

# If delivery used a service-based mechanism (e.g. Metasploit's own psexec-style
# module), also remove that service — see the corresponding module category's
# Target Evidence/Detection page for the exact cleanup
```
On the operator side (insider-threat/compromised-infrastructure scenarios only): terminating the handler job (`jobs -k <id>`) or the `msfconsole` process itself stops further callbacks from being caught, but does **not** retroactively remove whatever the payload already did on any host that connected in before remediation started — treat the database's `hosts`/`services`/`sessions` tables as a checklist of every host that needs its own target-side remediation pass, not just the one under active investigation.
