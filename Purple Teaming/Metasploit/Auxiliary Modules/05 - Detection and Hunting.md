# Metasploit — Auxiliary Modules — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target — By Category](#hunting-on-target--by-category)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Network-Layer Hunting](#network-layer-hunting)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

`auxiliary/*` doesn't expose module-specific evasion flags the way `psexec.py` does (`-file`, `-service-name`) — the operator-controllable variables that actually change this class's footprint are **`THREADS`/pacing** (how fast/loud a sweep runs), **credential-list shape** (a full wordlist "brute force" vs. one or two passwords across many accounts — a "spray," T1110.001 vs. T1110.003), **`SHOST`/source spoofing** (`dos/*`, `spoof/*` only), and **`ACTION`/module choice** for multi-behavior modules. Ranked by which survive those variables, strongest first — this table is written for the credential-validation scanner sub-category specifically (`smb_login`/`ssh_login`), since it's this page's primary worked example and the most heavily operator-tunable:

| Rank | Signal | Survives `THREADS`/pacing tuning? | Survives spray-vs-brute credential shaping? | Survives `STOP_ON_SUCCESS`/`ABORT_ON_LOCKOUT`? |
|---|---|---|---|---|
| 1 (strongest) | **Total failed-auth count from one source IP against many distinct accounts, over any observation window** | ✅ Yes — slowing `THREADS`/pacing spreads the same total volume over more time, it doesn't reduce it | ✅ Yes — a spray still generates one failure per account tried, just with fewer unique passwords | ✅ Yes — these options change *when the run stops*, not whether the attempts that did happen get logged |
| 2 | **One source IP touching an unusually wide fan-out of distinct destination hosts/accounts** | ✅ Yes — the fan-out shape is inherent to running against `RHOSTS`/a wordlist at all | ✅ Yes | ✅ Yes |
| 3 | **Burst timing / rate** (many auth events in a tight window) | ⚠️ **Weakens, doesn't disappear** — low `THREADS`, `BRUTEFORCE_SPEED`, or manual `DELAY`/`JITTER` (where the module exposes it, e.g. `portscan/tcp`) turns a sharp burst into a slow drip, which defeats a naive rate-threshold alert but not a wider-window aggregation | N/A | N/A |
| 4 | **Exact password(s) used, if recovered from a wordlist/history** | N/A | ❌ **No** — this is entirely operator-chosen and unpredictable without recovering the actual `PASS_FILE`/`USER_FILE` content | N/A |
| 5 (weakest) | **Which specific module/`ACTION` ran** | N/A | N/A | N/A — protocol-level wire traffic for `smb_login` vs. any other SMB-auth tool (NetExec, Hydra, a hand-rolled script) is not meaningfully distinguishable; the module identity itself is not a reliable network-level signal |

**One class-wide caveat, not in the table above:** because `auxiliary/*` covers six structurally different sub-categories, this priority ordering applies cleanly only to the credential-validation case. For `dos/*`/`spoof/*`, source-IP spoofing (`SHOST`, randomized by default in `synflood`) defeats source-IP-based correlation entirely — build those hunts on the packet-crafting fingerprint and protocol-anomaly signals in `04 - Target Evidence.md` instead, not on "who sent it." For `gather/*` external-OSINT modules, there is nothing to hunt target-side at all — see the negative-evidence callout there.

## Hunting on Source

```bash
# Auxiliary-module invocations in general — the module class, ACTION selections,
# and THREADS/pacing values an operator configured
grep -iE "use auxiliary|set RHOSTS|set THREADS|set ACTION|^run$" ~/.msf4/history 2>/dev/null

# Credential-list files referenced by scanner/admin modules — recovering these
# shows exactly what was tried, not just that something was tried
grep -iE "set (USER_FILE|PASS_FILE|USERPASS_FILE|USERNAME|PASSWORD)" ~/.msf4/history 2>/dev/null

# dos/* and spoof/* modules require elevated privileges for raw-socket access —
# an msfconsole/ruby process running as root is a signal in itself for this subclass
ps aux | grep -iE "msfconsole|ruby.*metasploit" | grep -v grep | awk '$1=="root"'

# Live thread/connection footprint proportional to a scanner module's THREADS setting
ss -tnp | grep -i msfconsole | wc -l

# Resource scripts naming a specific auxiliary module + option set staged for reuse
find / -iname "*.rc" -exec grep -l "auxiliary/scanner\|auxiliary/admin\|auxiliary/dos\|auxiliary/gather\|auxiliary/fuzzers\|auxiliary/spoof" {} \; 2>/dev/null

# Workspace database export — vulns/creds/loot/services tables are structured,
# timestamped evidence of exactly which auxiliary modules produced results
msfconsole -x "workspace; db_export -f xml /tmp/msf_export.xml; exit"
```

## Hunting on Target — By Category

### Scanner-class — service/port discovery

```powershell
# Windows host firewall connection logging must be explicitly enabled to catch this —
# not on by default. If enabled, look for a burst of distinct-port connections
# from one source IP in a short window.
Get-Content C:\Windows\System32\LogFiles\Firewall\pfirewall.log -Tail 5000 |
  Select-String -Pattern 'ALLOW|DROP' | Group-Object { ($_ -split '\s+')[3] } |
  Where-Object Count -gt 20
```

### Scanner-class — credential validation (the primary worked example)

```powershell
# Failed-logon burst from one source IP against many distinct accounts —
# the single strongest signal for this entire module class (see priority table above)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
  Group-Object { $_.Properties[19].Value } |     # source IP field
  Where-Object Count -gt 10 |
  Select-Object Count, Name

# Distinct accounts targeted per source IP — the fan-out signature that
# separates a spray/scan from routine password-typo noise
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
  Group-Object { $_.Properties[19].Value } |
  ForEach-Object {
    [PSCustomObject]@{
      SourceIP        = $_.Name
      FailedAttempts  = $_.Count
      DistinctAccounts = ($_.Group | ForEach-Object { $_.Properties[5].Value } | Sort-Object -Unique).Count
    }
  } | Where-Object DistinctAccounts -gt 5

# Account lockouts correlated to the same source IP / time window — smb_login's
# ABORT_ON_LOCKOUT is meant to prevent repeated triggers, but the first one still fires
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740}
```

```bash
# Linux SSH target — same fan-out logic against auth.log / journal
journalctl -u sshd --since "-1 hour" | grep "Failed password" | \
  awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20
```

### Admin-class — authenticated enumeration

```sql
-- If SQL Server login auditing is set to "Both failed and successful logins"
-- (not the default), the Application Event Log records each connection.
-- The distinctive signal is the *query sequence*, not any single query:
-- sys.syslogins -> sysadmin filter -> sp_configure walk -> xp_regread against
-- the service account key, all in one session -- verified from mssql_enum's
-- own source in 02 - Hands-On Use Cases.md.
```

```powershell
# Application log entries from the SQL Server source, if login auditing is enabled
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='MSSQLSERVER'} |
  Where-Object { $_.Message -match 'Login (succeeded|failed)' }
```

### DoS-class

```powershell
# Live half-open-connection state during an active flood
netstat -n | Select-String "SYN_RECEIVED" | Measure-Object | Select-Object Count
```

```bash
# Linux equivalent
ss -tn state syn-recv | wc -l
```

### Fuzzer-class

Cross-link `../Exploit Modules/05 - Detection and Hunting.md`'s crash-hunting queries (System 1001/41, WER report paths) — a successful fuzz hit produces the same crash-artifact class documented there. The fuzzer-specific angle is upstream of the crash: application/service logs showing malformed commands with format-string tokens (`%s`, `%n`, `%x`) or path-traversal sequences as command arguments, against one target, over an extended single-session window.

### Spoof-class — ARP poisoning

```bash
# Duplicate/flip-flopping MAC-to-IP bindings for the gateway or other
# sensitive IPs -- the core observable for ARP cache poisoning
arpwatch   # or: arp-scan / any switch's DAI-violation log, if configured
```

```
# Zeek arp.log, if the sensor is positioned on the affected broadcast segment
zeek-cut ts src_mac dst_mac operation < arp.log | grep -i reply
```

## Fleet-Wide Sweep

```powershell
# Domain-wide spray/scan detection -- aggregate 4625 events across every
# domain controller, not just one host, since a scanner module's RHOSTS
# range typically spans many members of the same domain
$DCs = (Get-ADDomainController -Filter *).HostName

$results = Invoke-Command -ComputerName $DCs -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
    Group-Object { $_.Properties[19].Value } |
    Where-Object Count -gt 10 |
    Select-Object Name, Count
} -ErrorAction SilentlyContinue

$results | Sort-Object Count -Descending | Select-Object -First 20
```

```powershell
# Fleet-wide account-lockout correlation -- a cluster of 4740 events in a tight
# window across many accounts is a strong indicator of an active spray, not
# isolated user error
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740; StartTime=(Get-Date).AddHours(-24)} |
  Group-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') } |
  Sort-Object Count -Descending | Select-Object -First 10
```

## Network-Layer Hunting

```
# Zeek's built-in scan-detection framework catches the portscan/tcp / smb_version
# fan-out pattern in most default deployments
zeek-cut ts note src dst p < notice.log | grep -i "Scan::"

# The inbound-connection-burst-from-one-source pattern generalizes across every
# category in this page -- scanner sweeps, credential sprays, floods, and
# fuzzer sessions all show up as an anomalous conn.log fan-out or single-target
# high-volume pattern, even before any host-based log is consulted
zeek-cut ts id.orig_h id.resp_h id.resp_p < conn.log | \
  awk '{print $2}' | sort | uniq -c | sort -rn | head -20   # busiest source IPs
```

## Remediation

**Capture evidence first** — export the Metasploit workspace DB if this is the operator side (`03 - Source Evidence.md`), or pull the relevant Security/Application log window, a network capture, and (for DoS) live connection-table state if this is the target side, before remediating:

```powershell
# Credential-spray response: reset any account that authenticated successfully
# during the identified window, and review its actual access before assuming
# a spray-recovered credential wasn't used for anything further
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$sprayStart; EndTime=$sprayEnd} |
  Where-Object { $_.Properties[8].Value -eq 3 }   # Logon Type 3 (network)
```

```powershell
# DoS in progress: identify and block the flood source at the firewall/upstream --
# note that a spoofed SHOST (dos/tcp/synflood's default behavior, see
# 04 - Target Evidence.md) may make source-IP blocking ineffective; rate-limiting
# or upstream scrubbing is the more durable response for a spoofed flood
```

```
# ARP poisoning in progress: flush affected ARP caches once the poisoning source
# is confirmed stopped, and enable Dynamic ARP Inspection / port security on
# affected switches going forward if not already configured
arp -d *          # Windows -- flush the local ARP cache after remediation
```

If a credential-validation sweep recovered a working credential and it was subsequently used for lateral movement (an `Admin`-level SMB login feeding a `psexec`-style follow-on, per `02 - Hands-On Use Cases.md`), treat this as a full compromise chain, not just exposed credentials — pivot to `../../Impacket/psexec/05 - Detection and Hunting.md` or `../Metasploit PsExec (exploit-windows-smb-psexec)/05 - Detection and Hunting.md` for what typically happens next.
