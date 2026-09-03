# Metasploit — Meterpreter — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Extension-Specific Hunts](#extension-specific-hunts)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

Meterpreter exposes several operator-side variables that change its footprint: transport choice (`reverse_tcp`/`reverse_https`/`reverse_http`/`bind_tcp`), whether `migrate` is used, which `getsystem` technique fires, and whether the *delivery* payload was encoded (`msfvenom` encoders like `shikata_ga_nai`) to dodge static AV. Rank hunts by what survives those changes, strongest first — and note up front: **encoders only affect the delivered payload's bytes on disk/in the exploit buffer.** Once `metsrv.dll` is reflectively loaded and running, encoding has already done its job (or failed to); it has **zero effect** on any runtime memory, injection, or protocol signal below. Public research is blunt about this — by the mid-2020s, `shikata_ga_nai`-class encoders are signatured at the decoder-stub level and flagged by behavioral/EDR heuristics regardless of the specific encoding applied, so don't present encoder use as a reliable evasion technique in write-ups or in threat modeling; it primarily defeats naive static-signature AV, not modern EDR.

| Rank | Signal | Survives `migrate`? | Survives transport change? | Survives encoders? | Survives which `getsystem -t`? |
|---|---|---|---|---|---|
| 1 (strongest) | Sysmon 8 (CreateRemoteThread) + 10 (ProcessAccess) pair around an injection event | N/A — this **is** the migrate/token-dup event itself | ✅ Yes — unrelated to transport | ✅ Yes | Fires for `-t 3` (token duplication); also fires for `migrate` regardless of technique |
| 2 | Memory-forensics signature — private executable region with no backing file (`malfind`-class detection) | ✅ Yes — re-appears in whichever process Meterpreter currently occupies | ✅ Yes | ✅ Yes | N/A — this detects the payload's residency, not `getsystem` specifically |
| 3 | TLV protocol header shape on the wire (fixed-size XOR key/GUID/flag/length/type fields) | ✅ Yes — protocol-level, independent of process | ⚠️ Partial — present on `reverse_tcp`/`bind_tcp` in the clear; wrapped in TLS on `reverse_https`, so requires TLS interception/JA3-class fingerprinting instead of payload inspection. `reverse_http` sits in between — HTTP-visible but not TLS-wrapped | ✅ Yes | N/A |
| 4 | Transient service install (System 7045) from `getsystem` techniques 1/2 | ✅ Yes (independent of later migrate) | ✅ Yes | ✅ Yes | **Does not fire for `-t 3`** — an operator who forces token duplication skips this signal entirely |
| 5 (weakest) | Default JA3 hash / self-signed cert fingerprint on `reverse_https` | ✅ Yes | ❌ **No** — only applies to `reverse_https`; switching to `reverse_tcp`/`reverse_http`/`bind_tcp` removes it entirely, and a custom `HandlerSSLCert` defeats the cert-fingerprint half even on `reverse_https` | ✅ Yes | N/A |

**Build hunts on ranks 1-2 as primary detections — they're rooted in mechanics the tool can't avoid without abandoning core functionality (`migrate`, extension loading, reflective residency). Treat ranks 3-5 as high-confidence enrichment once a candidate host/session is already identified, not sole detection logic.**

## Hunting on Source

Operator-side hunting only applies in an insider-threat/compromised-infrastructure scenario — you have legitimate access to the box `msfconsole` ran from.

```bash
# Framework command history — the richest single artifact if present
cat ~/.msf4/history 2>/dev/null | grep -iE "meterpreter|migrate|getsystem|kiwi|incognito|extapi|lanattacks"

# Confirm a live handler or session
ps aux | grep -iE "msfconsole|msfrpcd"
ss -tlnp | grep -E ':4444|:8443|:443'    # verify against configured LPORT, don't assume defaults
ss -tnp  | grep ESTAB

# Loot directory — direct manifest of what was harvested and when
ls -la ~/.msf4/loot/ 2>/dev/null

# Database query, if PostgreSQL is reachable/imaged
# (run from a psql shell against the imaged ~/.msf4/db/ data directory)
#   SELECT * FROM hosts; SELECT * FROM creds; SELECT * FROM sessions;

# auditd — survives ~/.msf4/history deletion since it's kernel-level
ausearch -x msfconsole 2>/dev/null
ausearch -x ruby 2>/dev/null
```

## Hunting on Target

PowerShell-first, per this module's convention — with an honest caveat: the **rank-1/2 memory-forensics signals are not something native PowerShell can reliably surface at scale.** Detecting a reflectively-loaded, no-backing-file memory region requires VAD-walking tooling (Volatility, an EDR's own memory-scanning capability, or a dedicated tool like PE-sieve) — don't rely on `Get-Process`-based PowerShell alone for that half of the hunt; use it for the log/event-based signals below and lean on EDR/memory-forensics tooling for ranks 1-2.

```powershell
# 1. HIGHEST-CONFIDENCE (survives migrate, transport, and encoders):
#    Sysmon CreateRemoteThread + ProcessAccess pair — catches migrate AND
#    getsystem -t 3 token duplication
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=8,10} |
  Select-Object TimeCreated, Id,
    @{n='SourceImage';e={$_.Properties[4].Value}},
    @{n='TargetImage';e={$_.Properties[6].Value}},
    @{n='GrantedAccess';e={$_.Properties[10].Value}} |
  Where-Object { $_.GrantedAccess -match '0x1F3FFF|0x1FFFFF|0x1010|0x0040' }  # broad admin/write/thread-create access masks — tune per environment, false-positive prone alone

# 2. Transient service installs from getsystem techniques 1/2 — won't catch -t 3,
#    pair with #1 above for full getsystem coverage
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
  Select-Object TimeCreated,
    @{n='ServiceName';e={$_.Properties[0].Value}},
    @{n='ImagePath';e={$_.Properties[1].Value}},
    @{n='Account';e={$_.Properties[4].Value}} |
  Where-Object { $_.Account -eq 'LocalSystem' }

# 3. Sysmon Image/DLL Load ABSENCE check — a process making outbound C2-shaped
#    connections (see #4) with no corresponding unusual Image Load event is
#    consistent with reflective injection; this is a negative-evidence hunt,
#    correlate manually rather than scripting a single query for it

# 4. Outbound connections to non-standard ports with long-lived (reverse_tcp)
#    or periodic-polling (reverse_http/reverse_https) session behavior —
#    coarse, needs tuning per environment's normal traffic
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} |
  Where-Object { $_.Message -match 'DestinationPort: (4444|8443|443)\b' }

# 5. rundll32.exe launching a DLL with no on-disk provenance — the ONE
#    filesystem-visible getsystem variant (technique 2's dropper path)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'rundll32\.exe' -and $_.Message -notmatch 'System32|SysWOW64' }
```

## Extension-Specific Hunts

Narrower signals tied to individual extensions — treat these as enrichment once core Meterpreter residency is already suspected, not as a primary detection strategy on their own (an operator who never loads these extensions produces none of this).

```powershell
# sniffer: NIC promiscuous-mode toggle — abnormal on a workstation
Get-CimInstance -ClassName Win32_NetworkAdapter |
  Where-Object { $_.NetConnectionStatus -eq 2 } |
  Select-Object Name, NetConnectionID, Index
# Cross-reference against the adapter's promiscuous-mode state via
# EDR-native NIC telemetry — WMI alone doesn't directly expose that flag

# lanattacks: unexpected DHCP server activity from a host that isn't
# infrastructure — best hunted at the network layer (Zeek dhcp.log),
# but a host-side symptom is other endpoints picking up an unfamiliar
# default gateway/DNS server shortly after this host became active
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} |
  Where-Object { $_.Message -match 'DestinationPort: (67|68)\b' }

# webcam_snap / record_mic: camera/microphone hardware activation —
# correlate against the OS-level privacy/usage log
Get-WinEvent -LogName 'Microsoft-Windows-Sensor-Service/Operational' -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'camera|microphone' }
```

## Fleet-Wide Sweep

```powershell
# Run from a hunting workstation with rights across the estate. This catches
# the getsystem-driven service-install pattern (ranks 3-4 above) across many
# hosts — pair with EDR-native fleet queries for the memory-residency signal
# this PowerShell sweep structurally cannot reach.
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 50 -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[4].Value -eq 'LocalSystem' } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated,
      @{n='ServiceName';e={$_.Properties[0].Value}}, @{n='ImagePath';e={$_.Properties[1].Value}}
} -ErrorAction SilentlyContinue

# Group by time window to spot a coordinated multi-host getsystem push
# vs. isolated single-host privilege escalation
$results | Group-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') } |
  Sort-Object Count -Descending | Select-Object -First 10 Count, Name

$results | Export-Csv -Path .\meterpreter_getsystem_sweep.csv -NoTypeInformation
```
For the memory-residency signal (rank 1-2), a fleet sweep realistically means querying whatever EDR platform is deployed for its own reflective-injection/no-backing-file detections across the estate — this module doesn't re-derive vendor-specific EDR query syntax, which varies by product. For `lanattacks`' rogue-DHCP signal specifically, a fleet sweep is more effective from the **network** side (a single Zeek sensor watching the segment's `dhcp.log` for a second DHCP server) than a per-host PowerShell loop.

## Remediation

**Capture evidence first** — image or at minimum dump the memory region flagged by `malfind`-class tooling, and pull the Sysmon 8/10/7045 records, before killing anything. If `migrate` occurred, confirm the **current** host process (via the Sysmon 8/10 trail) before acting — killing the original delivery process after a migrate does nothing to the live session.

```powershell
# Identify and terminate the process Meterpreter currently occupies
# (confirm via the injection-event trail above — do NOT assume it's still
# the original delivery process)
Stop-Process -Id <CurrentHostPID> -Force

# If getsystem -t 2's dropper variant fired, remove the leftover DLL/service
$svc = "<ServiceNameFrom7045>"
Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
sc.exe delete $svc

# If a persistence module was run (see 02 - Hands-On Use Cases.md), remove
# its specific launcher separately — it's a distinct artifact from Meterpreter
# itself; see Windows/10 - Persistence Mechanisms/ for the general cleanup
# pattern for whichever mechanism (registry Run key, scheduled task, VBS) was used
```
Rotate any credentials recovered via `hashdump`/`kiwi`/`incognito` during the session — assume full compromise of anything the SYSTEM-context session had access to, since `getsystem` and `kiwi` together give an operator the same practical reach a defender would assume for any other SYSTEM-level credential-theft tool in this module. If `lanattacks`' rogue DHCP server was active, also check whether other hosts on the segment picked up a malicious lease (unexpected gateway/DNS) during the window it ran, and remediate those separately.
