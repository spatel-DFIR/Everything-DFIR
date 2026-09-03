# Veil-Evasion — Detection and Hunting

## Hunting Priority

Veil exposes real customization/evasion surface (10 payload languages, 8+ obfuscation modules, operator-controlled output naming, environmental-keying options). Ranked by which signals survive the most of that surface — and, uniquely for this tool, by how much a **five-plus-year-old, frozen codebase** shifts the ranking versus an actively-maintained evasion tool:

| Rank | Signal | Survives language/obfuscation-module choice? | Survives operator renaming/output-path changes? | Notes |
|---|---|---|---|---|
| 1 | Modern AV/EDR static + behavioral detection of stock Veil output | ✅ Largely yes | ✅ Yes | The defining fact of this page (see `04`) — five-plus years of accumulated vendor coverage against a frozen 2020-era toolset means this should be your **highest-confidence** signal against any non-hand-modified sample, an inversion of the usual "assume evasion works" posture |
| 2 | PyInstaller `_MEI*` self-extraction / entropy-based unpacking detection | ✅ Yes, for all Python-language payloads | ✅ Yes (directory name is random but the pattern/behavior is fixed) | Independently confirmed via published entropy-detection-tool benchmarks (99%+ recall); only applies to the Python-language + PyInstaller-compiler path, not other languages |
| 3 | In-process RWX memory allocation + thread creation | ✅ Yes — structural to every payload template regardless of language/obfuscation | ✅ Yes | Requires EDR API-hooking/behavioral telemetry, not default Sysmon config, to see reliably — see `04`'s note that Sysmon 8 (`CreateRemoteThread`) does **not** fire since execution is same-process |
| 4 | Metasploit payload-protocol network callback (JA3/JARM, staged-payload request/response shape) | ✅ Yes — inherited from msfvenom, independent of Veil's own obfuscation choices | ✅ Yes | Defeated only if the operator supplies non-Metasploit shellcode via `shellcode_inject` with a custom stager — uncommon in practice; apply `Metasploit/Meterpreter/`'s and `Metasploit/msfvenom/`'s own network-signature hunting directly |
| 5 | `hashes.txt` / output-directory artifacts on the **operator's own host** | ✅ Yes if the host is seized/imaged | N/A (source-side, not target-side) | Only actionable if the operator's own infrastructure is in scope — see `03` |
| 6 | Static filename/path/command-line matching | ❌ No | ❌ No | Fully operator-controlled (`-o`, macro wrapping, arbitrary rename) — weakest signal in this table by construction, same caveat as most tools in this repo |

## Hunting on Source

**`hashes.txt` and output-directory presence (rank 5):**

```bash
# Direct artifact presence
find / -path /proc -prune -o -path "/var/lib/veil/output*" -print 2>/dev/null
cat /var/lib/veil/output/hashes.txt 2>/dev/null   # every payload hash/filename this host ever generated

# Package-manager confirmation (Kali)
dpkg -l | grep -i veil
```

**Wine/Ruby cross-compile toolchain (an unusual host-level artifact independent of any specific generated payload):**

```bash
find / -path /proc -prune -o -path "*/var/lib/veil/wine*" -print 2>/dev/null
ps aux | grep -E 'wine.*ruby|ocra'
```

**Shell-history reconstruction of CLI-mode invocations:**

```bash
grep -E 'Veil\.py|veil.*-t (Evasion|Ordnance)' ~/.bash_history ~/.zsh_history 2>/dev/null
```

**`checkvt` egress (operator-side network artifact):**

```bash
# Historical connection state / firewall logs for outbound HTTPS to VirusTotal's API
# from a host also showing Veil install/output artifacts above
grep -i virustotal /var/log/syslog /var/log/ufw.log 2>/dev/null
```

## Hunting on Target

**PyInstaller self-extraction sweep (rank 2 — Python-language payloads):**

```powershell
Get-ChildItem -Path $env:TEMP -Filter '_MEI*' -Directory -ErrorAction SilentlyContinue |
    Select-Object FullName, CreationTime, LastWriteTime
```

A live or recently-crashed `_MEI*` directory with no corresponding, digitally-signed, `Add/Remove Programs`-registered parent application is the strongest single artifact this hunt produces — cross-reference the owning process (still-running or from Sysmon Event 1/11) against a known-software inventory.

**Same-process RWX-then-thread pattern (rank 3 — requires EDR/behavioral telemetry, not default Sysmon):**

```powershell
# Illustrative only -- exact query depends on the EDR platform's own API-hooking
# telemetry schema. The pattern to hunt: VirtualAlloc(PAGE_EXECUTE_READWRITE)
# immediately followed by CreateThread targeting an address inside that same
# allocation, within the SAME process (not CreateRemoteThread against a
# different target image).
```

**Metasploit payload-protocol network callback (rank 4) — apply directly, do not re-derive:**

See `Metasploit/Meterpreter/05 - Detection and Hunting.md` and `Metasploit/msfvenom/05 - Detection and Hunting.md` for the full JA3/JARM/staged-payload hunting queries. The one Veil-specific addition — sweep for the tool's own default callback port if a full port range isn't already covered:

```powershell
Get-NetTCPConnection -RemotePort 8675 -ErrorAction SilentlyContinue
```

**Macro-delivery process-tree sweep (T1566.001/T1204.002 chain):**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 1 -and $_.Message -match 'ParentImage:.*\\(WINWORD|EXCEL|POWERPNT)\.EXE' -and
                   $_.Message -match 'Image:.*\\(powershell|cmd)\.exe' }
```

**AV/EDR detection-event sweep (rank 1 — the highest-confidence signal for this specific tool):**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
    Where-Object { $_.Id -in 1116,1117 }
```

Given this page's central finding, treat a **quiet** result from this query on a host otherwise showing PyInstaller/`_MEI*` or macro-delivery indicators as the anomaly worth escalating — not the reverse.

## Fleet-Wide Sweep

```powershell
# Endpoint-side: sweep the fleet for live/orphaned PyInstaller self-extraction
# directories -- the single most distinctive at-scale signal this tool produces
Invoke-Command -ComputerName (Get-ADComputer -Filter *).Name -ScriptBlock {
    Get-ChildItem -Path $env:TEMP -Filter '_MEI*' -Directory -ErrorAction SilentlyContinue
} -ErrorAction SilentlyContinue

# Fleet-wide AV/EDR detection sweep, last 24h
Invoke-Command -ComputerName (Get-ADComputer -Filter *).Name -ScriptBlock {
    Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -in 1116,1117 -and $_.TimeCreated -gt (Get-Date).AddHours(-24) }
} -ErrorAction SilentlyContinue
```

## Remediation

**Capture the artifact (compiled binary, macro-bearing document, or script), the full process-tree/event-log window, and — if the operator's own infrastructure is in scope — the `hashes.txt`/output-directory contents before taking any of the following actions.**

- **Confirm current AV/EDR engine and signature currency on any host where a Veil-sourced artifact executed without detection** — per this page's central finding, an undetected stock Veil payload in 2026 most plausibly indicates a stale or misconfigured endpoint product, and that gap is itself worth remediating independent of this specific incident.
- **Isolate and terminate the host process**, then check for any subsequent persistence mechanism installed by a *separate* tool/technique — Veil's own payloads carry no persistence (see `04`), so any Run key, scheduled task, or service found alongside it represents a distinct follow-on action requiring its own remediation path (cross-reference `LOLBins/schtasks/`, `PowerSploit/PowerUp/`, `GhostPack/` as applicable).
- **Enable PowerShell Module/Script Block Logging** (4103/4104) fleet-wide if not already on, for visibility into `powershell`-language payload variants — off by default, per `LOLBins/powershell/`.
- **Enable Process Creation auditing with command-line logging** (Event 4688 + the command-line-inclusion Group Policy) if not already on — the baseline visibility gap that otherwise leaves this hunt dependent entirely on Sysmon.
- **Block or alert on outbound Office-application child processes** (`WINWORD.EXE`/`EXCEL.EXE`/`POWERPNT.EXE` spawning `powershell.exe`/`cmd.exe`) via Attack Surface Reduction rules or equivalent — closes the macro-delivery chain this tool's `macro_converter` module specifically targets, independent of whether the payload itself is ever signature-matched.
- **Reset any credentials/sessions** the resulting Metasploit/meterpreter session was confirmed to have accessed, per the standard post-C2-session remediation already documented in `Metasploit/Meterpreter/05 - Detection and Hunting.md` — not re-derived here, since post-execution impact is msfvenom/meterpreter's scope, not Veil's.
