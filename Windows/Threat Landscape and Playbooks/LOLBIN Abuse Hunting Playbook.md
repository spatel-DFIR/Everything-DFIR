# LOLBIN Abuse Hunting Playbook

**Scope note:** this is a narrower, hunting-focused consolidation, not the full FOR608-style enterprise-hunting treatment (Sigma rule authoring, Hayabusa, EDR-bypass/AV-evasion detection) that `PLANNING.md` explicitly deferred for this pass. What it does cover: the five living-off-the-land binaries whose abuse tradecraft was otherwise scattered as passing mentions across `06`/`11` with no single place naming their command-line tells side by side — `certutil.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, and `wmic.exe`. Each is a legitimate, Microsoft-signed Windows binary an attacker repurposes for download, execution, or defense evasion specifically *because* it's already trusted and already present — no dropped tooling required to use it.

> 🔴 **Every LOLBIN in this note passes a code-signing check with flying colors — that's the entire point of using one.** None of these five binaries will ever show up as "unsigned" or "unknown" in a triage sweep; they're legitimate parts of Windows. The tell is never *what* ran, it's the **command-line arguments** — a legitimate admin rarely has a reason to invoke `regsvr32.exe` against a remote URL, or `certutil.exe` with `-decode`. Command-line visibility (4688 with command-line auditing enabled, or Sysmon Event ID 1) is not optional for this playbook — without it, every technique below is functionally invisible.

## Contents

- [Attack Chain](#attack-chain)
- [Quick Triage](#quick-triage)
- [The Five LOLBins and Their Tells](#the-five-lolbins-and-their-tells)
- [Scope the Activity](#scope-the-activity)
- [Timeline](#timeline)
- [Eradication](#eradication)
- [Credential Reset](#credential-reset)
- [Fleet Hunt](#fleet-hunt)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

## Attack Chain

LOLBins are rarely the initial access vector or the terminal payload themselves — they're a **primitive** an attacker plugs into a broader intrusion at whichever stage needs it: downloading a second-stage payload past application-allowlisting controls, executing attacker-supplied code through a trusted parent process to blend into normal-looking process trees, or decoding/deobfuscating a payload that arrived in an innocuous-looking encoded form. Because the binary itself is legitimate and signed, this stage of an intrusion is specifically designed to defeat "is this signed" as a detection heuristic — which is exactly why this playbook exists as a companion to, not a replacement for, execution-evidence and persistence-mechanism hunting elsewhere in this module.

## Quick Triage

Requires command-line visibility — confirm 4688 command-line auditing or Sysmon is actually deployed before trusting an empty result as "nothing happened" (note 11's own caution applies here directly).

```powershell
# All five LOLBins' command lines in one sweep, last 24 hours - the standing triage query
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'certutil\.exe|mshta\.exe|rundll32\.exe|regsvr32\.exe|wmic\.exe' } |
    Select-Object TimeCreated, @{N='CommandLine';E={($_.Message -split "Process Command Line:")[1]}}

# Sysmon equivalent, if deployed (Event ID 1) - generally more reliable command-line capture than native 4688
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'certutil\.exe|mshta\.exe|rundll32\.exe|regsvr32\.exe|wmic\.exe' }
```

## The Five LOLBins and Their Tells

The consolidated table this playbook exists to provide — what's legitimate, what abuse looks like, and the specific command-line pattern that separates the two.

| LOLBIN | Legitimate use | Abuse pattern | Command-line tell | ATT&CK ID |
|---|---|---|---|---|
| **`certutil.exe`** | Certificate/CA management, hash verification | Downloading a remote file (`-urlcache`) or decoding a base64-encoded payload staged as a fake certificate (`-decode`) — both entirely undocumented uses of a certificate-management tool | `-urlcache -split -f http(s)://...` (download); `-decode <infile> <outfile>` (decode-to-execute staging) | T1105 (Ingress Tool Transfer), T1140 (Deobfuscate/Decode Files or Information) |
| **`mshta.exe`** | Running trusted `.hta` (HTML Application) files | Executing attacker-controlled JScript/VBScript directly, often fetched from a remote URL, entirely outside the browser's own security context | `mshta.exe http://...` or `mshta.exe javascript:...` — a remote URL or inline script argument, not a local `.hta` file path | T1218.005 (System Binary Proxy Execution: Mshta) |
| **`rundll32.exe`** | Loading a DLL's exported function — routine, constant background Windows activity | Executing an exported function from an attacker-supplied or unusual DLL, or invoking `javascript:` execution via `rundll32.exe url.dll,OpenURL` and similar undocumented call chains | A DLL path outside `System32`/`SysWOW64`, or any `.dll,<exported_function>` pairing that doesn't match a known-legitimate Windows use | T1218.011 (System Binary Proxy Execution: Rundll32) |
| **`regsvr32.exe`** | Registering/unregistering a local COM DLL | "Squiblydoo" — registering a remote `.sct` scriptlet directly from a URL, with the `/s /u /i:<url> scrobj.dll` pattern bypassing both AppLocker and local-file requirements entirely | `/i:http(s)://...scrobj.dll` — a remote URL as the `/i:` argument is never a legitimate local COM-registration pattern | T1218.010 (System Binary Proxy Execution: Regsvr32) |
| **`wmic.exe`** | Local/remote WMI queries and management (deprecated in newer Windows builds but still present/usable on most estates) | Remote process creation (`/node:<host> process call create`) for lateral movement, or `wmic os get /format:<url>` — style XSL-transform execution abusing WMIC's output-formatting feature to run remote XSL/JScript | `/node:` targeting a remote host with `process call create`; `/format:http(s)://...` referencing a remote XSL stylesheet | T1047 (Windows Management Instrumentation) |

## Scope the Activity

```powershell
# Fleet-wide sweep for the same LOLBin command-line pattern, once one host confirms a hit
Invoke-Command -ComputerName (Get-Content C:\hunt\all_hosts.txt) -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match '<confirmed_malicious_pattern>' }
}
```

Scope by the specific command-line pattern confirmed on the first host, not just the binary name — `rundll32.exe` alone fires constantly as routine Windows activity; the malicious instance is defined by its arguments, and that's what should drive the fleet-wide sweep.

## Timeline

```powershell
# First-execution evidence for the LOLBin itself is usually unhelpful in isolation - Prefetch/Amcache (note 06)
# records that rundll32.exe or certutil.exe ran, which happens constantly for legitimate reasons.
# The 4688/Sysmon command-line timestamp IS the timeline anchor for this playbook, not Prefetch alone.
Get-ChildItem "$env:SystemRoot\Prefetch\CERTUTIL.EXE-*.pf" -ErrorAction SilentlyContinue | Select-Object CreationTime, LastWriteTime
```

Bracket the case around the confirmed malicious command-line timestamp, then work outward to what it downloaded/decoded/executed (a dropped file's own creation timestamp) and whatever ran next in the process tree — the LOLBin invocation itself is a single step in a longer chain, not the endpoint of the investigation.

## Eradication

```powershell
# Kill the LOLBin process if still running (often short-lived and already exited)
Get-Process -Name 'certutil','mshta','rundll32','regsvr32','wmic' -ErrorAction SilentlyContinue |
    Where-Object { $_.Path } | Stop-Process -Force

# Remove any file the LOLBin downloaded or decoded
Remove-Item '<downloaded_or_decoded_payload_path>' -Force -ErrorAction SilentlyContinue

# Block the source URL/domain at DNS/proxy/firewall if a download was involved
```

Address whatever the LOLBin actually delivered — a second-stage payload, a persistence mechanism (note 10), or a remote-execution foothold (note 12) — using that payload's own dedicated playbook or note; this section only covers the LOLBin invocation itself.

## Credential Reset

Not every LOLBin finding implicates credentials directly — `wmic /node:` remote execution is the exception, since it requires (and its presence confirms use of) a valid credential against the target host. If that's the confirmed pattern, treat it as a credential-theft/lateral-movement finding and hand off to [`12 - Lateral Movement`](<../12 - Lateral Movement.md>)'s credential-reset guidance rather than duplicating it here. For the download/decode/proxy-execution patterns (`certutil`, `mshta`, `rundll32`, `regsvr32`), credential reset only applies if the delivered payload itself turns out to be a credential stealer — see the [`Commodity Malware and Info-Stealer Playbook`](<Commodity Malware and Info-Stealer Playbook.md>) in that case.

## Fleet Hunt

```powershell
# Estate-wide sweep for all five patterns at once, independent of which host originally triggered this hunt
Invoke-Command -ComputerName (Get-Content C:\hunt\all_hosts.txt) -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match '-urlcache|-decode|mshta\.exe http|scrobj\.dll|/node:.*process call create|/format:http' }
}
```

## Correlate With

| To go deeper on… | Open |
|---|---|
| Whether 4688 command-line auditing is even enabled — the prerequisite this entire playbook depends on | [`11 - Event Log Analysis`](<../11 - Event Log Analysis.md>) |
| Prefetch/Amcache execution evidence for the LOLBin and whatever it delivered | [`06 - Evidence of Program Execution`](<../06 - Evidence of Program Execution>) |
| WMI-based remote execution and lateral movement in full depth | [`12 - Lateral Movement`](<../12 - Lateral Movement.md>), [`10 - Persistence Mechanisms/WMI Event Consumers.md`](<../10 - Persistence Mechanisms/WMI Event Consumers.md>) |
| What a delivered second-stage payload turns into, if it's a credential stealer | [`Commodity Malware and Info-Stealer Playbook`](<Commodity Malware and Info-Stealer Playbook.md>) |
| What a delivered second-stage payload turns into, if it's ransomware or mass-deployed via GPO | [`Ransomware Playbook`](<Ransomware Playbook.md>), [`GPO-Based Mass Deployment Playbook`](<GPO-Based Mass Deployment Playbook.md>) |

## Red Flags

| 🔴 Finding | Meaning |
|---|---|
| `certutil.exe -urlcache` or `-decode` against a non-certificate file | Download or decode-to-execute staging, not legitimate CA/hash-verification use |
| `mshta.exe` invoked against a remote URL or inline `javascript:` argument | Remote script execution outside browser security context |
| `rundll32.exe` loading a DLL path outside `System32`/`SysWOW64`, or an unrecognized exported function | Proxy execution of an attacker-supplied or unusual DLL |
| `regsvr32.exe /i:http(s)://...scrobj.dll` | Squiblydoo — remote scriptlet execution bypassing AppLocker/local-file requirements |
| `wmic.exe /node:<remote_host> process call create` | Remote process creation — requires and confirms use of a valid credential against the target |
| `wmic.exe .../format:http(s)://...` | XSL-transform remote-script-execution abuse of WMIC's output formatting |
| Any of the above with no corresponding 4688/Sysmon command-line data available | Confirm auditing is actually enabled before concluding "nothing happened" — absence of evidence here is usually absence of visibility |

## Resources

- MITRE ATT&CK **T1218.005** (System Binary Proxy Execution: Mshta) — https://attack.mitre.org/techniques/T1218/005/
- MITRE ATT&CK **T1218.010** (System Binary Proxy Execution: Regsvr32) — https://attack.mitre.org/techniques/T1218/010/
- MITRE ATT&CK **T1218.011** (System Binary Proxy Execution: Rundll32) — https://attack.mitre.org/techniques/T1218/011/
- MITRE ATT&CK **T1105** (Ingress Tool Transfer) — https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK **T1140** (Deobfuscate/Decode Files or Information) — https://attack.mitre.org/techniques/T1140/
- MITRE ATT&CK **T1047** (Windows Management Instrumentation) — https://attack.mitre.org/techniques/T1047/
- LOLBAS Project (living-off-the-land binaries reference) — https://lolbas-project.github.io/
