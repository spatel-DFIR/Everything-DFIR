# Mimikatz — sekurlsa — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal Survives Which Evasion](#hunting-priority--which-signal-survives-which-evasion)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal Survives Which Evasion

sekurlsa exposes three materially different operator postures, each defeating a different layer of detection: a **dropped `mimikatz.exe`/`.dll`** (defeats nothing but static signature), a **renamed/custom-compiled binary** (defeats hash/name-based signature specifically), and **in-memory execution** via `Invoke-Mimikatz`, Cobalt Strike `execute-assembly`, or Meterpreter's `kiwi` extension (defeats every file-based detection layer at once). Rank hunts by what survives all three, strongest first:

| Rank | Signal | Survives binary rename/custom compile? | Survives in-memory/reflective load (`kiwi`, `execute-assembly`, `Invoke-Mimikatz`)? |
|---|---|---|---|
| 1 (strongest) | Sysmon Event 10 `GrantedAccess` mask against `lsass.exe` (`0x1010`/`0x1410`/`0x1038` for `pth`) | ✅ Yes — kernel-generated at `OpenProcess()` time, independent of the caller's file identity | ✅ Yes — the underlying system call is identical whether the code came from a file or a reflectively-mapped memory region |
| 2 | ASR rule 1121 (block) / 1122 (audit) — "Block credential stealing from lsass.exe" | ✅ Yes | ✅ Yes — but **only if the rule is actually deployed**; this is a configuration-dependent signal, not a universal one, and its absence proves nothing |
| 3 | Sysmon `CallTrace` anomaly — `UNKNOWN`/unbacked-memory frame in the access thread's call stack | ✅ Yes | ✅ Yes — and this is specifically the signal that *helps confirm* reflective loading rather than just detecting the access itself; requires raw-event inspection, not surfaced in most default views |
| 4 | Minidump file artifact (large recent file, MZ header, unusual location) | ✅ Yes — naming/location is independent of file content | ⚠️ **N/A** — only applies to the offline `sekurlsa::minidump` workflow; a live in-memory read produces no file at all |
| 5 | Security 4656/4663 (SACL-audited handle request/access) | ✅ Yes, in principle | ✅ Yes, in principle — but **near-universally absent in practice**, since it requires a non-default SACL configured directly on the `lsass.exe` process object |
| 6 (weakest) | Static hash/filename signature (`mimikatz.exe`, known SHA1/SHA256) | ❌ **No** — this is exactly what renaming/custom-compiling defeats | ❌ **No** — no file exists to hash at all |

**Build detections on ranks 1-2. Treat ranks 3-5 as high-value enrichment/confirmation. Rank 6 catches only the least-careful operators and should never be a sole control.**

## Hunting on Source

Applies when the operator's own pivot/staging box (Windows or Linux) is itself in scope — a compromised-infrastructure investigation, insider-threat case, or a purple-team exercise reviewing the operator side. Finds the artifacts documented in `03 - Source Evidence.md`.

```powershell
# PSReadLine history — full command text including any inline /ntlm:/aes256: material,
# if mimikatz was run interactively from a PowerShell console on the operator's own box
Select-String -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" `
  -Pattern 'sekurlsa|Invoke-Mimikatz|privilege::debug' -ErrorAction SilentlyContinue

# Security 4688 (command-line process creation, if enabled) — the most durable operator-side
# record, generated at process-creation time, independent of shell history
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'mimikatz|Invoke-Mimikatz|sekurlsa' }

# Live process check for a still-running dropped binary — uncommon on a real engagement,
# realistic for a seized/compromised operator box
Get-Process | Where-Object { $_.ProcessName -match 'mimikatz' }

# Locally staged loot — a downloaded Invoke-Mimikatz.ps1, or a .dmp/.kirbi pulled back
# from a target for offline sekurlsa::minidump/sekurlsa::tickets analysis
Get-ChildItem -Path C:\ -Recurse -Include '*.dmp','*.kirbi','Invoke-Mimikatz*.ps1' `
  -ErrorAction SilentlyContinue -Force
```

```bash
# If the operator's pivot box is Linux (e.g. hosting a Beacon/Meterpreter handler rather
# than running mimikatz interactively) — captures the handler/framework invocation itself,
# not the mimikatz commands typed inside that C2 session's own interface
grep -iE "msfconsole|teamserver|beacon" ~/.bash_history ~/.zsh_history 2>/dev/null

# Live outbound connection to a target while a C2 session carrying sekurlsa/kiwi traffic
# is active — nothing mimikatz-specific in the connection itself, just corroborating state
ss -tnp | grep ESTAB
```

## Hunting on Target

```powershell
# 1. HIGHEST-CONFIDENCE: Sysmon Event 10 against lsass.exe with a known sekurlsa-family
#    GrantedAccess mask, excluding the small set of legitimate SourceImages — adjust the
#    exclusion list to your own environment's actual security-agent process names
$knownMaskPattern = '0x1010|0x1400|0x1410|0x1038|0x1F1FFF|0x1FFFFF'
$legitSourcePattern = 'MsMpEng\.exe|SenseIR\.exe|svchost\.exe'
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} |
  Where-Object {
    $_.Message -match 'TargetImage:.*lsass\.exe' -and
    $_.Message -match $knownMaskPattern -and
    $_.Message -notmatch $legitSourcePattern
  } |
  Select-Object TimeCreated, @{n='SourceImage';e={($_.Message -split "`r`n" | Where-Object { $_ -match 'SourceImage:' })}},
    @{n='GrantedAccess';e={($_.Message -split "`r`n" | Where-Object { $_ -match 'GrantedAccess:' })}}

# 2. sekurlsa::pth-specific signature — Security 4624 Logon Type 9 (NewCredentials),
#    correlated against a Sysmon 10 hit carrying the write-capable 0x1038 mask
$newCred = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
  Where-Object { $_.Properties[8].Value -eq 9 }
$pthAccess = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} |
  Where-Object { $_.Message -match 'lsass\.exe' -and $_.Message -match '0x1038' }
foreach ($n in $newCred) {
  $match = $pthAccess | Where-Object { [math]::Abs(($_.TimeCreated - $n.TimeCreated).TotalSeconds) -lt 30 }
  if ($match) { [PSCustomObject]@{ NewCredLogon = $n.TimeCreated; LsassAccess = $match.TimeCreated } }
}

# 3. ASR rule hits — Block (1121) and Audit (1122) for the LSASS credential-theft rule
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1121,1122} |
  Where-Object { $_.Message -match '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' }

# 4. Minidump file hunt — large, recently-created files carrying a Minidump/MZ signature
#    outside expected locations (crash-dump directories excluded)
Get-ChildItem -Path C:\Windows\Temp, C:\ProgramData -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object { $_.Length -gt 20MB -and $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
  ForEach-Object {
    $bytes = [System.IO.File]::ReadAllBytes($_.FullName) | Select-Object -First 2
    if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) { $_ }   # 'MZ' header
  }

# 5. WDigest posture gap — flag hosts where UseLogonCredential is enabled against an
#    expected-disabled baseline (proactive hardening-gap hunt, not an incident hunt)
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
  -Name UseLogonCredential -ErrorAction SilentlyContinue |
  Where-Object { $_.UseLogonCredential -eq 1 }

# 6. LSA Protection / hardening posture — inventory which hosts are NOT running RunAsPPL,
#    since those are the hosts where a plain-vanilla read-only OpenProcess will succeed
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue

# 7. Security 4656/4663 — only meaningful if lsass.exe carries a non-default SACL;
#    confirm that configuration exists before treating an empty result as "clean"
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4656,4663} |
  Where-Object { $_.Message -match 'lsass\.exe' }
```

## Fleet-Wide Sweep

Two distinct fleet-wide use cases: an **incident sweep** (has this technique been run anywhere?) and a **posture sweep** (which hosts are even exposed to it?). Both matter for sekurlsa specifically, since the posture question (WDigest/RunAsPPL/Credential Guard state) directly determines blast radius.

```powershell
$targets = Get-Content .\hosts.txt

# Incident sweep — GrantedAccess hits against lsass.exe across the estate
$incidentResults = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'lsass\.exe' -and $_.Message -match '0x1010|0x1410|0x1038' } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated
} -ErrorAction SilentlyContinue

# Posture sweep — which hosts still allow the technique at all
$postureResults = Invoke-Command -ComputerName $targets -ScriptBlock {
  [PSCustomObject]@{
    Host          = $env:COMPUTERNAME
    RunAsPPL      = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
    WDigestOn     = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential
  }
} -ErrorAction SilentlyContinue

$postureResults | Where-Object { $_.RunAsPPL -ne 1 -or $_.WDigestOn -eq 1 } |
  Export-Csv -Path .\sekurlsa_exposed_hosts.csv -NoTypeInformation
```

## Remediation

**Capture evidence before acting.** sekurlsa's real damage is whatever credential material it already read and exfiltrated — killing the offending process doesn't undo that, and remediation steps below destroy the artifacts this note is built around. Export the Sysmon 10/ASR events and, where forensically warranted, capture a memory image of `lsass.exe` (or the full host) before proceeding.

```powershell
# 1. Isolate the host — a pass-the-hash session (sekurlsa::pth) or exfiltrated hash/ticket
#    material can be used for lateral movement independent of anything happening on this box
# (isolation mechanism is environment-specific — EDR network-containment, VLAN change, etc.)

# 2. Kill the offending process/session
Get-Process | Where-Object { $_.ProcessName -match 'mimikatz|rundll32|procdump' } | Stop-Process -Force -ErrorAction SilentlyContinue

# 3. If a sekurlsa::pth NewCredentials (Logon Type 9) session was identified, terminate
#    the spawned process under that logon and treat the impersonated account as compromised
#    (rotate its credentials regardless of whether the spawned process is still running)

# 4. Force credential rotation for every account whose material appeared in the dump —
#    assume anything sekurlsa could have read (NTLM hash, WDigest plaintext, Kerberos
#    keys/tickets) is compromised, not just the account used to gain initial access
```

**Close the underlying exposure, not just this incident:**
- Enable the ASR rule "Block credential stealing from the Windows local security authority subsystem (lsass.exe)" (`9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`) in **Block** mode, with exclusions for legitimate diagnostic tooling if needed.
- Enable LSA Protection (`RunAsPPL`) fleet-wide where compatible, and Credential Guard where hardware/OS support allows — both covered in `01 - Overview.md`'s Prerequisites table.
- Confirm `WDigest UseLogonCredential` is `0` (or absent, on a build where that's the secure default) via GPO baseline, not host-by-host.
- If a minidump was exfiltrated (`02 - Hands-On Use Cases.md`'s quiet-target workflow), treat the exposure as already complete regardless of what's cleaned up locally — the credential material was parsed offline, entirely outside this host's visibility (`04 - Target Evidence.md`'s timeline section). Check operator-infrastructure evidence (`03 - Source Evidence.md`) for where that file went.
