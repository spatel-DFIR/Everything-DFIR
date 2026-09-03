# Impacket — psexec.py — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Network-Layer Hunting](#network-layer-hunting)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

Not every artifact in `03 - Source Evidence.md`/`04 - Target Evidence.md` survives operator evasion equally well. Rank hunts by **invariant strength**, strongest first:

| Rank | Signal | Survives `-service-name`/`-remote-binary-name`? | Survives `-file`? |
|---|---|---|---|
| 1 (strongest) | `\PIPE\RemCom_*` named-pipe family (Sysmon 17/18) | ✅ Yes — pipe names are hard-coded client-side, unrelated to naming flags | ✅ Yes — the pipe protocol is independent of which binary was uploaded |
| 2 | Event-sequence timing (4624 → 5140 → 7045 → 7036 in a tight window) | ✅ Yes | ✅ Yes |
| 3 | File hash of the dropped binary | ✅ Yes (naming doesn't touch content) | ❌ **No** — `-file` replaces the binary entirely |
| 4 (weakest) | Default random-naming pattern (4-char service, 8-char binary) | ❌ **No** — this is exactly what those flags exist to defeat | N/A |

**Build hunts on ranks 1-2 as your primary detections; treat ranks 3-4 as high-confidence enrichment, not sole detection logic.**

## Hunting on Source

```bash
# Shell history for any psexec/impacket invocation (credentials may be exposed in the match)
grep -iE "psexec|impacket" ~/.bash_history ~/.zsh_history 2>/dev/null

# Live process check — argv is visible to any local user via /proc, not just root
ps aux | grep -i psexec

# Confirm impacket install + locate the script and its version on disk
pip3 show impacket 2>/dev/null
find / -iname "psexec.py" 2>/dev/null

# Live SMB connection to a target on 445 (or 139 if -port was used)
ss -tnp | grep -E ':445|:139'

# If auditd is enabled, pull the execve record even after the process has exited —
# this is the one source-side artifact that survives a shell-history wipe
ausearch -x psexec.py 2>/dev/null

# .pyc bytecode-cache mtimes can bound "first run on this box" even after history -c
find / -path "*/impacket/*" -name "*.pyc" -newer /etc/hostname 2>/dev/null
```

## Hunting on Target

```powershell
# 1. Service-installation events — match BOTH naming conventions: the default random
#    pattern (4-letter service name / 8-letter binary in C:\Windows root) AND any
#    ImagePath outside the normal System32/Program Files locations, since -service-name
#    defeats the first pattern but not the location anomaly
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
  Select-Object TimeCreated,
    @{n='ServiceName';e={$_.Properties[0].Value}},
    @{n='ImagePath';e={$_.Properties[1].Value}},
    @{n='ServiceType';e={$_.Properties[2].Value}},
    @{n='StartType';e={$_.Properties[3].Value}},
    @{n='Account';e={$_.Properties[4].Value}} |
  Where-Object {
    $_.ImagePath -match '\\Windows\\[A-Za-z]{8}\.exe$' -or
    ($_.ImagePath -notmatch '\\Windows\\System32|\\Program Files' -and $_.Account -eq 'LocalSystem')
  }

# 2. Network logons (Type 3) immediately preceding a 7045 event -> correlate source IP
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
  Where-Object { $_.Properties[8].Value -eq 3 } |
  Select-Object TimeCreated, @{n='Account';e={$_.Properties[5].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}

# 3. ADMIN$ / share access immediately preceding a file write
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5140} |
  Where-Object { $_.Message -match '\\\\ADMIN\$|\\\\C\$' }

# 4. HIGHEST-CONFIDENCE: Sysmon named-pipe events for the RemCom protocol family —
#    survives every evasion flag this tool exposes (see priority table above)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=17,18} |
  Where-Object { $_.Message -match 'RemCom_(communicaton|stdin|stdout|stderr)' }

# 5. Orphaned dropped binaries that survived a failed cleanup (default naming only —
#    won't catch a -remote-binary-name override, pair with hash/pipe hunts for that)
Get-ChildItem C:\Windows\*.exe -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^[A-Za-z]{8}\.exe$' }

# 6. Orphaned Prefetch entries matching the same default naming pattern
Get-ChildItem C:\Windows\Prefetch\*.pf -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^[A-Za-z]{8}\.EXE-' }

# 7. Hash-match against the known default Impacket RemCom-derived binary
#    (pull a current IOC hash set from threat intel before relying on this —
#    remember: -file defeats this entirely, see priority table)
$knownImpacketPsexecHashes = @('<sha1-or-sha256-from-current-threat-intel>')
Get-FileHash C:\Windows\*.exe -Algorithm SHA1 -ErrorAction SilentlyContinue |
  Where-Object { $_.Hash -in $knownImpacketPsexecHashes }

# 8. Service lifecycle anomaly: created, started, and stopped within a tight window —
#    catches custom-named services that hash/naming hunts above would miss
$svc7045 = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045}
foreach ($e in $svc7045) {
  $name = $e.Properties[0].Value
  $stopEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7036} |
    Where-Object { $_.Message -match [regex]::Escape($name) -and $_.TimeCreated -lt $e.TimeCreated.AddMinutes(10) }
  if ($stopEvents) {
    [PSCustomObject]@{ Service = $name; Installed = $e.TimeCreated; StoppedWithin10Min = $true }
  }
}
```

## Fleet-Wide Sweep

```powershell
# Run from a hunting workstation with rights across the estate — catches the
# mass-execution scenario from 02 - Hands-On Use Cases.md, where the real signal
# is many hosts showing the SAME pattern in a tight time window, not any single host
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 50 -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[1].Value -match '\\Windows\\[A-Za-z]{8}\.exe$' } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated,
      @{n='ServiceName';e={$_.Properties[0].Value}}, @{n='ImagePath';e={$_.Properties[1].Value}}
} -ErrorAction SilentlyContinue

# Group by time window to spot a burst (ransomware-style push) vs. isolated single-host lateral movement
$results | Group-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') } |
  Sort-Object Count -Descending | Select-Object -First 10 Count, Name

$results | Export-Csv -Path .\psexec_sweep_results.csv -NoTypeInformation
```

## Network-Layer Hunting

For environments with a network sensor (Zeek, Suricata, etc.) — valuable in segments without endpoint logging, or as an independent corroborating source:

```
# Zeek: DCE/RPC operations against the svcctl named pipe endpoint,
# independent of any host-based log entirely
zeek-cut ts id.orig_h id.resp_h endpoint operation < dce_rpc.log | grep -i svcctl

# Zeek: SMB tree-connects to ADMIN$/C$ followed closely by a file write
zeek-cut ts id.orig_h id.resp_h path < smb_mapping.log | grep -iE 'ADMIN\$|C\$'
```

## Remediation

**Capture evidence first** — export the Event 7045/Sysmon 17-18 records and hash the dropped binary before touching anything, since remediation destroys the artifacts this note is built around.

```powershell
$svc = "<ServiceNameFrom7045>"
Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
sc.exe delete $svc
Remove-Item "C:\Windows\<RANDOM8>.exe" -Force -ErrorAction SilentlyContinue

# If -c uploaded a second payload, remove that separately — it won't share
# the RemCom binary's name or hash
```
