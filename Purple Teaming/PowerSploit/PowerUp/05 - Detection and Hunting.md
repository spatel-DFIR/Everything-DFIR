# PowerUp — Detection and Hunting

## Contents
- [Hunting Priority](#hunting-priority)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority

Ranked by which signal survives PowerUp's own evasion angles — a custom `-UserName`/`-Password`/`-Command` (defeats the default-credential signature), disabled PowerShell logging (defeats content-level detection), and a re-encoded/repacked payload template (defeats static-signature matching on the known Base64 blob).

| Rank | Signal | Survives custom user/command? | Survives disabled logging? | Survives repacked payload? |
|---|---|---|---|---|
| 1 | `HKLM\SYSTEM\CurrentControlSet\Services\<name>\ImagePath` registry value not matching the service's baselined/known-good original | Yes — the registry write happens regardless of what command was patched in | Yes — registry, not a log | Yes — the write location doesn't depend on payload content |
| 2 | Absence of a corresponding Event 4697/7045 for a service whose config just changed (the reconfigure-vs-create gap) | Yes | Yes | Yes |
| 3 | PE-metadata/hash match against the known-constant `$B64Binary` template regions | No — a repacked/recompiled payload changes the file entirely | Yes | **No** — this is exactly what a repack defeats |
| 4 | Local account named `john`/password `Password123!` created (default-credential signature) | **No** — trivially defeated by `-UserName`/`-Password` | Yes | Yes |
| 5 | Event 400 (classic PowerShell channel) — session start with the invoking command line | Yes | Yes — on by default | Yes |
| 6 | 4104 Script Block Logging full content (function names, patched command visible) | Yes | **No** — off by default | Yes |
| 7 | EDR static signature on the unmodified payload blob | N/A | N/A | **No** — this is the first thing a competent operator changes |

## Hunting on Source

```powershell
# Event 400 — session start with a PowerUp-suggestive command line
Get-WinEvent -LogName "Windows PowerShell" |
    Where-Object { $_.Id -eq 400 -and $_.Message -match 'Invoke-(AllChecks|PrivescAudit)|Get-Modifiable|Set-ServiceBin|Install-ServiceBinary|Write-ServiceBinary' } |
    Select-Object TimeCreated, Message

# 4104 content, where Script Block Logging is enabled
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
    Where-Object { $_.Id -eq 4104 -and $_.Message -match 'Invoke-(AllChecks|PrivescAudit)|ChangeServiceConfig|Write-ServiceBinary|B64Binary' }

# ConsoleHost_history.txt — interactive sessions only
Select-String -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" `
    -Pattern 'Invoke-AllChecks|Invoke-PrivescAudit|Set-ServiceBin|Install-ServiceBinary'
```

## Hunting on Target

```powershell
# Registry: enumerate every service's ImagePath and flag ones pointing outside
# well-known system directories or matching a known-bad path
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
    $ip = (Get-ItemProperty $_.PSPath -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
    if ($ip -and $ip -notmatch '^"?C:\\Windows\\System32|^"?C:\\Program Files') {
        [PSCustomObject]@{ Service = $_.PSChildName; ImagePath = $ip }
    }
}

# Local account named exactly "john" — default-credential signature, cheap and high-confidence when it hits
Get-LocalUser -Name john -ErrorAction SilentlyContinue

# Event 4720 (account created) / 4732 (added to group) in the same short window as a service registry change
Get-WinEvent -LogName Security | Where-Object { $_.Id -in 4720,4732 -and $_.Message -match 'john' }

# Absence check: services with a recent registry LastWriteTime but no matching 4697/7045
# (requires a registry-timestamp baseline comparison — not a single native log query)

# EDR/AV alert history for known PowerUp payload-template signatures
```

## Fleet-Wide Sweep

Because PowerUp is purely local (see `03 - Source Evidence.md`), a "fleet-wide" hunt here means running the same per-host registry/local-account checks above across the estate via a management tool (Group Policy scheduled script, EDR live-response query, or a remote PowerShell fan-out), not a network-flow aggregation the way PowerView's fleet sweep is:

```powershell
# Example: fan out the ImagePath-baseline check across every domain computer
# reachable via WinRM (adjust scope/throttling for a real estate)
$Computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
Invoke-Command -ComputerName $Computers -ScriptBlock {
    Get-LocalUser -Name john -ErrorAction SilentlyContinue
} -ErrorAction SilentlyContinue
```

## Remediation

- **Fix the underlying misconfigurations PowerUp discovers, not just the operator's specific abuse of them** — an unquoted service path, a world-writable service binary, or `AlwaysInstallElevated` left on are the real vulnerability; reverting one attacker-modified `ImagePath` value without fixing the permission gap that allowed it leaves the host exploitable again immediately.
- **Enable Script Block Logging (4104) and Module Logging (4103)** — same fleet-wide recommendation as `PowerView/05 - Detection and Hunting.md`; both tools share the identical PowerShell-engine evidence gap.
- **Baseline service `ImagePath` values** (and alert on drift) — this is the one signal that survives every evasion option in the Hunting Priority table above; it's worth the operational investment specifically because of that durability.
- **Restrict local write access to `%PATH%` directories and service binary locations** — directly closes `Get-ModifiablePath`/`Get-ModifiableServiceFile`'s discovery surface rather than only reacting to abuse of it.
- **Disable `AlwaysInstallElevated`** (`HKLM`/`HKCU` `SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated`) unless a specific, documented deployment need requires it.
- **Preserve evidence before restoring a hijacked service** — capture the modified `ImagePath` value and the dropped/replaced binary (for the constant-template hash match) before running `Restore-ServiceBinary` or reverting the registry value by hand; both remove the clearest artifact of what actually happened.
