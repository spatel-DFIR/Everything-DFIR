# LaZagne — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal Survives Which Evasion Option](#hunting-priority--which-signal-survives-which-evasion-option)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal Survives Which Evasion Option

LaZagne's evasion surface is narrower than most tools in this repo — it's an open-source Python application, so **recompiling/repacking the standalone `.exe`** (defeats file-hash/static signature matching) and **running from source instead of the standalone build** (defeats PE-metadata matching entirely) are the two realistic operator moves. Neither touches the *behavioral* artifacts below, which come from what the code does at runtime, not what the file looks like on disk.

| Rank | Signal | Survives repacking/recompiling? | Survives running from Python source instead of the standalone `.exe`? | Requires admin? |
|---|---|---|---|---|
| 1 (strongest) | `reg.exe save hklm\{sam,security,system}` process-creation cluster (Sysmon 1 / Security 4688 with command-line auditing) — 3 children, each targeting a random 6-12-char extensionless `%TEMP%` filename, all within about a second of each other | ✅ Yes — `reg.exe` is Microsoft's own binary, unaffected by anything done to the LaZagne build itself | ✅ Yes — this is runtime behavior, identical whether LaZagne runs as a compiled `.exe` or raw Python | Yes |
| 2 | `netsh.exe wlan show profile "<SSID>" key=clear` process creation, for the `wifi` module's no-admin fallback path | ✅ Yes | ✅ Yes | No |
| 3 | PyInstaller `CArchive` magic-cookie trailer (`MEI\x0c\x0b\x0a\x0b\x0e`) present in the on-disk binary, independent of filename | ✅ Yes, survives renaming — ⚠️ **No**, defeated by running from Python source (no PyInstaller wrapper exists in that case) or by a different freezing tool (Nuitka, per the project's own documented build option) | ❌ No, by definition — this is a source-vs-standalone distinction | N/A |
| 4 | Mass `OpenProcess`/`OpenProcessToken` pattern across many PIDs from one source process (Sysmon 10 ProcessAccess, `GrantedAccess: 0x400`) | ✅ Yes | ✅ Yes | Yes — this phase only runs elevated |
| 5 (weakest, config-dependent) | Same as rank 4, but **many default/published Sysmon configurations exclude `GrantedAccess: 0x400` specifically** to reduce noise from benign monitoring-tool activity — verify your own deployment's actual `ProcessAccess` filter rule before relying on this at all | N/A (a deployment/config question, not an evasion the operator controls) | N/A | Yes |
| — | File hash / static AV signature on the standalone `.exe` | ❌ No — trivially defeated by recompiling or repacking | ❌ No — doesn't apply once running from source | N/A |
| — | Command-line content matching a fixed binary name (`laZagne.exe`) | ❌ No — trivially defeated by rename | ❌ No | N/A |

**Build hunts on ranks 1-2 first.** They're native Microsoft-binary process-creation events, require only standard Sysmon/command-line-auditing deployment (no exotic config), and are completely unaffected by anything an operator does to the LaZagne binary itself — the strongest possible position for a tool whose actual on-disk footprint is otherwise easy to disguise.

## Hunting on Source

Because LaZagne is purely local (per `03`), "source" hunting here means hunting the **delivery** evidence, not a distinct LaZagne-specific behavior — see `03`'s framing. The commands below belong on whatever host staged or pushed the binary:

```powershell
# 1. Recently-transferred files matching the PyInstaller CArchive signature,
#    on a host suspected of staging LaZagne for delivery — carve for the
#    trailer bytes rather than trusting the filename
Get-ChildItem -Path C:\ -Recurse -Include *.exe -ErrorAction SilentlyContinue |
  ForEach-Object {
    $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
    $magic = [byte[]](0x4D,0x45,0x49,0x0C,0x0B,0x0A,0x0B,0x0E)  # 'MEI' + cookie
    if (($bytes.Length -gt 8) -and ([System.Text.Encoding]::ASCII.GetString($bytes[-64..-1]) -match 'MEI')) {
      $_.FullName
    }
  }

# 2. If a prior lateral-movement tool delivered the binary, pivot to that
#    tool's own 03 - Source Evidence.md hunt commands (PsExec, Impacket
#    psexec/smbexec, etc.) rather than duplicating them here
```

## Hunting on Target

This is where the real signal is — see the Hunting Priority table above for what to trust most:

```powershell
# 1. (Rank 1) The reg.exe hive-export cluster — the single strongest signal.
#    Look for 3 reg.exe save children within a tight window, targeting
#    random-looking extensionless filenames under %TEMP%
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'reg\.exe.*save hklm\\(sam|security|system)\s' }

# Same via Security 4688, if command-line auditing is enabled
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'reg\.exe.*save hklm\\(sam|security|system)\s' }

# 2. (Rank 2) netsh.exe WiFi key-recovery command
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'netsh\.exe.*wlan show profile.*key=clear' }

# 3. (Rank 3) PyInstaller-trailer carving against the current filesystem,
#    independent of any filename LaZagne was renamed to (see script in
#    "Hunting on Source" above — same technique, run here against the
#    executing host instead of a staging host)

# 4-5. (Rank 4/5) Mass process-token access — verify your Sysmon config's
#    ProcessAccess GrantedAccess filter before relying on this
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} -ErrorAction SilentlyContinue |
  Group-Object { ([xml]$_.ToXml()).Event.EventData.Data[2].'#text' } |  # group by SourceImage
  Where-Object { $_.Count -gt 15 } |
  Select-Object Name, Count

# 6. Filesystem — a leftover unnamed/extensionless file in %TEMP% (survives
#    only if the run crashed or was killed before delete_hives() ran)
Get-ChildItem $env:TEMP -File | Where-Object {
  $_.Name -match '^[a-z]{6,12}$' -and $_.Extension -eq ''
}

# 7. Output-file sweep — timestamp-derived name, not a fixed string
Get-ChildItem -Path C:\ -Recurse -Include 'credentials_*.txt','credentials_*.json' -ErrorAction SilentlyContinue

# 8. Standalone-binary presence, if not running from memory/source
Get-ChildItem -Path C:\ -Recurse -Include *.exe -ErrorAction SilentlyContinue |
  Where-Object { (Get-AuthenticodeSignature $_.FullName).Status -ne 'Valid' } |
  Select-String -Path { $_.FullName } -Pattern 'lazagne' -SimpleMatch -ErrorAction SilentlyContinue
```

## Fleet-Wide Sweep

The `reg.exe`/`netsh.exe` process-creation pattern is the right basis for a fleet sweep — it's stable, native-binary-based, and doesn't depend on the LaZagne build being unmodified:

```powershell
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
    Where-Object {
      $_.Message -match 'reg\.exe.*save hklm\\(sam|security|system)\s' -or
      $_.Message -match 'netsh\.exe.*wlan show profile.*key=clear'
    } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated,
      @{n='CommandLine';e={($_.Message | Select-String -Pattern 'CommandLine:\s*(.+)').Matches.Groups[1].Value}},
      @{n='ParentImage';e={($_.Message | Select-String -Pattern 'ParentImage:\s*(.+)').Matches.Groups[1].Value}}
} -ErrorAction SilentlyContinue

$results | Sort-Object TimeCreated | Export-Csv -Path .\lazagne_sweep_results.csv -NoTypeInformation

# The reg.exe cluster (rank 1) is high-precision on its own; correlate a
# hit against Sysmon 10's ProcessAccess volume (rank 4, config permitting)
# on the same host in the same window to confirm the impersonation phase
# also ran, distinguishing a full elevated sweep from a narrower
# single-module invocation
```

## Remediation

**Capture evidence first** — pull the Sysmon 1/10 events, any surviving `%TEMP%` hive-copy remnants, and (if not already exfiltrated) the `credentials_*` output file before killing the process or isolating the host. Per `04`, LaZagne holds decrypted plaintext in the process's own memory for the run's duration — a live memory capture of a still-running process is the only way to recover exactly what it found if the operator avoided writing an output file and captured results only via C2 task output (per `03`).

LaZagne itself isn't the thing to fix — it's exploiting the same broad set of legitimate, by-design local credential-storage mechanisms (DPAPI, Credential Manager, browser-vendor encryption, application config files) that every user and admin process relies on. The durable hardening targets are the access paths and privilege boundaries it rides, not the binary:

```powershell
# Command-line auditing is the single highest-value native control here —
# NOT enabled by default, and the rank-1/2 process-creation signals above
# depend on it for Security 4688 visibility (Sysmon 1 captures command
# lines regardless, making Sysmon deployment the higher-leverage move if
# it isn't already present):
# Computer Configuration > Administrative Templates > System > Audit
# Process Creation > "Include command line in process creation events" = Enabled

# Reduce the value of a successful admin-level run:
# - Enforce Credential Guard where hardware/OS support allows — it doesn't
#   block LaZagne's disk/registry-based extraction paths directly, but it
#   materially changes the LSA-secrets/credential-caching landscape those
#   paths depend on
# - Minimize standing local-admin rights and shared local-admin credentials
#   across the fleet specifically to blunt Phase 3's cross-user
#   impersonation value — a box where every user's process runs under a
#   distinct, non-privileged identity and no single account has admin
#   everywhere limits how much one elevated run can reach
# - Rotate and monitor Autologon usage — HKLM Winlogon cleartext credential
#   storage on older/misconfigured systems is a near-zero-effort win for
#   this tool specifically

# Review who genuinely needs local admin on shared/jump-box-style hosts —
# Phase 3/4's per-user impersonation and filesystem-walk value scale
# directly with how many distinct users' material is reachable from a
# single elevated session on that box
```

If a `credentials_*` output file or a leftover `%TEMP%` hive-copy remnant is found, treat every credential it could plausibly contain as compromised and rotate accordingly — LaZagne's own coverage (30+ browsers, every major remote-access client, OS-level stores) means a successful run's blast radius is rarely limited to a single account or application.
