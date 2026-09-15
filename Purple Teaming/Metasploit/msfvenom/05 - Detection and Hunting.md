# Metasploit — msfvenom — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

msfvenom exposes more operator-controlled variation than almost any other tool in this module — payload choice, encoder and iteration count, custom template (`-x`/`-k`), output format, and even encryption (`--encrypt`). That surface area is precisely why **static-signature hunting against msfvenom output is structurally weaker than against a tool with a fixed default artifact** (contrast with Impacket's `psexec.py`, whose default binary barely varies — see `../../Impacket/psexec/05 - Detection and Hunting.md`). Rank hunts by what survives that variation, strongest first:

| Rank | Signal | Survives `-e`/`-i` (encoding)? | Survives `-x`/`-k` (templating)? | Survives `-f` (format) change? | Survives `--encrypt`? |
|---|---|---|---|---|---|
| 1 (strongest) | Behavioral EDR on runtime execution (shellcode-shaped `VirtualAlloc`/`VirtualProtect`/execute sequence; for Meterpreter payloads, the reflective-load and injection behaviors in `../Meterpreter/05 - Detection and Hunting.md`) | ✅ Yes — encoding only changes bytes before execution | ✅ Yes | ✅ Yes — behavior is independent of container | ✅ Yes — once decrypted and running, behavior is identical |
| 2 | Code-section entropy anomaly (high-entropy injected region inside an otherwise normal-entropy template/container) | ✅ Yes — encoding *increases* apparent randomness, doesn't remove the contrast | ✅ Yes — the injection itself is what creates the anomaly, regardless of which template | ⚠️ Partial — only applies to executable-container formats (`exe`/`dll`/`elf`/`macho`), not `raw`/source-code transform formats, which have no "rest of the binary" to contrast against | ✅ Yes |
| 3 | Network-layer signal specific to the chosen payload (e.g. Meterpreter's TLV header shape, JA3 on `reverse_https` — full detail in `../Meterpreter/05 - Detection and Hunting.md`) | ✅ Yes — payload-layer protocol, unrelated to how the delivery file was built | ✅ Yes | ✅ Yes | ✅ Yes — network behavior is post-decryption |
| 4 | Default-template/default-encoder static signature (known-bad hash, known decoder-stub byte pattern) | ❌ **No** — a new `-e`/`-i` combination changes the stub's bytes | ❌ **No** — `-x` replaces the template entirely | N/A | N/A — encrypted output has no recognizable stub at all |
| 5 (weakest) | Exact file hash match against a known-bad IOC list | ❌ **No** — any parameter change produces a new hash | ❌ **No** | ❌ **No** — different format is a different file entirely | ❌ **No** |

**Build hunts on ranks 1-2 as primary detections — they're rooted in what the payload has to do to function (execute shellcode, exhibit the injection-entropy contrast) rather than any specific byte pattern an operator can trivially regenerate away. Treat ranks 3 as strong corroboration once a candidate is identified, and ranks 4-5 as enrichment against unmodified/default-configuration use only** — a real, non-trivial share of observed msfvenom activity in practice *is* default-configuration (operators reuse the simplest command that works), so don't discard hash/signature hunting outright, just don't rely on it alone.

**Exception — web-application-format payloads (`-f war`/`jsp`/`raw`-as-PHP/`asp`/`aspx`):** rank 2's entropy-contrast signal doesn't apply — these are plain script/source text, not a compiled container with a "rest of the binary" to contrast against, and rank 4's decoder-stub signature doesn't apply either since these payloads are rarely encoded (`-e` targets compiled shellcode, not JSP/PHP source). For this category, the **application-server-spawns-a-shell process-tree anomaly** (`java.exe`/`w3wp.exe`/`php-cgi` → `cmd.exe`/`powershell.exe`/`/bin/sh`, detailed in `04 - Target Evidence.md`) functionally replaces rank 1 as the strongest, most evasion-resistant signal for this specific delivery shape — see [Hunting on Target](#hunting-on-target) below.

## Hunting on Source

Operator-side hunting only applies in an insider-threat/compromised-infrastructure scenario — legitimate access to the box msfvenom was run from.

```bash
# Shell history — the richest single artifact; reveals payload, LHOST/LPORT,
# template path, and output filename in one line
grep -iE "msfvenom" ~/.bash_history ~/.zsh_history 2>/dev/null

# Live process check (short-lived — catch it mid-run for large/heavily-iterated generations)
ps aux | grep -i msfvenom

# Locate any surviving generated payload files by common extension near
# recent msfvenom activity
find / -newer /etc/hostname \( -iname "*.exe" -o -iname "*.apk" -o -iname "*.elf" -o -iname "*.dll" -o -iname "*.bin" \) 2>/dev/null

# Confirm Framework install + version (module content shifts across releases)
gem list metasploit-framework 2>/dev/null
find / -iname "msfvenom" -type f 2>/dev/null

# auditd — survives shell-history deletion since it's kernel-level
ausearch -x msfvenom 2>/dev/null
ausearch -x ruby 2>/dev/null
```

## Hunting on Target

PowerShell-first, per this module's convention — with an explicit caveat: **rank-1/2 signals (behavioral EDR, entropy analysis) are not something native PowerShell alone can reliably surface.** Use PowerShell for the log/event-based enrichment below and lean on EDR/dedicated static-analysis tooling (e.g. PE-sieve, entropy-scanning utilities) for the strongest signals in the priority table.

```powershell
# 1. Process creation for recently-written executables with no MOTW —
#    combine both conditions since neither alone is unusual
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 500 |
  Where-Object { $_.Message -match 'CommandLine' } |
  Select-Object TimeCreated,
    @{n='Image';e={$_.Properties[4].Value}},
    @{n='Hashes';e={$_.Properties[17].Value}}

# 2. Hash-match against current threat-intel IOC lists — enrichment only
#    (rank 4-5 in the priority table above); pull a CURRENT list, don't
#    hardcode stale hashes
$knownMsfvenomHashes = @('<sha1-or-sha256-from-current-threat-intel>')
Get-FileHash C:\Users\*\Downloads\*.exe, C:\Users\*\AppData\Local\Temp\*.exe -Algorithm SHA256 -ErrorAction SilentlyContinue |
  Where-Object { $_.Hash -in $knownMsfvenomHashes }

# 3. Sysmon Image/DLL Load for a msfvenom-generated DLL loaded the
#    CONVENTIONAL way (unlike Meterpreter's own reflectively-loaded
#    metsrv.dll — see ../Meterpreter/05 - Detection and Hunting.md —
#    a plain -f dll payload loaded via LoadLibrary DOES show up here)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=7} |
  Where-Object { $_.Message -match '\.dll' -and $_.Message -notmatch 'C:\\\\Windows\\\\System32|C:\\\\Program Files' }

# 4. Network connections matching common msfvenom-configured callback
#    ports — coarse, needs tuning; the payload's OWN network behavior
#    (TLV shape, JA3, etc.) is the stronger corroborating signal, see
#    ../Meterpreter/05 - Detection and Hunting.md
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} |
  Where-Object { $_.Message -match 'DestinationPort: (4444|8443|443)\b' }

# 5. Service installs for a -f exe-service payload
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
  Select-Object TimeCreated,
    @{n='ServiceName';e={$_.Properties[0].Value}},
    @{n='ImagePath';e={$_.Properties[1].Value}}

# 6. WAR/JSP/ASP/ASPX web-shell-format payload — application-server process
#    spawning an interactive shell is the strongest signal for this category
#    (see the priority-table exception above); catches Tomcat-on-Windows or
#    IIS regardless of which msfvenom evasion flags built the underlying payload
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 500 |
  Where-Object {
    $_.Message -match 'ParentImage:.*(java\.exe|w3wp\.exe|httpd\.exe|php-cgi\.exe|tomcat)' -and
    $_.Message -match 'Image:.*(cmd\.exe|powershell\.exe|pwsh\.exe)'
  } |
  Select-Object TimeCreated,
    @{n='ParentImage';e={$_.Properties[20].Value}},
    @{n='Image';e={$_.Properties[4].Value}},
    @{n='CommandLine';e={$_.Properties[10].Value}}
```

For a Linux-hosted Tomcat/PHP server, the same process-tree anomaly is the target — `auditd` execve records showing `java`/`httpd`/`php-fpm` as the parent of `/bin/sh`/`/bin/bash` are the direct equivalent of the Sysmon hunt above:

```bash
ausearch -k exec_shell 2>/dev/null | grep -B2 -A2 "ppid.*\(java\|httpd\|php-fpm\)"
```

For the rank-1/2 entropy and behavioral signals, this module doesn't re-derive vendor-specific EDR query syntax or entropy-scanning tool usage — pull whatever the deployed EDR platform exposes for shellcode-injection/high-entropy-region detection, and treat the PowerShell log-based hunts above as the enrichment layer around a candidate the EDR already flagged.

## Fleet-Wide Sweep

```powershell
# Run from a hunting workstation with rights across the estate — catches
# the same payload delivered to multiple hosts in a short window, the
# realistic shape of a phishing campaign or mass-delivery scenario
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'OriginalFileName:\s*-' -or $_.Message -match '\.exe$' } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated,
      @{n='Image';e={$_.Properties[4].Value}}, @{n='Hash';e={$_.Properties[17].Value}}
} -ErrorAction SilentlyContinue

# Group by hash to find the SAME generated payload landing on multiple
# hosts — the strongest fleet-wide signal available from this query shape,
# since it doesn't depend on any hash being pre-known/threat-intel-sourced
$results | Group-Object Hash | Where-Object { $_.Count -gt 1 } |
  Select-Object Count, Name, @{n='Hosts';e={($_.Group.Host | Select-Object -Unique) -join ', '}}

$results | Export-Csv -Path .\msfvenom_fleet_sweep.csv -NoTypeInformation
```
Grouping by hash rather than filename/path is deliberate — msfvenom gives the operator full control over the output filename, so the file's *content* (hash) is the more reliable cross-host correlator than any naming pattern.

## Remediation

**Capture evidence first** — preserve the delivered file itself (hash it, and retain a copy under evidence control) before deleting it; once removed, the exact `-p`/`-e`/`-x`/`-f` combination that produced it may be unrecoverable, which matters for scoping (is this the same payload seen elsewhere, or a re-generated variant).

```powershell
# Remove the delivered payload file
Remove-Item "C:\Path\To\Delivered\payload.exe" -Force -ErrorAction SilentlyContinue

# If it installed as a service (-f exe-service), remove the service too
$svc = "<ServiceNameFromDelivery>"
Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
sc.exe delete $svc

# If the payload was Meterpreter and a session was confirmed live,
# follow ../Meterpreter/05 - Detection and Hunting.md's Remediation
# block for process/credential-rotation cleanup — that section owns
# the post-execution remediation, this note only owns the delivered
# file's own cleanup
```
If the delivered payload successfully established a session (Meterpreter or otherwise), treat everything downstream — credential exposure, lateral movement, persistence — as covered by whichever payload-specific note applies (`../Meterpreter/05 - Detection and Hunting.md` for Meterpreter). Rotate any credentials plausibly exposed to that session before considering the incident closed.
