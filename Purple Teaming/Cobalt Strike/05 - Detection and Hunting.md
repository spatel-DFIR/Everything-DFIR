# Cobalt Strike — Detection and Hunting

Scope note: this file hunts for exactly what `03 - Source Evidence.md` and `04 - Target Evidence.md` already document — Team Server host artifacts, the five listener transports, `spawnto`/injection, named-pipe chaining, `jump psexec`/`winrm` lateral movement, and the bundled Mimikatz credential-access path. Malleable C2's entire purpose is rewriting network content, so this file ranks every signal by whether a profile change alone defeats it — that's the single most important organizing fact for hunting this tool.

## Contents
- [Hunting Priority — What Survives Malleable C2 Customization](#hunting-priority--what-survives-malleable-c2-customization)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — What Survives Malleable C2 Customization

Cobalt Strike exposes more operator-controllable network-content variables than most tools in this repo (`01 - Overview.md`'s Malleable C2 profile section), plus a separate licensed customization surface (Artifact Kit, Sleep Mask Kit, UDRL Kit) that can additionally erode process/memory-level signatures. Rank hunts by what survives **both** axes, not by treating every signal as equally durable:

| Rank | Signal | Survives Malleable C2 profile customization? | Survives Artifact/Sleep-Mask/UDRL Kit customization? | Notes |
|---|---|---|---|---|
| 1 (strongest) | Beacon check-in periodicity (sleep + jitter) as a statistical pattern across many connections | ✅ Yes — profile customization changes *content*, not the underlying interval the operator set | ✅ Yes — no kit touches timing | Even fully profile-customized traffic still beacons on a near-fixed interval; RITA-style statistical beaconing analysis remains effective regardless of URI/UA/cert content |
| 2 | Process/network-layer mismatch: `spawnto` process (default `rundll32.exe`-class binary) making outbound connections with no legitimate reason to | ✅ Yes — profile customization is network-content-only, doesn't change which process makes the connection | ⚠️ Partial — a custom UDRL can change the injection *mechanism*, but the sacrificial-process concept itself (something making a network connection it has no business making) generally persists unless the operator also avoids process spawning entirely | Per Fortra's own acknowledgment of the `rundll32.exe`-connecting-out pattern (`04 - Target Evidence.md`) |
| 3 | Sysmon 8/10 (CreateRemoteThread/ProcessAccess) for `spawn`/`inject`/`execute-assembly`/Mimikatz's LSASS access | ✅ Yes | ❌ **No** — a custom UDRL is licensed Cobalt Strike's direct answer to defeating this exact signal class | Treat as strong on an un-customized/trial-tier deployment, weaker on a well-resourced licensed one |
| 4 | Named-pipe patterns (`\msagent_*`, `\postex_*`, `\status_*`, `\MSSE-*-server`) | ✅ Yes — profile customization doesn't touch Artifact Kit pipe-naming code | ❌ **No** — Artifact Kit modification + recompile changes these; per multiple independent sources many operators don't bother | Community-verified defaults (`04 - Target Evidence.md`'s caveat) — real-world productive despite being trivially defeatable in principle |
| 5 | `jump psexec`/`psexec64` service-creation events (Security 4697/System 7045) | ✅ Yes | ✅ Yes — SCM service-install mechanics are OS-level, not something any Cobalt Strike kit touches | The lateral-movement mechanism itself is invariant even if the service name/binary path is operator-chosen |
| 6 | Default TLS cert (`CN=jquery.com`, serial `146473198`), default URIs (`/jquery-*.min.js`), default User-Agent | ❌ **No** — the entire point of a Malleable C2 profile is rewriting exactly these fields | N/A | Only useful against sloppy/unmaintained infrastructure still running an out-of-the-box or lightly modified public profile — still common enough to be worth checking, per `01 - Overview.md`'s note on public-profile reuse |
| 7 (weakest) | JA3/JA3S/JARM hashes tied to the default Java TLS stack | ❌ Mostly no — a supplied cert/JDK-version change shifts JARM; profile customization doesn't fully control this but operator infrastructure choices (reverse proxy, different TLS terminator) do | N/A | Fingerprints the *TLS library*, not Cobalt Strike specifically — useful as a candidate filter, not standalone proof |

**Build primary hunts on ranks 1-2 wherever you have full-packet-capture/Zeek visibility — they're the two signals a Malleable C2 profile structurally cannot touch. Ranks 3-5 are your best host-level detections and remain strong against a non-licensed or lightly-customized deployment (the majority of cracked/leaked-license activity per `02 - Hands-On Use Cases.md`'s ransomware-precursor scenario, since attackers running stolen/cracked copies rarely also have the Arsenal Kits needed to defeat ranks 3-4). Treat ranks 6-7 as bonus checks only.**

## Hunting on Source

Commands below assume access to a suspected/known Team Server host (an authorized red-team infrastructure audit, or a seized/identified rogue server during an investigation) — this section is naturally thinner than a typical tool in this repo since Cobalt Strike's Team Server is Linux-only and closed-source, unlike the Windows-heavy operator tooling elsewhere in this module.

```bash
# 1. Identify a running teamserver process
ps aux | grep -i '[c]obaltstrike\|[t]eamserver'

# 2. Locate the license/auth file and profile in use (03 - Source Evidence.md)
find / -xdev -iname 'CobaltStrike.auth' -o -iname '*.profile' 2>/dev/null

# 3. Team Server logs — richest source-side artifact
find / -xdev -path '*logs/*/events.log' -o -path '*logs/*/web.log' -o -path '*logs/*/*.log' 2>/dev/null | \
  xargs -I{} ls -la {} 2>/dev/null

# 4. Data store (.bin files) — session/listener/credential state
find / -xdev \( -name 'sessions.bin' -o -name 'listeners.bin' -o -name 'credentials.bin' \) 2>/dev/null

# 5. Listener/management ports bound on this host
ss -tlnp 2>/dev/null | grep -E ':50050|:80 |:443 |:53 '

# 6. Shell history for the launch command (captures profile path + kill date)
grep -E 'teamserver|c2lint' ~/.bash_history ~/.zsh_history 2>/dev/null

# 7. Network-based candidate identification (unauthenticated infra recon —
#    only appropriate for authorized hunting/attribution work, not exploitation)
#    JARM against a candidate host's suspected listener port:
python3 jarm.py <candidate-ip> -p 443
```

For a live/recently-terminated `teamserver` process's memory (private key material backing the Beacon connection keystore, in-flight tasking, decrypted watermark derivation — `03 - Source Evidence.md`'s Memory Forensics section), use a platform-appropriate Linux memory-acquisition tool (AVML/LiME) rather than a query-style hunt.

## Hunting on Target

```powershell
# 1. spawnto/rundll32-class outbound connection anomaly — rank 2
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'rundll32\.exe' -and $_.Message -notmatch 'DllRegisterServer|InstallHelper' }

# 2. CreateRemoteThread / ProcessAccess for spawn/inject/execute-assembly/Mimikatz — rank 3
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=8,10} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'GrantedAccess' }
# LSASS-specific GrantedAccess mask interpretation follows
# Mimikatz/sekurlsa (Credential Dumping)/04 - Target Evidence.md

# 3. Named-pipe creation/connection matching known default patterns — rank 4
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=17,18} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '\\msagent_|\\postex_|\\status_|\\MSSE-.*-server' }

# 4. jump psexec service-install sequence — rank 5
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4697} -ErrorAction SilentlyContinue
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -ErrorAction SilentlyContinue
# Cross-reference against Security 4688/5140/5145 in the same tight window
# for the SMB/ADMIN$ binary-drop step preceding service start

# 5. jump winrm — WinRM session + PowerShell logging, if enabled
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 500 -ErrorAction SilentlyContinue
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4103,4104} -ErrorAction SilentlyContinue

# 6. Pass-the-hash / make_token signature — Logon Type 9 (NewCredentials)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'Logon Type:\s*9' }

# 7. Beaconing-interval statistical check — established connections to the
#    same remote endpoint at a near-fixed interval (rank 1, the strongest
#    Malleable-C2-resistant signal); this is best run against Zeek/NetFlow
#    data rather than host-local state, shown here as a coarse local proxy
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
  Group-Object RemoteAddress | Where-Object Count -gt 5

# 8. DNS-listener beaconing — Sysmon 22, encoded-looking query volume to a
#    single non-corporate parent domain
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=22} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'QueryName: [a-z0-9]{15,}\.' }

# 9. Low-confidence bonus check — default cert/URI/UA (rank 6-7, only
#    catches un-customized/lazy deployments per the priority table)
#    Best run at the proxy/Zeek layer, not host-local:
#    look for User-Agent "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
#    combined with a TLS 1.2/1.3 handshake (an IE11-era UA has no business
#    negotiating modern TLS) or a request to /jquery-3.3.*.min.js /
#    /submit.php?id= from a process other than an actual browser
```

## Fleet-Wide Sweep

```powershell
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ErrorAction SilentlyContinue -ScriptBlock {
  $hits = [System.Collections.Generic.List[object]]::new()

  # Rank 4: known default named-pipe patterns
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=17,18} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match '\\msagent_|\\postex_|\\status_|\\MSSE-.*-server' } | ForEach-Object {
      $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'default-pipe'; Time = $_.TimeCreated })
    }

  # Rank 5: jump psexec service installs
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4697} -ErrorAction SilentlyContinue | ForEach-Object {
    $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'service-install'; Time = $_.TimeCreated })
  }

  # Rank 2: rundll32-class process with an outbound connection
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'rundll32\.exe' } | ForEach-Object {
      $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'rundll32-network'; Time = $_.TimeCreated })
    }

  # Rank 3: injection primitive
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=8} -ErrorAction SilentlyContinue | ForEach-Object {
    $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'remote-thread'; Time = $_.TimeCreated })
  }

  $hits
}

# A host hitting MULTIPLE independent signal classes in a tight window
# (e.g. rundll32-network AND remote-thread AND default-pipe) is a far
# stronger candidate than any single signal alone
$results | Group-Object Host, Signal | Sort-Object Count -Descending | Select-Object -First 30 Count, Name

$results | Export-Csv -Path .\cobaltstrike_sweep_results.csv -NoTypeInformation
```

## Remediation

**Capture evidence before acting.** Killing the Beacon process or isolating the host destroys exactly the volatile artifacts this note has emphasized as most valuable: the in-memory Malleable C2 profile/config (recoverable via `1768.py`/`CobaltStrikeParser` per `04 - Target Evidence.md`'s Memory Forensics section, which also directly identifies the watermark/license family behind the intrusion), and any `execute-assembly`/BOF output that never touched disk. Pull a memory image, Sysmon 1/3/8/10/17/18 events, and Security 4688/4697/System 7045 events for the affected host(s) first — and, if a Team Server is directly reachable/seizable as part of the response, its `logs/`/`data/` artifacts per `03 - Source Evidence.md` before that host is touched.

Cobalt Strike itself isn't the thing to "fix" — for legitimate engagements it's licensed red-team software riding legitimate OS mechanisms (SMB, WinRM, process injection APIs, Windows service creation); for illegitimate/ransomware-precursor use (`02 - Hands-On Use Cases.md`) it's very likely a cracked copy riding the exact same mechanisms. The hardening targets are the access paths documented throughout this note:

```powershell
# Command-line auditing for process creation — without it, Security 4688
# can't corroborate the spawnto/injection process lineage or any jump/
# remote-exec command line at all:
# Computer Configuration > Administrative Templates > System > Audit
# Process Creation > "Include command line in process creation events" = Enabled

# Restrict SMB admin-share/service-creation access where not operationally
# required — closes the jump psexec lateral-movement path (Security 4697/
# System 7045):
# Computer Configuration > Windows Firewall > "File and Printer Sharing"
# inbound rule group — scope to management hosts only

# Restrict/monitor WinRM (TCP 5985/5986) to expected management sources
# only — closes the jump winrm path documented in 04 - Target Evidence.md

# Egress filtering with a default-deny + explicit allowlist policy forces
# HTTP(S)/DNS C2 traffic onto a proxied/logged path where beaconing-
# interval statistical analysis (rank 1 in the priority table) has
# visibility, regardless of Malleable C2 profile customization

# LSASS protection (Credential Guard / RunAsPPL) — blunts the built-in
# logonpasswords/mimikatz/hashdump credential-access path; see
# Mimikatz/sekurlsa (Credential Dumping)/05 - Detection and Hunting.md
# for the full LSASS-hardening treatment, applies identically here

# Ensure Sysmon is deployed with process (1), network (3),
# CreateRemoteThread (8), ProcessAccess (10), pipe (17/18), and DNS (22)
# events enabled — per the priority table, this is the one native-logging
# source that reliably survives Malleable C2 profile customization on
# ranks 2-4 even where command-line auditing or PowerShell logging is off

# If a cracked/leaked license is suspected (watermark value 0/1, or any
# watermark not matching your own organization's known-legitimate auth
# file), report the finding — Fortra has an active disruption partnership
# with Microsoft and the Health-ISAC specifically targeting cracked
# Cobalt Strike infrastructure (01 - Overview.md)
```

Enabling Sysmon with the specific event-ID set above, combined with beaconing-interval statistical analysis at the network layer, is the single highest-leverage compensating control from this note's perspective — it is the one combination that survives Malleable C2 profile customization in full, regardless of how much effort an operator put into rewriting the wire content.
