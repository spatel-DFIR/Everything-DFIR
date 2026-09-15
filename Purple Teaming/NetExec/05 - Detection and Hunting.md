# NetExec — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal Survives Which Evasion Option](#hunting-priority--which-signal-survives-which-evasion-option)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal Survives Which Evasion Option

NetExec's real evasion surface is narrower than its flag count suggests: `--no-admin-check` removes the `\svcctl` probe (but not the null-session probe — there is no flag for that at all), `--exec-method` changes which artifact family appears (but not that *some* execution artifact appears), `--jitter`/`--no-bruteforce`/`--fail-limit`* change the *shape* of a spray (but not that authentication attempts occur), and `atexec`'s XML/path randomization defeats static string matching specifically (but not RPC-call-pattern matching). Ranked by what survives the most of these:

| Rank | Signal | Survives `--no-admin-check`? | Survives `--exec-method` choice? | Survives spray-shape flags (`--jitter`/`--no-bruteforce`)? | Survives `atexec`'s XML/path randomization? |
|---|---|---|---|---|---|
| 1 (strongest) | Security 4624, Logon Type 3, account `ANONYMOUS LOGON` — the unconditional null-session probe | ✅ Yes — unrelated flag | N/A — fires before any exec method runs | ✅ Yes — fires regardless of spray shape or timing | N/A |
| 2 | A single source IP authenticating (real or anonymous) against an unusually large number of distinct destination hosts/accounts in a short window | ✅ Yes | ✅ Yes | ⚠️ **Partial** — `--jitter` widens the window a fixed-interval threshold would catch, `--fail-limit`* narrows per-account attempts, but the many-hosts-one-source pattern itself persists | ✅ Yes |
| 3 | `\svcctl` bind + `EnumServicesStatusW` immediately following a successful SMB auth, with no other requested action in the same session | ❌ **No** — this is exactly what `--no-admin-check` removes | N/A | ✅ Yes | N/A |
| 4 | Exec-method-specific artifact (service create/delete for `smbexec`, `WmiPrvSE.exe` child + Temp output file for `wmiexec`, scheduled-task lifecycle for `atexec`, DCOM/MMC activation for `mmcexec`) | ✅ Yes | ❌ **No, by design** — switching methods changes which artifact family appears entirely; a hunt tuned to only one method misses the others | ✅ Yes | ⚠️ Partial — RPC-call-sequence matching survives; literal command-line/XML-content matching does not |
| 5 | Static filename/command-line string matching (`nxc`, `netexec`, literal task/service name patterns) | ✅ Yes | ✅ Yes | ✅ Yes | ❌ **No** — this is exactly what the built-in randomization is engineered to defeat |
| 6 (weakest) | Directory Service Event 1644 (expensive-query diagnostic, DC-side) for `--bloodhound`/bulk LDAP enumeration | ✅ Yes | N/A | ✅ Yes | N/A | — not enabled by default (same caveat as `AdFind/05`) |

**Build hunts on ranks 1–2 first.** Rank 1 in particular is a genuine gift: because the null-session probe is unconditional and un-disableable in the current source, it is the one signal that survives literally every evasion flag NetExec exposes, including ones not yet invented — any future flag would have to change core connection-loop behavior, not just add an option, to remove it.

*`--gfail-limit`/`--ufail-limit`/`--fail-limit` are officially lockout-avoidance controls, not stealth controls — they happen to narrow rank 2's per-account attempt count as a side effect.

## Hunting on Source

Applies where the operator host itself is available (an internal red-team retro, or a seized attack-platform image):

```powershell
# 1. Recover the full engagement scope directly from the workspace database
#    (SQLite -- requires a sqlite3 client, not a native PowerShell cmdlet)
sqlite3 $env:USERPROFILE\.nxc\workspaces\default\smb.db `
  "SELECT ip, hostname, domain, os, admin FROM hosts;"

# 2. Recover every credential ever tried in this workspace
sqlite3 $env:USERPROFILE\.nxc\workspaces\default\smb.db `
  "SELECT domain, username, credtype, credential FROM users;"

# 3. Enumerate the per-host/per-artifact log tree (filenames alone name every
#    dumped host and the exact timestamp, before opening a single file)
Get-ChildItem "$env:USERPROFILE\.nxc\logs" -Recurse -File |
  Select-Object FullName, LastWriteTime

# 4. Shell-history fallback if the workspace itself isn't recoverable
Select-String -Path $env:USERPROFILE\.bash_history, $env:USERPROFILE\.zsh_history `
  -Pattern 'nxc |netexec |cme ' -ErrorAction SilentlyContinue

# 5. Live-response: a running nxc process and its outbound connection fan-out
Get-Process | Where-Object { $_.Path -match 'python3?$' -and $_.CommandLine -match 'nxc|netexec' }
Get-NetTCPConnection -State Established |
  Group-Object RemoteAddress | Where-Object Count -gt 0 | Sort-Object Count -Descending
```

## Hunting on Target

```powershell
# 1. Rank-1 signal -- the unconditional null-session probe, fleet-wide
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
  Where-Object { $_.Message -match 'Logon Type:\s*3' -and $_.Message -match 'ANONYMOUS LOGON' } |
  Select-Object TimeCreated, @{n='SourceIP';e={($_.Message | Select-String -Pattern 'Source Network Address:\s*(\S+)').Matches.Groups[1].Value}}

# 2. Rank-2 signal -- one source authenticating against many accounts/hosts
#    in a short window (run per-host, aggregate centrally via SIEM in practice)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 5000 |
  Where-Object { $_.Message -match 'Logon Type:\s*3' } |
  Group-Object @{Expression={($_.Message | Select-String -Pattern 'Source Network Address:\s*(\S+)').Matches.Groups[1].Value}} |
  Where-Object Count -gt 20 |
  Select-Object Name, Count

# 3. Rank-3 signal -- \svcctl admin-check with no accompanying execution artifact
#    (requires Object Access auditing on IPC$/named pipes, non-default)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5145} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'svcctl' }

# 4. Rank-4 signal -- exec-method-specific, check all four:
#    smbexec: service create/start/delete cluster with a 10-char random name
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
  Where-Object { $_.Message -match 'Service Name:\s*[A-Za-z]{10}\s' }

#    wmiexec: WmiPrvSE.exe spawning cmd.exe with output redirected to
#    \Windows\Temp\<6-char-random>, no extension
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'ParentImage:.*WmiPrvSE\.exe' -and $_.Message -match '\\Windows\\Temp\\[A-Za-z]{6}\s' }

#    atexec: scheduled task named with an 8-char random string, short-lived
#    (created and deleted within seconds -- cross-link LOLBins/schtasks/05)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} |
  Where-Object { $_.Message -match 'Task Name:\s*\\[A-Za-z]{8}\s' }

# 5. LDAP-side: Kerberoasting/AS-REP roasting bursts and targeted-SPN writes
#    (mechanics fully covered in Impacket/GetUserSPNs (Kerberoasting)/05 and
#    LOLBins/setspn/05 -- apply those queries directly, NetExec produces the
#    identical event shape)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} |
  Group-Object @{Expression={($_.Message | Select-String -Pattern 'Account Name:\s*(\S+)').Matches.Groups[1].Value}} |
  Where-Object Count -gt 5
```

## Fleet-Wide Sweep

```powershell
# Sweep the estate for the unconditional null-session probe -- the one
# signal every nxc/cme invocation leaves regardless of protocol, module,
# exec-method, or evasion flag in play
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Logon Type:\s*3' -and $_.Message -match 'ANONYMOUS LOGON' } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated,
      @{n='SourceIP';e={($_.Message | Select-String -Pattern 'Source Network Address:\s*(\S+)').Matches.Groups[1].Value}}
} -ErrorAction SilentlyContinue

# Group by source IP -- a single IP appearing across dozens/hundreds of
# distinct target hosts in a tight window is the fleet-wide signature
$results | Group-Object SourceIP | Sort-Object Count -Descending |
  Select-Object Name, Count | Export-Csv -Path .\netexec_sweep_results.csv -NoTypeInformation

# Cross-reference: a source IP producing this pattern followed within a
# short window by BloodHound/SharpHound collection activity, or by an
# Impacket-style wmiexec/smbexec/secretsdump artifact set, is a strong
# composite signal for active credential validation feeding straight into
# exploitation -- see ../BloodHound/SharpHound/05 - Detection and Hunting.md
# and ../Impacket/wmiexec/05 - Detection and Hunting.md for those tools'
# own hunt queries to run alongside this one
```

## Remediation

**Capture evidence first** — pull the source-side workspace database if the operator host is reachable (it names the *entire* intended scope and credential set in one file, per `03`), and the target-side 4624/4769/4698/7045 clusters, before killing sessions or resetting credentials; a NetExec sweep's own footprint (per `03`/`04`) is thin enough on some exec paths (`mmcexec`, `wmiexec` fileless mode) that acting first risks losing the only recoverable record of what was actually touched.

NetExec itself isn't the thing to fix — like `AdFind/`, it's a legitimate audit/pentest tool exploiting normal SMB/LDAP/WinRM administrative surface and (for the null-session probe specifically) a protocol behavior that predates the tool by decades:

```powershell
# 1. Close the actual exposure the null-session/guest probe exists to find --
#    restrict anonymous access rather than trying to detect every tool that
#    might attempt it (NetExec is one of dozens that will)
# Computer Configuration > Windows Settings > Security Settings >
#   Local Policies > Security Options >
#   "Network access: Restrict anonymous access to Named Pipes and Shares" = Enabled
#   "Network access: Let Everyone permissions apply to anonymous users" = Disabled

# 2. Enable command-line/process-creation auditing + Sysmon if not already
#    deployed -- the single highest-leverage move for ranks 2/4/5 above,
#    same recommendation already made in AdFind/05 and PsExec/05
# Computer Configuration > Administrative Templates > System > Audit
#   Process Creation > "Include command line in process creation events" = Enabled

# 3. Enable Object Access auditing on IPC$/named-pipe access if not already
#    a standing requirement -- required for rank-3 (\svcctl probe) visibility
#    via 5145; weigh the logging volume this adds against the marginal gain,
#    since ranks 1/2/4/5 don't depend on it

# 4. Reduce the value of a successful credential-validation sweep rather
#    than trying to block LDAP/SMB read access outright (broad read is
#    normal/required AD/file-share behavior):
#    - Eliminate local-admin password reuse across the fleet (LAPS or
#      equivalent) -- this is the single condition that turns "one spray
#      hit" into "fleet-wide Pwn3d!" in the chained workflow from 02
#    - Enforce SMB signing everywhere reachable -- directly defeats the
#      --gen-relay-list -> Impacket/ntlmrelayx/ chain documented in 02
#    - Rotate/clear SYSVOL GPP cpassword remnants (gpp_password module
#      target) and any remaining PASSWD_NOTREQD/adminCount=1 stale flags
#      (same audit-yourself-first recommendation as AdFind/05)
```

Restricting anonymous SMB access and deploying command-line-capturing Sysmon are the two highest-leverage moves from this note's perspective — together they cover ranks 1, 2, 4, and 5 of the priority table above without depending on any non-default DC diagnostic logging or Object Access auditing overhead.
