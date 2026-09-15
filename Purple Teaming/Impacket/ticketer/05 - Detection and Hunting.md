# Impacket — ticketer.py — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal Survives Which Mode](#hunting-priority--which-signal-survives-which-mode)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal Survives Which Mode

Same structural point as `Mimikatz/kerberos (Golden-Silver Ticket)/05 - Detection and Hunting.md`'s priority table — Golden vs. Silver is a permanent, upfront choice that determines the entire downstream detection surface — **plus one axis that's unique to `ticketer.py`: plain forging vs. `-request`/`-impersonate`**, which determines whether the *forging step itself* generates any target-side evidence at all.

| Rank | Signal | Applies to | Notes |
|---|---|---|---|
| 1 (strongest) | DC-side Golden Ticket signals — Zeek `kerberos.log`, Security 4769-with-no-prior-4768, MDI alert family | Golden, **any forging mode**, at USE time | Identical to Mimikatz's equivalent — **not re-ranked here**, see `Mimikatz/kerberos (Golden-Silver Ticket)/05 - Detection and Hunting.md` directly |
| 2 (ticketer.py-specific) | Genuine 4768/4769 for the `-user` account, paired with that same source host later presenting a *different* identity's ticket elsewhere | `-request`/`-impersonate` only, at **forging** time | No Mimikatz equivalent — this signal doesn't exist for plain forging or for any Mimikatz `kerberos::golden` variant. Requires host-level source correlation, not a single-event hunt |
| 3 | Target application server's own access/authorization anomaly (behavioral) | Silver, **any mode** | The only lever against Silver Ticket regardless of forging tool — identical framing to the Mimikatz note's rank-6 entry, not re-derived |
| 4 | Operator-side artifacts — shell history, the `.ccache` file, `KRB5CCNAME` | All modes | Requires the operator/pivot host to be in scope (`03 - Source Evidence.md`) |
| — | Time-anomaly / lifetime-based signal (MDI 2022-equivalent) | Plain forge only | **Does not survive `-request`** at all — `-duration` is silently ignored and the ticket inherits a real, policy-compliant lifetime (`01 - Overview.md`), unlike Mimikatz where lifetime-matching is always an optional evasion flag the operator has to remember to set |

**Build primary detections on rank 1 for Golden Ticket coverage regardless of forging tool — that hunt is tool-agnostic by construction. Rank 2 is the one genuinely new lever this tool's `-request`/`-impersonate` modes create, and it doesn't exist anywhere in the Mimikatz-focused coverage; build it as a distinct hunt, not a variant of an existing one.**

## Hunting on Source

Applies when the operator's own host, or a pivot host reached via a prior compromise, is itself in scope. Finds the artifacts documented in `03 - Source Evidence.md`.

```bash
# Shell history — the forged identity, raw key material, and (for -request/-impersonate)
# the template account's own credentials
grep -iE "ticketer\.py|getTGT\.py" ~/.bash_history ~/.zsh_history 2>/dev/null

# Locally staged .ccache files — the forged ticket itself
find / -iname "*.ccache" -newer /etc/hostname 2>/dev/null

# KRB5CCNAME references in shell config/environment
grep -rn "KRB5CCNAME" ~/.bashrc ~/.zshrc ~/.profile ~/.bash_profile 2>/dev/null
env | grep KRB5CCNAME

# Live process check
ps aux | grep -i ticketer

# Confirm impacket install + version — -impersonate/Sapphire support is comparatively recent
pip3 show impacket 2>/dev/null

# Outbound Kerberos-port connections — expected ONLY for -request/-impersonate runs;
# their presence for what shell history shows as a plain (no -request) invocation is
# itself an inconsistency worth investigating
ss -tnp | grep -E ':88|:464'

# auditd execve record — survives a shell-history wipe
ausearch -x ticketer.py 2>/dev/null
```

## Hunting on Target

```powershell
# 1. DC-side Golden Ticket USE evidence — cross-link, don't duplicate. Run the exact
#    Zeek kerberos.log / Security 4769-without-4768 / MDI alert queries documented in
#    Mimikatz/kerberos (Golden-Silver Ticket)/05 - Detection and Hunting.md's
#    "Hunting on Target" section. They detect a ticketer.py-forged Golden Ticket's use
#    identically to a Mimikatz kerberos::golden one, since both present the same
#    wire-protocol artifact once used.

# 2. TICKETER.PY-SPECIFIC: correlate a genuine 4768/4769 with a LATER, DIFFERENT
#    identity's ticket use from the SAME source. This is the -request/-impersonate
#    signal that has no Mimikatz equivalent — it hunts the forging step itself, not
#    just the eventual use.
$templateAuths = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768,4769} -MaxEvents 5000 |
  Select-Object TimeCreated, @{n='Account';e={$_.Properties[0].Value}}, @{n='SourceIP';e={$_.Properties[9].Value}}
# Cross-reference $templateAuths against subsequent 4624/4769 events from the SAME
# SourceIP for a DIFFERENT account within a short window (minutes) — a low-privilege
# account requesting a TGT/TGS, then a high-privilege identity appearing from the same
# source shortly after, is the pattern to chase. Requires host-level source-IP
# correlation across event types; not a single built-in query.

# 3. Target-application-server behavioral anomaly — the only lever for SILVER, any mode
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
  Where-Object { $_.Message -match 'Logon Type:\s*3' -and $_.Message -match 'Kerberos' } |
  Group-Object { ($_.Message -split "`r`n" | Where-Object { $_ -match 'Account Name:' })[0] } |
  Where-Object { $_.Count -eq 1 }   # first-ever-seen access from this account to this server

# 4. -k/ccache-authenticated Impacket sessions specifically — 4624 events with
#    AuthenticationPackageName: Kerberos and NO corresponding NTLM-hash/password material
#    anywhere in a paired command-line/process-creation event, on hosts where the four
#    already-built Impacket tools' own hunts (Impacket/psexec, wmiexec, smbexec,
#    secretsdump — each 05) would otherwise expect to find one
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
  Where-Object { $_.Message -match 'Authentication Package:\s*Kerberos' }

# 5. Posture check — krbtgt password age (same as Mimikatz note's equivalent hunt)
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object PasswordLastSet
```

## Fleet-Wide Sweep

```powershell
$domainControllers = (Get-ADDomainController -Filter *).HostName

# Incident sweep for Golden Ticket USE — identical query to
# Mimikatz/kerberos (Golden-Silver Ticket)/05 - Detection and Hunting.md's Fleet-Wide
# Sweep, unmodified — it doesn't distinguish forging tool
$incidentResults = Invoke-Command -ComputerName $domainControllers -ScriptBlock {
  $tgs = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 1000 -ErrorAction SilentlyContinue
  $tgt = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768} -MaxEvents 1000 -ErrorAction SilentlyContinue
  $tgtAccounts = $tgt | ForEach-Object { $_.Properties[0].Value } | Sort-Object -Unique
  $tgs | Where-Object { $tgtAccounts -notcontains $_.Properties[0].Value } |
    Select-Object @{n='DC';e={$env:COMPUTERNAME}}, TimeCreated, @{n='Account';e={$_.Properties[0].Value}}
} -ErrorAction SilentlyContinue

# Posture sweep — krbtgt rotation age, same value as the Mimikatz note's equivalent
[PSCustomObject]@{
  KrbtgtPasswordLastSet = (Get-ADUser krbtgt -Properties PasswordLastSet).PasswordLastSet
  KrbtgtAgeInDays        = ((Get-Date) - (Get-ADUser krbtgt -Properties PasswordLastSet).PasswordLastSet).Days
}
```

## Remediation

**Capture evidence before acting.** The credential material this tool exploits was already stolen by whatever technique obtained the krbtgt/service key in the first place (realistically `secretsdump.py -just-dc-user krbtgt`, `01 - Overview.md`/`02 - Hands-On Use Cases.md`) — remediation here is about cutting off continued use of the forged ticket(s), not undoing a read that already happened.

1. **Determine blast radius** — identical Golden-vs-Silver scoping logic as `Mimikatz/kerberos (Golden-Silver Ticket)/05 - Detection and Hunting.md`'s Remediation section: a Golden Ticket (krbtgt-derived) is a full-domain-compromise assumption; a Silver Ticket is bounded to the one service the key belongs to. **Not re-derived — apply that guidance directly.**

2. **Rotate krbtgt TWICE, separated by replication convergence time**, to fully invalidate every outstanding forged ticket regardless of when it was created or how long it claims to be valid for — a single rotation is **not** sufficient, because AD's key-history depth (retaining the previous key) means a stale key can still validate old tickets until the second rotation pushes it out of history entirely. **Same underlying requirement documented in `Mimikatz/kerberos (Golden-Silver Ticket)/05 - Detection and Hunting.md` and `Mimikatz/lsadump (DCSync)/05 - Detection and Hunting.md` — this is not a `ticketer.py`-specific mechanic, it's a property of krbtgt's key-history depth regardless of which tool forged the ticket.**

3. **For Silver Ticket:** rotate the specific service/computer account's password:
   ```powershell
   Set-ADAccountPassword -Identity "svc-mssql" -Reset
   ```

4. **Terminate any live sessions authenticated via the forged ticket** on every target host it was used against — identified from `04 - Target Evidence.md`'s "Evidence of Using the Forged Ticket" section (the `-k`-authenticated sessions on whichever Impacket tools consumed the `.ccache`), since DC-side evidence alone won't surface a Silver Ticket's targets at all, and won't surface *which specific Linux host or operator* used a Golden Ticket either — only that it was used, and against what.

**Close the underlying exposure, not just this incident:**
- **Rotate krbtgt on a regular schedule**, deploy Microsoft Defender for Identity, build target-application-layer behavioral baselines, enable full PAC validation where the performance cost is acceptable, and minimize/audit `DS-Replication-Get-Changes-All` holders — every one of these is already covered in depth in `Mimikatz/kerberos (Golden-Silver Ticket)/05 - Detection and Hunting.md`'s closing bullets and applies identically here, since none of it is specific to which tool did the forging. **Not re-derived.**
- **`ticketer.py`-specific addition:** if `-request`/`-impersonate` usage is suspected or confirmed, review authentication logging for the specific low-privileged `-user` account used as the template — that account's credentials were necessarily known to the operator (a password or NTLM hash was supplied on the command line, `03 - Source Evidence.md`), meaning **it is itself compromised** and needs its own credential rotation independent of the krbtgt/service-account rotation above. This is easy to miss because the account is, by design, not the identity the final forged ticket claims to be.
