# Domain Credential Compromise (DCSync and NTDS.dit Theft) Playbook

**Scope note before anything else:** this playbook is deliberately narrow. [`23 - Special Services/Kerberos Ticket Abuse Investigation`](<../23 - Special Services/Kerberos Ticket Abuse Investigation.md>) already gives Golden Ticket, Silver Ticket, Kerberoasting, AS-REP Roasting, Pass-the-Ticket, and delegation abuse a full step-by-step investigative workflow — that ground is not re-plowed here. [`05b - Active Directory & Domain Forensic Artifacts`](<../05b - Active Directory & Domain Forensic Artifacts.md#dcsync--replication-abuse>) owns the DCSync detection signature (event 4662), and [`23 - Special Services/Domain Controller — Role-Specific Forensics`](<Domain Controller — Role-Specific Forensics.md#step-7--what-ntdsad-database-dumping-looks-like-on-the-host-itself>) owns the on-host NTDS.dit-extraction detection tree (the `ntdsutil`/`vssadmin` process-context decision tree). What none of those three notes stitch together is the **response** once either vector is confirmed — scoping the blast radius, sequencing the credential reset, and hunting for actual downstream use. That's this playbook's entire job.

> 🔴 **DCSync and NTDS.dit theft are the two paths to the same outcome — the domain's entire credential material, including the krbtgt key — and neither path leaves you a reliable way to know exactly which accounts' secrets were actually taken.** A DCSync request can target one account or silently be re-run against every account the requester's rights allow; a raw `ntds.dit` extraction hands over literally everything at once. Once either is confirmed, the only defensible posture is to treat every domain secret — not just the account or object you happened to catch the request for — as compromised. Scoping this incident narrower than "the whole domain" is usually wishful thinking, not evidence-based analysis.

## Contents

- [Attack Chain](#attack-chain)
- [Quick Triage](#quick-triage)
- [Confirm and Scope](#confirm-and-scope)
- [Timeline](#timeline)
- [Eradication](#eradication)
- [Credential Reset](#credential-reset)
- [Fleet Hunt](#fleet-hunt)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

## Attack Chain

Two distinct paths converge on the same outcome:

**Path A — DCSync (remote, no DC disk/memory access needed):** an attacker obtains an account holding (or is granted, often through over-delegation) the AD extended rights **Replicating Directory Changes** and **Replicating Directory Changes All** — normally held only by DCs, Domain/Enterprise Admins, and a handful of built-in service accounts such as Azure AD Connect/Entra Connect's sync account — then issues an MS-DRSR replication request from any host with network reach to a DC. The DC, having no way to distinguish this from a legitimate peer-DC replication request, dutifully hands back the requested secrets, most valuably the **krbtgt** account's key or a Domain/Enterprise Admin's NT hash.

**Path B — NTDS.dit theft (on-host, requires DC access):** an attacker who has gained code execution or an interactive session on a Domain Controller itself extracts the AD database directly — typically via a shadow copy (`vssadmin`/`ntdsutil "ifm"`) followed by offline parsing (`secretsdump.py`, `ntdsutil`, or equivalent) — bypassing the replication-rights model entirely by just reading the file.

Either path yields the same prize: every account's NT hash, most critically **krbtgt**, which enables forging a valid-looking TGT for any identity, domain-wide, indefinitely — until specifically remediated (see Credential Reset below). From here the attacker has effectively unlimited impersonation capability that produces no anomalous logon telemetry of its own, which is precisely what makes this the highest-severity class of AD compromise this repo covers.

## Quick Triage

Run both checks in parallel — either can be the entry point, and a sophisticated operator may have attempted both.

```powershell
# Path A: 4662 replication-GUID check sourced from anything that isn't a DC (05b's signature, full mechanics there)
$dcs = (Get-ADDomainController -Filter *).Name
Get-WinEvent -ComputerName (Get-ADDomainController).HostName -FilterHashtable @{LogName='Security';Id=4662} |
    Where-Object { $_.Message -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' } |
    Where-Object { ($_.Properties[1].Value -replace '\$$','') -notin $dcs }

# Path B: ntdsutil/vssadmin execution on any DC, outside a documented backup window (23/DC-role's decision tree)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 500 |
    Where-Object { $_.Message -match 'ntdsutil\.exe|vssadmin\.exe' }
```

## Confirm and Scope

1. **Confirm which path (or both).** Path A confirmation is the non-DC-sourced 4662 event itself (05b). Path B confirmation walks 23/DC-role's full process-context decision tree — parent process, account context, command-line arguments (`ifm`/`create full`), and output destination (a UNC share, removable media, or a cloud-sync folder is the high-concern branch).
2. **Do not try to scope this down to "only these accounts" from the DCSync event alone.** The MS-DRSR protocol's replication rights are evaluated at the domain naming-context level, not per-object — the 4662 event confirms *that* a replication request was made and by whom, but does not reliably tell you *which* accounts' secrets were actually returned in the response. The same is true for a raw `ntds.dit` pull: the whole database was read, full stop.
3. **Prioritize which accounts to actually investigate for follow-on misuse**, even while treating the whole domain as exposed for reset purposes: **krbtgt** first (enables Golden Ticket forging domain-wide), then Domain/Enterprise Admins, then any account with cross-domain trust significance if SID history is a factor (05b's Domain Trust and SID History Abuse section).
4. **Identify the abused rights grant or access path** — was a specific ACE over-delegated (check via 05b's Hunt Evil DCSync-rights query), or was a legitimately-privileged account (Domain Admin, or the Azure AD Connect sync account specifically) itself compromised first? This determines what needs revoking in Eradication, separately from the credential reset itself.

## Timeline

```powershell
# Path A: the 4662 event's own timestamp is the replication-request moment
# Path B: bracket via the ntdsutil/vssadmin process-creation timestamp AND the shadow-copy creation timestamp
vssadmin list shadows

# Corroborate with repadmin's per-attribute metadata (05b) if the attacker also modified any object
# around the same window - establishes ordering independent of Security-log retention/rollover
repadmin /showobjmeta <DC_FQDN> "CN=krbtgt,CN=Users,DC=<domain>,DC=com"
```

Bracket the case as: the confirmed replication request or `ntdsutil`/shadow-copy timestamp → first post-compromise ticket-usage discontinuity (23's krbtgt-reset-boundary technique, run retroactively against the *compromise* timestamp rather than a reset timestamp, to see if Golden Ticket usage was already happening) → any subsequent lateral movement using the dumped material (Fleet Hunt below).

## Eradication

```powershell
# 1. Revoke the specific over-delegated ACE if that was the access path (confirm nothing legitimate
#    depends on it first - Azure AD Connect's sync account legitimately needs these rights)
# Use dsacls or ADUC's Security tab on the domain object to remove the Replicating Directory Changes /
# Replicating Directory Changes All grant from the abused principal

# 2. If a privileged account was compromised rather than a rights grant abused, disable it immediately
Disable-ADAccount -Identity '<compromised_admin_account>'

# 3. Path B only: contain the DC itself - this is NOT a routine "isolate the host" call (note 21's
#    DC-specific containment nuance applies); kill the attacker's active session/process first,
#    then work network containment carefully given the DC's role in the domain's own functioning
Get-Process | Where-Object { $_.Path -match '<attacker_tool_path>' } | Stop-Process -Force
```

## Credential Reset

**This is the section this playbook exists to sequence — everything above was about confirming you need to do this and how far it reaches.**

1. **Reset krbtgt — twice, with replication convergence between resets.** This is [`21 - Remediation and Containment`](<../21 - Remediation and Containment.md#the-krbtgt-double-reset>)'s own guidance and command; not re-derived here. A single reset is explicitly insufficient (the immediately-previous key remains valid for a compatibility window) — confirm the second reset actually completed and converged across every DC before considering krbtgt remediated.
2. **Rotate every domain account's password, not just the ones you have direct evidence were misused.** Per the Confirm and Scope reasoning above, neither DCSync nor an `ntds.dit` pull gives you a reliable "only these accounts" boundary — practically sequence this as Domain/Enterprise Admins and other Tier-0 accounts first, then service accounts, then the general user population, rather than attempting to prove exposure account-by-account first.
3. **Reset the DSRM (Directory Services Restore Mode) password on every Domain Controller** — an `ntds.dit`-level compromise (Path B) exposes this too, and it's easy to overlook since it's rarely touched outside a DC's initial promotion.
4. **If the abused account was the Azure AD Connect/Entra Connect sync account specifically**, rotate its credential and review exactly which rights it holds — this account legitimately needs DCSync rights to function, which is exactly why it's such a high-value target; confirm the rights themselves haven't been broadened beyond what sync actually requires.
5. **Re-verify after rotation**, the same way 21's remediation-verification principle applies elsewhere: confirm the new krbtgt key is actually in use domain-wide (no lingering Golden Ticket activity per the Fleet Hunt below) before considering this closed.

## Fleet Hunt

Because the exposure is effectively domain-wide, the fleet hunt here is about detecting **actual use** of the compromised material, not further scoping who else might be affected.

```powershell
# Golden Ticket discontinuity check, run against the compromise timestamp (not just a reset boundary) -
# full technique owned by 23's Step 3
$compromiseTime = '<confirmed-DCSync-or-ntds.dit-timestamp>'
# 4769 activity for any account with no corresponding fresh 4768 after $compromiseTime is the tell

# Anomalous authentication from any Tier-0 account (Domain/Enterprise Admin, krbtgt-adjacent service
# accounts) from an unfamiliar source, fleet-wide, following the compromise window (05b, 12)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4769} -MaxEvents 5000 |
    Where-Object { $_.TimeCreated -gt $compromiseTime -and $_.Message -match '<tier0_account_name>' }

# Confirm the abused DCSync rights grant hasn't reappeared or been re-added elsewhere
Get-Acl "AD:\<DomainDN>" | Select-Object -ExpandProperty Access | Where-Object { $_.ObjectType -match '1131f6aa|1131f6ad' }
```

## Correlate With

| To go deeper on… | Open |
|---|---|
| DCSync mechanics, the 4662 replication-GUID signature, DCSync-rights enumeration | [`05b - Active Directory & Domain Forensic Artifacts`](<../05b - Active Directory & Domain Forensic Artifacts.md#dcsync--replication-abuse>) |
| Golden Ticket / Silver Ticket / Kerberoasting / Pass-the-Ticket full investigative workflow, once downstream ticket abuse is suspected | [`23 - Special Services/Kerberos Ticket Abuse Investigation`](<../23 - Special Services/Kerberos Ticket Abuse Investigation.md>) |
| On-host `ntdsutil`/`vssadmin`/shadow-copy NTDS.dit-extraction decision tree | [`23 - Special Services/Domain Controller — Role-Specific Forensics`](<Domain Controller — Role-Specific Forensics.md#step-7--what-ntdsad-database-dumping-looks-like-on-the-host-itself>) |
| krbtgt double-reset command and remediation guidance in full | [`21 - Remediation and Containment`](<../21 - Remediation and Containment.md>) |
| What downstream lateral movement with dumped hashes/tickets looks like | [`12 - Lateral Movement`](<../12 - Lateral Movement.md#pass-the-hash--pass-the-ticket--the-credential-theft-angle>) |
| AD replication metadata for corroborating exactly when an object was touched | [`05b`](<../05b - Active Directory & Domain Forensic Artifacts.md#ad-replication-metadata-for-timeline-corroboration>) |

## Red Flags

| 🔴 Finding | Meaning |
|---|---|
| 4662 with `DS-Replication-Get-Changes`/`-All` GUIDs, sourced from anything that isn't a DC | DCSync — near-certain credential-replication abuse |
| `ntdsutil`/`vssadmin` execution on a DC outside a documented backup window, especially with `ifm`/`create full` and a non-standard output path | Active NTDS.dit theft in progress |
| Either finding, with no reliable way to bound which specific accounts were exposed | The expected case, not a scoping failure — proceed straight to domain-wide credential reset |
| krbtgt reset performed only once following a confirmed compromise | Insufficient per the double-reset requirement — previously-forged tickets remain valid |
| 4769 activity continuing uninterrupted across the confirmed compromise timestamp with no fresh 4768 | Golden Ticket already in active use, forged from the stolen krbtgt key |
| Azure AD Connect/Entra Connect sync account identified as the abused principal | A legitimately-necessary DCSync grant turned into the highest-value single account in the domain — rotate and review its rights specifically |
| DSRM password left unrotated after a confirmed `ntds.dit`-level compromise | An overlooked credential that the same compromise already exposed |

## Resources

- MITRE ATT&CK **T1003.006** (OS Credential Dumping: DCSync) — https://attack.mitre.org/techniques/T1003/006/
- MITRE ATT&CK **T1003.003** (OS Credential Dumping: NTDS) — https://attack.mitre.org/techniques/T1003/003/
- MITRE ATT&CK **T1558.001** (Steal or Forge Kerberos Tickets: Golden Ticket) — https://attack.mitre.org/techniques/T1558/001/
- Microsoft Learn — resetting the KRBTGT account password/keys (double-reset guidance): https://learn.microsoft.com/windows-server/security/kerberos/manage-kerberos-tickets
