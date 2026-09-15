# AdFind — Hands-On Use Cases

Every scenario below is a variation on the same LDAP bind/base/filter/scope mechanism documented in `01 - Overview.md`, expressed either as a hand-built `-b`/`-f` filter or a built-in `-sc` shortcut. Real-world command lines below are drawn from published incident reporting (The DFIR Report, CISA #StopRansomware advisories, Microsoft's own Nobelium/SolarWinds hunting guidance) wherever a citation is given — everything else is a direct, source-verified application of the switches documented in `01`.

## Contents
- [Bulk Domain-User Enumeration](#bulk-domain-user-enumeration)
- [Bulk Computer-Object Enumeration](#bulk-computer-object-enumeration)
- [Domain and Privileged-Group Membership Mapping](#domain-and-privileged-group-membership-mapping)
- [Domain Trust Enumeration](#domain-trust-enumeration)
- [OU Structure Mapping](#ou-structure-mapping)
- [Subnet and Site Enumeration](#subnet-and-site-enumeration)
- [GPO Enumeration](#gpo-enumeration)
- [Finding Accounts With Weak Authentication Settings](#finding-accounts-with-weak-authentication-settings)
- [SPN Enumeration — Kerberoasting Precursor](#spn-enumeration--kerberoasting-precursor)
- [Domain Controller and Forest Topology Enumeration](#domain-controller-and-forest-topology-enumeration)
- [One-Liner `-sc` Shortcuts vs. Hand-Built Filters](#one-liner--sc-shortcuts-vs-hand-built-filters)
- [Alternate-Credential Enumeration](#alternate-credential-enumeration)
- [Global Catalog Forest-Wide Sweeps](#global-catalog-forest-wide-sweeps)
- [CSV Bulk Export for Offline Analysis](#csv-bulk-export-for-offline-analysis)
- [Chained Workflow — the Classic Ransomware-Precursor Recon Batch](#chained-workflow--the-classic-ransomware-precursor-recon-batch)

---

## Bulk Domain-User Enumeration

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/) (Account Discovery: Domain Account)

```
AdFind.exe -f "(objectcategory=person)" > ad_users.txt
```

Returns every person object under the default domain naming context with no scoping filter beyond `objectCategory`. This exact filter string, output to a file named `ad_users.txt`, is a direct match to the batch-file pattern documented in Trickbot/Ryuk-linked intrusions (The DFIR Report, "AdFind Recon," 2020) — one of the most consistently observed AdFind invocations across ransomware precursor activity.

## Bulk Computer-Object Enumeration

**MITRE ATT&CK:** [T1018](https://attack.mitre.org/techniques/T1018/) (Remote System Discovery)

```
AdFind.exe -f "objectcategory=computer" cn createTimeStamp > ad_computers.txt
```

Every computer object in the domain, with just `cn` and `createTimeStamp` pulled back — enough to build a target list and a rough age/joined-date picture without the noise of every replicated attribute. Same `ad_computers.txt` naming convention seen in the same Trickbot/Ryuk batch-script pattern.

## Domain and Privileged-Group Membership Mapping

**MITRE ATT&CK:** [T1069.002](https://attack.mitre.org/techniques/T1069/002/) (Permission Groups Discovery: Domain Groups)

```
# Every group object in the domain
AdFind.exe -f "(objectcategory=group)" > ad_group.txt

# Membership of a specific group (e.g. Domain Admins)
AdFind.exe -b "CN=Domain Admins,CN=Users,DC=corp,DC=local" member

# Recursive/nested membership — the :1.2.840.113556.1.4.1941: matching-rule OID
# walks the full nested-group chain, not just direct members
AdFind.exe -b "DC=corp,DC=local" -bit -f "memberof:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=corp,DC=local" sAMAccountName -nodn

# Accounts flagged adminCount=1 (AdminSDHolder-protected — current and
# former privileged-group members)
AdFind.exe -default -f "(&(|(&(objectCategory=person)(objectClass=user))(objectCategory=group))(adminCount=1))" -dn
```

The `adminCount=1` query is a particularly efficient shortcut: AdminSDHolder stamps this attribute on any account that has ever been a member of a protected group (Domain Admins, Enterprise Admins, Schema Admins, etc.), so it surfaces the privileged-account population in one query without having to walk every protected group's membership individually — and it also catches accounts that were *removed* from a privileged group but never had the flag cleared.

## Domain Trust Enumeration

**MITRE ATT&CK:** [T1482](https://attack.mitre.org/techniques/T1482/) (Domain Trust Discovery)

```
AdFind.exe -sc trustdmp > ad_trustdmp.txt
```

`trustdmp` is one of AdFind's built-in `-sc` shortcuts — it queries the `trustedDomain` objects under the Configuration partition's System container and dumps trust direction, type, and attributes for every trust relationship the domain participates in. This single command is enough to plan cross-domain/cross-forest lateral movement and is explicitly called out in MITRE's own S0552 write-up as one of AdFind's core documented capabilities.

## OU Structure Mapping

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/) (Account Discovery: Domain Account) — OU structure directly informs where privileged/high-value accounts and computers are administratively grouped

```
# All OUs in the domain
AdFind.exe -default -f "objectcategory=organizationalUnit" -dn

# Every object inside one specific OU, one level down
AdFind.exe -b "OU=Finance,DC=corp,DC=local" -s onelevel -dn
```

Mapping OU structure gives an operator the AD administrative boundaries at a glance — which OUs correspond to which business unit or admin tier, useful for both targeting (where are the finance/HR/IT-admin accounts) and for understanding which GPOs (see below) apply to which population.

## Subnet and Site Enumeration

**MITRE ATT&CK:** [T1016](https://attack.mitre.org/techniques/T1016/) (System Network Configuration Discovery)

```
AdFind.exe -subnets -f "(objectCategory=subnet)" > ad_subnets.txt
```

`-subnets` resolves the base DN to the Sites container's Subnets object automatically. The result maps every IP subnet AD knows about to its associated site — real network-topology intelligence pulled straight from the directory rather than requiring an active network scan, and a good example of why AdFind sweeps are often run *before* a noisier tool like an IP scanner: the subnet list tells the operator what ranges are worth scanning in the first place.

## GPO Enumeration

**MITRE ATT&CK:** [T1615](https://attack.mitre.org/techniques/T1615/) (Group Policy Discovery)

```
AdFind.exe -sc gpodmp > ad_gpodmp.txt
```

`gpodmp` dumps Group Policy Object metadata from the directory (GUID, display name, linked OUs) — informs an operator which OUs/computers a given policy actually applies to, relevant both for understanding existing hardening (AppLocker, Defender exclusions pushed via GPO) and for evaluating GPO-based lateral-movement or persistence options later in the intrusion.

## Finding Accounts With Weak Authentication Settings

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/) (Account Discovery: Domain Account) — this discovery directly informs a follow-on [T1110](https://attack.mitre.org/techniques/T1110/) (Brute Force) or [T1078](https://attack.mitre.org/techniques/T1078/) (Valid Accounts) attempt

```
# Built-in shortcut for accounts with the PASSWD_NOTREQD UAC flag set
AdFind.exe -sc computers_pwdnotreqd > ad_pwdnotreqd.txt

# The same query hand-built as a raw filter — PASSWD_NOTREQD is UAC bit
# 0x0020 (decimal 32); the :1.2.840.113556.1.4.803: OID is the bitwise-AND
# LDAP matching rule (or use -bit and write :AND:= instead)
AdFind.exe -b "DC=corp,DC=local" -f "(&(objectcategory=person)(objectclass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" sAMAccountName -nodn

# Accounts with an expired password
AdFind.exe -s subtree -b "DC=corp,DC=local" -f "userAccountControl:1.2.840.113556.1.4.803:=8388608" -dn

# Disabled accounts (still worth knowing — sometimes still usable via a
# stale Kerberos ticket, and useful for excluding noise from other results)
AdFind.exe -default -bit -f "userAccountControl:AND:=2"
```

`computers_pwdnotreqd` (spelled exactly this way in AdFind's own `-sc` list — note some third-party detection write-ups render it `computers_pwnotreqd`, missing the second "d," which does **not** match the tool's real shortcut name) is the fast path to any account whose password policy has been explicitly weakened — a direct password-guessing/spraying target list generated in a single command.

## SPN Enumeration — Kerberoasting Precursor

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/) (Account Discovery: Domain Account) for the discovery step itself; feeds directly into [T1558.003](https://attack.mitre.org/techniques/T1558/003/) (Kerberoasting)

```
AdFind.exe -b "DC=corp,DC=local" -f "(servicePrincipalName=*)" sAMAccountName servicePrincipalName > ad_spns.txt
```

This is functionally the same discovery step as `setspn -Q */*` (see `../LOLBins/setspn/`) or Impacket's `GetUserSPNs.py -request` without the `-request` flag — AdFind only **lists** SPN-bearing accounts, it has no built-in capability to request a TGS or extract a crackable hash. In practice this query is a triage step: the operator runs AdFind first to see what's out there (which accounts, whether any look like high-value service accounts by naming convention), then hands the target list to a Kerberoasting-capable tool for the actual ticket request/crack. See `../LOLBins/setspn/02 - Hands-On Use Cases.md` for the write-capable variant of SPN enumeration AdFind cannot do (`setspn -S` can add a new SPN to a writable account — AdFind has no write capability of any kind).

## Domain Controller and Forest Topology Enumeration

**MITRE ATT&CK:** [T1018](https://attack.mitre.org/techniques/T1018/) (Remote System Discovery), [T1482](https://attack.mitre.org/techniques/T1482/) (Domain Trust Discovery) for the forest-wide variants

```
AdFind.exe -sc dclist       > ad_dclist.txt      # every DC in the domain
AdFind.exe -sc dcmodes      > ad_dcmodes.txt      # domain/forest functional levels
AdFind.exe -sc fsmo         > ad_fsmo.txt         # FSMO role holders
AdFind.exe -sc domainlist   > ad_domainlist.txt   # every domain in the forest
AdFind.exe -sc adinfo                             # summary AD environment info (RootDSE-derived)
```

A fast topology pass — how many DCs, what functional level (bearing on which AD-relative attacks are even possible), which server holds which FSMO role (a high-value target for certain attacks), and how many domains exist in the forest. This is frequently one of the very first things run after landing on a domain-joined host, before any of the bulk object dumps above.

## One-Liner `-sc` Shortcuts vs. Hand-Built Filters

**MITRE ATT&CK:** Not a distinct technique — a syntax/efficiency choice layered on whichever discovery ID the underlying query maps to

```
# Shortcut form
AdFind.exe -sc trustdmp

# Equivalent hand-built form (illustrative — the shortcut also sets
# additional attribute/output defaults beyond just the base+filter shown
# here, which is the whole point of using it instead)
AdFind.exe -config -f "(objectclass=trustedDomain)"
```

The `-sc` shortcuts exist because a large fraction of real AD-recon needs are the same handful of queries every time — an operator who has them memorized (or scripted) can run a full recon pass in a handful of one-word commands. From a detection standpoint this matters directly: the shortcut names themselves (`trustdmp`, `dclist`, `computers_pwdnotreqd`, …) are just as distinctive a command-line string as a raw filter, and multiple published detection analytics (Elastic, Splunk, Microsoft Sentinel/Defender hunting queries — see `05 - Detection and Hunting.md`) match on the shortcut names directly for exactly this reason.

## Alternate-Credential Enumeration

**MITRE ATT&CK:** [T1078](https://attack.mitre.org/techniques/T1078/) (Valid Accounts) for the credential-use aspect

```
AdFind.exe -h dc01.corp.local -u CORP\svc-backup -up "P@ssw0rd!" -f "(objectcategory=person)"

# Prompt interactively instead of putting the password on the command
# line / into shell history
AdFind.exe -h dc01.corp.local -u CORP\svc-backup -up *

# Obfuscate the password for reuse in a saved script (NOT strong
# encryption — a locally reversible encoding only)
AdFind.exe -encpwd "P@ssw0rd!"
# -> ENCPWD:EhfEeD0ZV
AdFind.exe -h dc01.corp.local -u CORP\svc-backup -up ENCPWD:EhfEeD0ZV -f "(objectcategory=person)"
```

**Worth being precise about what this is not:** unlike Impacket's `-hashes` option or Mimikatz's pass-the-ticket workflow, AdFind's `-u`/`-up` require a **real password** (cleartext, interactively prompted, or the `ENCPWD:` obfuscated form) — there is no NTLM-hash or Kerberos-ticket injection switch documented anywhere in the tool. An operator who has only a hash (no cracked plaintext) cannot use `-u`/`-up` directly; they either crack the hash first, or simply omit `-u`/`-up` entirely and let AdFind ride the current process's logon session — which is itself compatible with an already-obtained Kerberos ticket in the session's ticket cache (pass-the-ticket), since that's just the ambient token AdFind's default bind uses.

## Global Catalog Forest-Wide Sweeps

**MITRE ATT&CK:** [T1482](https://attack.mitre.org/techniques/T1482/) (Domain Trust Discovery) / [T1087.002](https://attack.mitre.org/techniques/T1087/002/) depending on what's queried

```
# Forest-wide user search from a single GC query instead of querying
# every domain individually
AdFind.exe -gc -b "" -f "(&(objectcategory=person)(objectclass=user))" sAMAccountName mail -csv > all_forest_users.csv
```

An empty `-b ""` against a GC server searches from the forest root — combined with `-gc`'s partial-attribute-set replica, this is the fastest way to get a single forest-wide object list without visiting each domain's own DC in turn. Trade-off: only GC-replicated attributes are available in the result set; a follow-up non-GC query against a specific hit's own domain is needed for full attribute detail.

## CSV Bulk Export for Offline Analysis

**MITRE ATT&CK:** Not a distinct technique — an output-format choice layered on whichever query produced the data

```
AdFind.exe -b "DC=corp,DC=local" -f "(objectcategory=person)" sAMAccountName displayName mail department -csv > ad_users.csv
```

`-csv` is the format of choice when the operator's next step is opening the result in Excel for manual triage, or feeding it into a second script/tool — a direct, deliberate choice over the default label-per-line console output, which is easier for a human to read live but far less convenient for bulk offline analysis.

## Chained Workflow — the Classic Ransomware-Precursor Recon Batch

**MITRE ATT&CK:** Composite of every ID above — this is the realistic end-to-end pattern documented across Trickbot/Ryuk, Maze, FIN6, and CISA's Akira/Play advisories

```batch
adfind.exe -f "(objectcategory=person)"           > ad_users.txt
adfind.exe -f "objectcategory=computer"           > ad_computers.txt
adfind.exe -f "(objectcategory=organizationalUnit)" > ad_ous.txt
adfind.exe -subnets -f "(objectCategory=subnet)"  > ad_subnets.txt
adfind.exe -f "(objectcategory=group)"            > ad_group.txt
adfind.exe -sc trustdmp                           > ad_trustdmp.txt
adfind.exe -sc computers_pwdnotreqd               > ad_pwdnotreqd.txt
```

This exact shape — a batch file running a fixed sequence of AdFind invocations, output redirected to a set of consistently-named `.txt` files — is the single most widely documented AdFind usage pattern in ransomware intrusion reporting (The DFIR Report's 2020 "AdFind Recon" case study; CISA's #StopRansomware advisories for Akira and Play both name AdFind explicitly as the domain-enumeration tool used before further lateral movement and, ultimately, ransomware deployment). The output files are rarely the end goal themselves — they're read (locally, or exfiltrated) to plan the next several steps: which accounts to target for Kerberoasting or credential theft, which trusts open up additional domains, which subnets are worth scanning next. See `../BloodHound/` for the graph-based evolution of this same "map the domain before acting" step, and `../LOLBins/setspn/` for the write-capable SPN-enumeration alternative AdFind's own read-only SPN listing (above) cannot perform.
