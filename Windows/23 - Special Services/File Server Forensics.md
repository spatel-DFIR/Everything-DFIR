# File Server Forensics

A file server's job is to sit still and hand out files over SMB — which is exactly why it becomes the scene of the crime in two of the most common incident types in this repo's Threat Landscape: an attacker using it as a staging/recon target before mass encryption, and an attacker using it as the last hop before exfiltration. This note is written for the moment an analyst opens a remote session (or a triage collection) against a Windows File Server — standalone, clustered, or fronted by a DFS namespace — and needs to work the box top-to-bottom: what's shared, who's connected, what was touched, and whether the audit trail needed to answer those questions was even turned on.

This is the first note in the **Special Services** family — role-specific server forensics, distinct from the general host-artifact notes elsewhere in this repo that apply to any Windows machine regardless of role. Everything general-purpose (NTFS timestamps, execution evidence, event log mechanics) still applies to a file server; this note covers only what's specific to the file-server *role*: SMB share structure, DFS resolution, share-level and object-level auditing, and the access-pattern hunts that matter on a host whose entire purpose is being touched by many accounts, constantly.

> 🔴 **On a file server, absence of evidence is disproportionately likely to be evidence of absent auditing, not evidence of absent activity.** Every high-value event this note relies on — 5140, 5145, 4663, 4670, 5142 — sits behind non-default audit policy, and one of them (4663) sits behind a *second*, independently-configured requirement on top of that (§4). Confirm the audit trail was actually capturing before reading a quiet log as "nothing happened here."

**Orientation — the shape of a top-to-bottom pass:**

```
1. Enumerate shares (custom vs admin/hidden, share vs NTFS permissions)
        │
2. Resolve DFS logical paths to physical targets, if DFS is in play
        │
3. Verify object-access auditing is actually configured (two-part gotcha)
        │
4. Check FSRM, if configured (optional evidence source)
        │
5. Check Shadow Copies for pre-incident file state
        │
6. Live triage: who's connected right now, what's open right now
        │
7-12. Hunt: recon volume, encryption-in-progress, off-hours anomalies,
      honeytokens, permission-change abuse, rogue share creation
```

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Investigation Workflow](#investigation-workflow)
  - [1. Enumerate the Shares](#1-enumerate-the-shares)
  - [2. Resolve DFS Namespace Paths, If Present](#2-resolve-dfs-namespace-paths-if-present)
  - [3. Verify Object-Access Auditing Is Actually On](#3-verify-object-access-auditing-is-actually-on)
  - [4. File Server Resource Manager (FSRM), If Configured](#4-file-server-resource-manager-fsrm-if-configured)
  - [5. Shadow Copies — Recovering What a File Looked Like Before](#5-shadow-copies--recovering-what-a-file-looked-like-before)
  - [6. Live Triage — Current Sessions and Open Files](#6-live-triage--current-sessions-and-open-files)
  - [7. Hunt — Mass File-Access / Enumeration (Pre-Encryption Recon)](#7-hunt--mass-file-access--enumeration-pre-encryption-recon)
  - [8. Hunt — Mass Rename / Extension-Change (Encryption in Progress)](#8-hunt--mass-rename--extension-change-encryption-in-progress)
  - [9. Hunt — Off-Hours Access-Volume Anomalies](#9-hunt--off-hours-access-volume-anomalies)
  - [10. Honeytoken / Canary Files](#10-honeytoken--canary-files)
  - [11. Hunt — Permission-Change Auditing (4670)](#11-hunt--permission-change-auditing-4670)
  - [12. Hunt — Unauthorized New Share Creation](#12-hunt--unauthorized-new-share-creation)
- [Investigative Sequence Summary](#investigative-sequence-summary)
- [Red Flags](#red-flags)
- [MITRE ATT&CK Techniques Covered](#mitre-attck-techniques-covered)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage for a file server mid-incident — no third-party tooling required. Each hint here is expanded to full evidence-chain depth in the numbered workflow below.

```powershell
# Every share on this box, custom and administrative/hidden alike - the starting inventory for everything below
Get-SmbShare | Select-Object Name, Path, Description, ShareState, Special

# Who is connected right now, and how many files/pipes they currently have open - the live "who's in the building" check
Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens, Dialect
Get-SmbOpenFile | Select-Object ClientComputerName, ClientUserName, Path

# Is the auditing this whole note depends on actually turned on - check before trusting a quiet log
auditpol /get /subcategory:"File Share","Detailed File Share","File System"

# 5145 volume by account in the last hour - the pre-encryption recon signature (full threshold logic in §7)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5145; StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue |
    ForEach-Object { if ($_.Message -match 'Account Name:\s*(\S+)') { $Matches[1] } } |
    Group-Object | Sort-Object Count -Descending | Select-Object -First 10

# A burst of writes to one new extension across many files in the shares this server hosts - encryption in progress, right now (full detail in §8)
Get-SmbShare -Special $false | ForEach-Object {
    Get-ChildItem -Path $_.Path -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-15) }
} | Group-Object Extension | Sort-Object Count -Descending | Select-Object -First 20

# New shares created in the last 24h - attacker-staged exfil/foothold share (full detail in §12)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5142; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, @{N='ShareName';E={ if ($_.Message -match 'Share Name:\s*(\S+)') { $Matches[1] } }}

# Shadow copies present right now on this server - the recovery baseline before anyone declares files unrecoverable (full detail in §5)
Get-CimInstance Win32_ShadowCopy | Select-Object ID, VolumeName, InstallDate
```

## Investigation Workflow

### 1. Enumerate the Shares

Start with a complete share inventory before touching anything else — every later step (auditing, DFS, hunts) needs to know what surface actually exists.

```powershell
Get-SmbShare | Select-Object Name, Path, Description, ShareState, ShareType, Special, CurrentUsers
net share
```

`Get-SmbShare` and `net share` both return every share by default, but an analyst has to actively distinguish two very different populations in that output:

| Share type | Naming pattern | Purpose | Investigative weight |
|---|---|---|---|
| **Custom shares** | Whatever the admin named it — `Finance$`, `Public`, `UserHome` | The actual business data this server exists to host | Where the hunts in §7–§12 do most of their work |
| **Administrative/hidden shares** | Trailing `$` — `C$`, `D$`, `ADMIN$`, `IPC$` | Built-in, created automatically on every drive at boot; `ADMIN$` maps to `%SystemRoot%`, `C$`/`D$`/etc. map to drive roots, `IPC$` supports named-pipe communication with no filesystem backing at all | The lateral-movement/remote-execution surface — full evidence chains for `ADMIN$`/`C$` abuse already live in **Lateral Movement (12)** and **Persistence Mechanisms — Services (10)**; don't re-derive that here, but don't overlook it either — a file server is still a Windows host and `ADMIN$` still works against it |

`Get-SmbShare -Special $true` isolates just the administrative population; `-Special $false` isolates just the custom shares — useful for scoping the hunts below to the shares that actually hold business data.

🔴 **The dual-permission model gotcha.** A share sits behind *two* independent permission layers, and effective access is the **intersection**, not the union, of them. This is one of the most common sources of analyst (and admin) confusion on a file server, because it means neither layer alone answers "could this account have read/written that file":

| Layer | Configured via | What it controls | The gotcha |
|---|---|---|---|
| **Share permissions** | Share tab of folder Properties, or `Get-SmbShareAccess` | A coarse allow/deny checked only at the moment of connecting to `\\server\share` | Frequently left at `Everyone: Full Control` in practice, because admins rely on the NTFS layer to do the real access control — meaning share permissions on their own tell you almost nothing about who can actually do what |
| **NTFS (file system) permissions** | Security tab of folder/file Properties, or `Get-Acl` | Fine-grained per-file/per-folder ACLs, enforced on every access regardless of how the object was reached | Applies to local access too, not just share access — but a remote user still has to clear the share layer first to even get a chance to hit this layer |
| **Effective access** | The intersection of the two | The *more restrictive* of {share permission, NTFS permission} wins for any given account and any given action | 🔴 **Check both, always.** A user denied at the NTFS layer is denied even if the share grants Full Control; a user denied at the share layer never even gets a chance to test the NTFS layer. Reasoning from only one layer produces confidently wrong conclusions about what an account could or couldn't have done. |

```powershell
Get-SmbShareAccess -Name "Finance$"                    # Share-layer permissions
Get-Acl -Path "D:\Shares\Finance" | Format-List          # NTFS-layer permissions on the underlying folder
icacls "D:\Shares\Finance"                                # Native equivalent, prints inherited/explicit ACEs inline
```

### 2. Resolve DFS Namespace Paths, If Present

If this server is a **DFS Namespace (DFSN)** target or replication (**DFSR**) partner, the path an attacker (or a user) actually touched, as it appears in a log or a ticket, may be a **logical namespace path** that resolves through to a completely different physical server and share than the one currently in front of you.

🔴 **This is a real investigative trap, not a theoretical one.** A log entry, ticket, or ransom note referencing `\\corp\Public\Finance\report.xlsx` names a DFS *namespace* — `corp\Public` — not necessarily a physical server. Investigating the DFS namespace server itself, or assuming the namespace name is the file server's own hostname, can put an analyst's entire evidence-collection effort against the wrong box.

```
Log/ticket references:  \\corp\Public\Finance\report.xlsx    (DFS logical path)
                                     │
                    Get-DfsnFolderTarget -Path "\\corp\Public\Finance"
                                     │
                                     ▼
        Actual physical target:  \\FS03\FinanceShare$\report.xlsx
        — could be a different server, different share name, different
          drive letter/path entirely than what the logical path implies
```

```powershell
# Enumerate namespace roots this domain/server publishes
Get-DfsnRoot | Select-Object Path, Type, State

# Every logical folder under a given namespace root
Get-DfsnFolder -Path "\\corp.local\Public\*" | Select-Object Path, State

# The resolution step that matters - logical folder to physical target(s), including which is Active vs Offline
Get-DfsnFolderTarget -Path "\\corp.local\Public\Finance" | Select-Object Path, TargetPath, State
```

Native (non-PowerShell) equivalents, useful when working from a live host or a limited toolset:

```
dfsutil /pktinfo                     :: Dumps this client's cached DFS referral (partition knowledge table) entries
dfsutil client property state        :: Shows per-target state (Active/Offline) as this host currently sees it
dfsrdiag replicationstate /rgname:<ReplicationGroup>   :: DFSR-specific — is this member currently replicating, backlogged, or idle
```

If DFSR is in play, also check for **replication backlog** — a large or growing backlog between the touched server and its replication partners changes both how urgently you need to image the *other* member(s) (they may still hold an un-encrypted/un-deleted copy that hasn't replicated yet) and how you interpret timestamps (a file's replicated copy can lag the origin server by minutes to hours depending on backlog).

### 3. Verify Object-Access Auditing Is Actually On

Nearly every hunt in this note reads from Security-log events that are **non-default** and, for one of them, gated by a **second** independent requirement. Confirm the audit trail before trusting — or distrusting — anything it does or doesn't show.

| Event ID | Name | Audit policy subcategory (Object Access) | Also requires a SACL on the specific object? | Verbosity / value |
|---|---|---|---|---|
| **5140** | A network share object was accessed | **Audit File Share** | No — applies automatically to every share once the subcategory is on | Low volume, one event per share connection. The share-level equivalent of a logon event: who connected to which share, from where |
| **5145** | A network share object was checked to see whether the client can be granted the desired access (detailed) | **Audit Detailed File Share** | No — same as 5140, policy-level only | **Very high volume** — one event per file/folder open attempt inside an audited share, but the single highest-value event in this note: it names the specific relative path touched inside the share, the access requested, and whether it was granted or denied. This is what §7 and §9's hunts are built on. |
| **4663** | An attempt was made to access an object | **Audit File System** | 🔴 **Yes** — a SACL must additionally be configured on the specific file(s)/folder(s) of interest | Fires only for objects an admin has explicitly chosen to audit. Highest-fidelity object-level record (paired with 4656, the handle-request event that precedes it), but only exists where someone deliberately set it up |

🔴 **The two-part gotcha, worth its own callout (same shape as the 4697/service-install gap documented in note 10):** 5140 and 5145 need only the audit-policy subcategory enabled — flip the switch and every share starts generating them, no per-object configuration required. **4663 needs both halves**: the "Audit File System" subcategory *and* a SACL explicitly set on the object. Enable the subcategory without ever setting a SACL, and 4663 will never fire for anything — silently, with no error, and no obvious sign in the audit policy itself that the second half was skipped. Do not read a 4663-shaped silence as "nothing touched this file" — check whether a SACL was ever configured on it before drawing that conclusion.

```powershell
# Confirm the audit policy subcategories are actually enabled - the first half of the 4663 gotcha
auditpol /get /subcategory:"File Share","Detailed File Share","File System"

# Confirm a SACL actually exists on a specific object - the second, independently-required half for 4663
(Get-Acl -Path "D:\Shares\Finance\report.xlsx" -Audit).Audit
```

To pull recent 5145 events and shape them into an analyst-usable table (raw `.Message` text is workable but slow to scan across volume), use this PowerShell approach:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5145; StartTime=(Get-Date).AddHours(-6)} -ErrorAction SilentlyContinue | ForEach-Object {
    $m = $_.Message
    [PSCustomObject]@{
        TimeCreated  = $_.TimeCreated
        Account      = if ($m -match 'Account Name:\s*(\S+)') { $Matches[1] }
        Source       = if ($m -match 'Source Address:\s*(\S+)') { $Matches[1] }
        Share        = if ($m -match 'Share Name:\s*(\S+)') { $Matches[1] }
        RelativePath = if ($m -match 'Relative Target Name:\s*(\S+)') { $Matches[1] }
        AccessDenied = $m -match 'Access Reason:.*Denied'
    }
}
```

### 4. File Server Resource Manager (FSRM), If Configured

FSRM is an optional role service under **File and Storage Services** — not every file server has it, but where it's configured it's a genuinely useful additional evidence source that has nothing to do with the Security log. Its two relevant capabilities:

- **File screening** — actively blocks (or passively just logs) attempts to save files matching a defined file group. A curated file group naming common ransomware extensions, configured as an **active** screen, will outright reject the write attempt — a real, if uncommon, proactive control worth checking for. A **passive** screen only logs the attempt without blocking it.
- **Quota management** — storage quotas per folder/volume, with threshold-based notification.

```powershell
Get-FsrmFileScreen | Select-Object Path, Description, Active, Template
Get-FsrmFileGroup | Select-Object Name, IncludePattern           # What's actually in the "blocked extensions" group, if one exists
Get-FsrmQuota | Select-Object Path, Size, Usage, Description
```

FSRM writes its own events to the **Application** log under source `SRMSVC`; the specific event IDs generated vary by scenario (quota threshold crossed vs. file-screen violation vs. report generation) — filter the Application log to that source and read the events directly rather than hunting for one canonical ID. FSRM can also be configured to email an admin/DL automatically on a screening violation — check for that notification configuration and, if present, whoever's mailbox receives it may already have a timestamped alert for the exact incident window.

🔴 Treat FSRM as **optional corroboration, not a required evidence source** — plenty of legitimate file servers never have it configured. Its absence is not itself a finding; its *presence with a triggered violation* is a strong, independent confirmation of exactly the mass-write/extension-change behavior §8 hunts for from the Security-log side.

### 5. Shadow Copies — Recovering What a File Looked Like Before

Volume Shadow Copy Service on a file server answers one narrow, very practical question: **what did this specific file look like before it was encrypted, deleted, or modified?** This section is scoped tightly to that recovery use case — full VSS mechanics, the Copy-on-Write internals, and the anti-forensic/evidence-destruction angle (an attacker running `vssadmin delete shadows` to sabotage recovery) already live in **Anti-Forensics and Evidence Destruction (19)**; go there for that depth, not here.

```powershell
vssadmin list shadows           # Run on the FILE SERVER itself - shadow copies live on the volume hosting the share, not the client
vssadmin list shadowstorage     # Confirms shadow storage wasn't reduced/zeroed - a secondary VSS-tampering signal, full depth in note 19
```

Two practical access paths, specific to a *shared folder* rather than a local volume:

| Method | How | Notes |
|---|---|---|
| **`@GMT-` UNC syntax** | `\\<server>\<share>@GMT-2026.07.18-14.30.00` | Directly addresses a specific shadow-copy snapshot of that share over SMB, no local mount step required — the fastest way to pull a prior version of one specific file off the server remotely. Timestamp is UTC ("GMT" in the syntax, despite the misleading name) |
| **Previous Versions (client-side)** | Right-click the file/folder on the mapped share → Properties → Previous Versions | The end-user-facing equivalent of the same mechanism — useful when walking a user through self-service recovery, or when confirming what a user *could* have seen/recovered themselves before escalating |

```powershell
# List available snapshots for one share, then pull a specific prior version of one file out of it
Get-ChildItem "\\fs03\Finance$@GMT-2026.07.18-14.30.00\report.xlsx"
Copy-Item "\\fs03\Finance$@GMT-2026.07.18-14.30.00\report.xlsx" -Destination "C:\evidence\report_pre-incident.xlsx"
```

For the deletion/anti-forensics angle — confirming *whether* shadow copies were deliberately destroyed, and the detection-evidence chain for that — see **Anti-Forensics and Evidence Destruction (19)**; this note only covers using shadow copies that still exist.

### 6. Live Triage — Current Sessions and Open Files

Fast, live "who's in the building right now" checks — the first thing to run on a server believed to be under active attack, before anything changes.

```powershell
# Every currently connected SMB session - who, from where, how many opens
Get-SmbSession | Select-Object SessionId, ClientComputerName, ClientUserName, NumOpens, Dialect

# Every currently open file/handle on this server, and who holds it
Get-SmbOpenFile | Select-Object ClientComputerName, ClientUserName, Path, ShareRelativePath

# Cross-reference: does one session correspond to an abnormal number of open handles right now
Get-SmbOpenFile | Group-Object ClientUserName | Sort-Object Count -Descending
```

`net use`, `net view`, and share-mapping reconnaissance from the *attacker's* source host are already covered from that angle in **Lateral Movement (12)** — this section is deliberately the mirror image of that: the destination/server-side view of the same connections, live, right now.

### 7. Hunt — Mass File-Access / Enumeration (Pre-Encryption Recon)

One account touching an abnormally large number of distinct files/folders in a short window is a well-documented ransomware **pre-encryption reconnaissance** signature — the operator (or, increasingly, the encryptor's own recon phase) walks the share tree to map out what's there before the encryption pass begins. This is a detection query, not a response workflow — for the full pre-to-post-encryption response sequence once this fires, go straight to the **Ransomware Playbook**.

```powershell
# Aggregate 5145 (detailed share access) by account within a rolling window, threshold-flag anything abnormal
$windowStart = (Get-Date).AddHours(-1)
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5145; StartTime=$windowStart} -ErrorAction SilentlyContinue

$byAccount = $events | ForEach-Object {
    if ($_.Message -match 'Account Name:\s*(\S+)') { $Matches[1] }
} | Group-Object | Sort-Object Count -Descending

# Threshold logic: tune the count against this server's own normal baseline before alerting - a busy shared drive
# has a much higher legitimate baseline than a narrowly-scoped departmental share
$byAccount | Where-Object Count -gt 1000 | Select-Object Name, Count
```

| Signal | Why it matters |
|---|---|
| One account's 5145 count is an outlier against its own historical baseline, not just an absolute number | A service account that normally touches 50,000 files/day behaves differently than a human account that normally touches 200 — baseline per-account, don't use one global threshold across a mixed population |
| The touched paths span many unrelated folders/departments in one short session | Legitimate business use is usually scoped to one or a few functional areas; broad, unscoped traversal across the whole share tree is the recon shape |
| The account is a service/admin account not normally associated with interactive file access | A compromised service account walking the tree is a stronger signal than a normal user doing the same, since service accounts rarely have a legitimate reason for broad manual enumeration |

### 8. Hunt — Mass Rename / Extension-Change (Encryption in Progress)

The in-progress-encryption signature itself: a burst of writes/renames appending a new, previously-unseen extension across many files in a tight time window. This is the file-server-side detection query; **the Ransomware Playbook is the primary resource for what to do once this fires** — full response sequencing (contain vs. capture-first, scope determination, deployment-mechanism investigation, credential/lateral-movement reconstruction) lives there, not here.

```powershell
# Files modified in the last 15 minutes across every custom share this server hosts, grouped by extension -
# a live encryption sweep leaves a tight, abnormal extension spike; same signature the Ransomware Playbook's
# own Hunt Evil checks for host-side, applied here at the share-tree level
Get-SmbShare -Special $false | ForEach-Object {
    Get-ChildItem -Path $_.Path -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-15) }
} | Group-Object Extension | Sort-Object Count -Descending | Select-Object -First 20

# 5145 corroboration: the same account driving a spike of WriteData accesses across many distinct relative paths
# in the same window - pairs the filesystem-timestamp evidence above with an audit-log source and an attributable account
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5145; StartTime=(Get-Date).AddMinutes(-15)} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Accesses:.*WriteData' } |
    ForEach-Object { if ($_.Message -match 'Account Name:\s*(\S+)') { $Matches[1] } } |
    Group-Object | Sort-Object Count -Descending
```

🔴 **Once this fires, stop treating it as a file-server-only problem.** A single account driving a mass-rename spike against this server's shares is very likely a symptom of a fleet-wide deployment event, not an isolated file-server incident — jump to the Ransomware Playbook's scope-determination step immediately rather than working this server in isolation.

### 9. Hunt — Off-Hours Access-Volume Anomalies

The same 5145 aggregation as §7, filtered to outside the account's normal working hours — a distinct signal from raw volume, because it catches lower-and-slower activity (staged exfiltration, careful reconnaissance) that stays under a pure volume threshold but is still anomalous for *when* it happens.

```powershell
# 5145 events outside a defined business-hours window (example: 07:00-19:00 local), grouped by account
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5145; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue

$offHours = $events | Where-Object { $_.TimeCreated.Hour -lt 7 -or $_.TimeCreated.Hour -ge 19 }

$offHours | ForEach-Object { if ($_.Message -match 'Account Name:\s*(\S+)') { $Matches[1] } } |
    Group-Object | Sort-Object Count -Descending | Select-Object -First 20
```

Cross-reference any account that surfaces here against its normal shift pattern/time zone before treating it as a finding — a legitimate off-hours batch job or a genuinely different-time-zone remote employee produces the same shape and is the most common false positive this hunt generates.

### 10. Honeytoken / Canary Files

Worth naming as a **proactive control**, not just a reactive hunting technique: placing a small number of decoy files with enticing names (`Payroll_2026_Q3.xlsx`, `Domain_Admin_Passwords.txt`) inside shares that hold real sensitive data, then auditing access to *only those specific files*. Because a legitimate user has no reason to ever open a file like that, any access at all — a single 4663 (with a SACL configured on just that one file, per §3) or a 5145 detailed-access event against it — is a near-zero-false-positive tripwire, and one of the earliest available signals of an attacker (or an automated recon tool/encryptor) walking the share tree, often firing well before the volume-based hunts in §7 would cross their own threshold.

```powershell
# Confirm a SACL is actually set on a specific canary file - without this, 4663 will never fire for it (§3's gotcha applies here too)
(Get-Acl -Path "D:\Shares\Finance\Payroll_2026_Q3.xlsx" -Audit).Audit

# Any access at all to the canary file, ever - one hit here is a finding worth immediate attention, not a threshold to tune
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Payroll_2026_Q3\.xlsx' }
```

This same idea is available as a commercial/managed product category (canary-file and honeytoken services) if a fully automated, alerting-integrated version is wanted rather than a manually-audited file — naming a specific vendor isn't necessary to make the point that the technique generalizes beyond a DIY SACL.

### 11. Hunt — Permission-Change Auditing (4670)

**Security 4670 — "Permissions on an object were changed"** — records a DACL change on an audited object. On a file server this is a **privilege-escalation-via-ACL-abuse** signal: an attacker with write access to a folder's permissions granting a compromised account (or a newly created one) broader access to a sensitive share than it had before, rather than going through the noisier route of a group-membership change.

Like 4663, 4670 depends on the object being audited — it fires for changes to the DACL of an object that has a SACL configured to watch for permission changes, so the same two-part awareness from §3 applies: check that the object was actually being audited before treating a quiet log as "no permission changes happened."

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4670; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, @{N='Object';E={ if ($_.Message -match 'Object Name:\s*(\S+)') { $Matches[1] } }},
                  @{N='SubjectAccount';E={ if ($_.Message -match 'Subject:.*?Account Name:\s*(\S+)') { $Matches[1] } }}
```

| Finding | Why it matters |
|---|---|
| A non-admin account's DACL change grants itself (or another account it controls) access to a share it previously couldn't reach | Direct ACL-abuse escalation — the account is expanding its own reach without needing a domain-level privilege change that would be more likely to draw attention |
| A permission change on a sensitive share immediately precedes a burst of 5145 activity from the newly-granted account | Confirms the ACL change was operationally used, not just made — ties §11's finding directly into §7/§8's hunts |
| Permission changes clustered around the same time window as other findings in this note (new share creation, mass access) | Part of the same operational sequence — an attacker staging broader access as one step in a larger operation, not an isolated administrative change |

### 12. Hunt — Unauthorized New Share Creation

An attacker-created share is a common staging mechanism — a foothold for exfiltrating data out under a share name that blends in, or a drop location for tooling that doesn't require going through `ADMIN$`/`C$` (which is more likely to already be monitored). All three related events come from the same **Audit File Share** subcategory already covered in §3 — enabling it for 5140/5145 gets these three "for free," no additional configuration needed.

| Event ID | Meaning |
|---|---|
| **5142** | A network share object was **added** — new share created. The primary signal for this hunt. |
| **5143** | A network share object was **modified** — an existing share's settings (path, permissions, description) changed. Worth checking for a legitimate share quietly being widened rather than a brand-new one being created. |
| **5144** | A network share object was **deleted** — the share is removed. An attacker cleaning up a staging share after use is exactly the pattern that makes this event worth reviewing alongside 5142, not on its own. |

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5142,5143,5144; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            EventId     = $_.Id
            ShareName   = if ($_.Message -match 'Share Name:\s*(\S+)') { $Matches[1] }
            SharePath   = if ($_.Message -match 'Share Path:\s*(\S+)') { $Matches[1] }
            Account     = if ($_.Message -match 'Account Name:\s*(\S+)') { $Matches[1] }
        }
    } | Sort-Object TimeCreated
```

🔴 **A 5142 followed by a 5144 for the same share within a short window is a pattern worth flagging on its own, independent of what happened in between** — create, use, delete is the shape of a deliberately transient staging share, not normal administrative share management (which rarely deletes what it just created).

## Investigative Sequence Summary

| # | Step | Primary artifact/command | Goal |
|---|---|---|---|
| 1 | Enumerate shares | `Get-SmbShare`, `net share`, `Get-SmbShareAccess` + `Get-Acl` | Know the full surface; understand share-vs-NTFS effective access |
| 2 | Resolve DFS paths | `Get-DfsnFolderTarget`, `dfsutil` | Confirm the logical path in a log actually points at the physical server/share in front of you |
| 3 | Verify auditing | `auditpol /get`, `Get-Acl -Audit` | Confirm 5140/5145/4663's prerequisites are actually met before trusting the log |
| 4 | Check FSRM | `Get-FsrmFileScreen`, `Get-FsrmQuota`, Application log (`SRMSVC`) | Optional corroborating evidence source for screening/quota violations |
| 5 | Shadow copies | `vssadmin list shadows`, `\\server\share@GMT-...` | Recover pre-incident file state |
| 6 | Live triage | `Get-SmbSession`, `Get-SmbOpenFile` | Who's connected and what's open, right now |
| 7 | Mass-access hunt | 5145 aggregation by account | Detect pre-encryption recon |
| 8 | Mass-rename hunt | Filesystem timestamp sweep + 5145 WriteData | Detect encryption in progress → escalate to Ransomware Playbook |
| 9 | Off-hours hunt | 5145 filtered by time-of-day | Detect low-and-slow activity outside volume thresholds |
| 10 | Honeytoken check | 4663/5145 on a decoy file | Near-zero-false-positive early tripwire |
| 11 | Permission-change hunt | 4670 | Detect ACL-abuse privilege escalation |
| 12 | New-share hunt | 5142/5143/5144 | Detect attacker-staged exfil/foothold shares |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| A log/ticket references a DFS logical path and no one resolved it to a physical target before starting collection | Risk of investigating the wrong physical server entirely (§2) |
| 5140/5145/4663 all absent, on a server presumed to be under active investigation | Almost certainly means auditing was never configured, not that nothing happened — check `auditpol` and object SACLs before concluding otherwise (§3) |
| A SACL was never configured on a sensitive file/folder despite "File System" auditing being enabled at the policy level | The two-part 4663 gotcha — the object-level half was skipped, so no 4663 will ever fire for it regardless of activity (§3) |
| One account's 5145 volume is a sharp outlier against its own historical baseline | Pre-encryption reconnaissance signature (§7) |
| A previously-unseen file extension appears across many files in a tight time window | Encryption in progress — escalate immediately to the Ransomware Playbook (§8) |
| `vssadmin list shadows` returns empty on a server expected to have shadow copies enabled | Possible deliberate VSS destruction — full detection chain in note 19, not re-derived here (§5) |
| Any access at all to a designated honeytoken/canary file | Near-zero-false-positive early compromise indicator (§10) |
| 4670 grants an account broader access to a sensitive share, followed by that account's own 5145 activity on the newly-granted path | ACL-abuse privilege escalation, operationally used, not just made (§11) |
| A share is created (5142) and deleted (5144) again within a short window | Transient staging share — create, use, delete is not normal administrative share lifecycle (§12) |
| A share connection to `ADMIN$`/`C$` from a source host with no legitimate administrative function | Lateral-movement/remote-execution use of the file server as a Windows host, not its file-server role — full chain in notes 10 and 12 |

## MITRE ATT&CK Techniques Covered

| Technique | ID | Where it shows up in this note |
|---|---|---|
| **Data Encrypted for Impact** | T1486 | The headline correlation — §8's mass-rename hunt is the file-server-side detection query for the encryption stage the **Ransomware Playbook** covers end-to-end |
| **Network Share Discovery** | T1135 | An attacker's initial share enumeration (`net view`, `net share`, `Get-SmbShare` run *against* this server from elsewhere) — the reconnaissance step §1's inventory and §7's access-volume hunt both help detect from the server side |
| **File and Directory Discovery** | T1083 | §7's mass file-access/enumeration hunt — walking the share tree to map out what's present before acting on it |
| **Remote Services: SMB/Windows Admin Shares** | T1021.002 | `ADMIN$`/`C$` access flagged in §1's share taxonomy and the Red Flags table — full evidence chain lives in notes 10 and 12 |
| **Data from Network Shared Drive** | T1039 | Collection/staging directly from the shares this server hosts, ahead of exfiltration |
| **Exfiltration Over Alternative Protocol** | T1048 | Bulk data movement off the shares via SMB itself, outside the primary C2 channel |
| **Exfiltration to Cloud Storage** | T1567.002 | Where the destination for data pulled off a share is a cloud-sync client — cross-ref **Cloud Storage Artifacts (13)** for the client-side evidence |
| **File and Directory Permissions Modification** | T1222.001 | §11's 4670 hunt — an attacker widening its own effective access via a DACL change rather than a group-membership change |
| **Inhibit System Recovery** | T1490 | Shadow-copy destruction on the file server itself — full detection chain in note 19, only cross-referenced here (§5) |

## Tooling

| Tool | Use |
|---|---|
| **`Get-SmbShare` / `Get-SmbShareAccess`** | Native share inventory and share-level permissions (§1) |
| **`Get-SmbSession` / `Get-SmbOpenFile`** | Live connection and open-handle triage (§6) |
| **`Get-Acl` / `icacls.exe`** | NTFS-layer permissions and SACL inspection, live or against a mounted volume (§1, §3, §10) |
| **`auditpol.exe`** | Confirms which Object Access subcategories are actually enabled (§3) |
| **`Get-DfsnRoot` / `Get-DfsnFolder` / `Get-DfsnFolderTarget`** | DFS Namespace logical-to-physical resolution (§2) |
| **`dfsutil.exe` / `dfsrdiag.exe`** | Native DFS referral-cache inspection and DFSR replication-state diagnostics, useful when the DFSN PowerShell module isn't available (§2) |
| **FSRM console (`fsrm.msc`) / `Get-FsrmFileScreen` / `Get-FsrmQuota` / `Get-FsrmFileGroup`** | File-screening and quota configuration and violation history, where configured (§4) |
| **`vssadmin.exe`** | Live shadow-copy enumeration on the file server (§5) — full VSS tooling table in note 19 |
| **Sysinternals AccessEnum** | GUI sweep of NTFS permissions across a directory tree — fast way to spot an over-permissioned folder without walking ACLs one at a time |
| **Sysinternals ShareEnum** | Network-wide share enumeration across a domain/workgroup — useful for confirming what an attacker's own `net view`/share-discovery sweep (T1135) would have surfaced |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Full pre-to-post-encryption response sequence once §8's mass-rename hunt fires — deployment mechanism, shadow-copy destruction confirmation, credential/lateral-movement reconstruction, IOC extraction | [**Ransomware Playbook**](<../Threat Landscape and Playbooks/Ransomware Playbook.md>) — this note supplies the file-server-side detection query; that note owns everything from "confirmed" forward |
| Full VSS mechanics, Copy-on-Write internals, and the shadow-copy-*deletion*/anti-forensics evidence chain | [**Anti-Forensics and Evidence Destruction (19)**](<../19 - Anti-Forensics and Evidence Destruction.md>) — this note only covers using shadow copies that still exist (§5) |
| Attacker/source-host perspective on `net use`, share mapping, and SMB-based lateral movement (PsExec/`ADMIN$`, WMI, remote services/tasks) | [**Lateral Movement (12)**](<../12 - Lateral Movement.md>) — this note owns the destination/file-server-side perspective on the same connections |
| Full registry/event-log evidence chain if this file server is also found to be hosting a remote-service-based persistence/deployment mechanism | [**Persistence Mechanisms — Services (10)**](<../10 - Persistence Mechanisms/Services.md>) |
| Logon-type interpretation (Type 3 network logons underlie every share connection this note discusses) | [**Users, Groups & Authentication (05)**](<../05 - Users, Groups & Authentication.md>) |
| General event-log mechanics, log clearing (1102/104) if an attacker clears the Security log after touching this server's shares | [**Event Log Analysis (11)**](<../11 - Event Log Analysis.md>) |
| Whether the exfil path was host→share (this note) vs. host→removable media | [**Removable Device (USB) Forensics (09)**](<../09 - Removable Device (USB) Forensics.md>) — worth a quick check when scoping how data actually left, since the two evidence chains don't overlap |

## Resources

- Microsoft Learn — SMB Security Auditing / Advanced Security Audit Policy Settings (Object Access category, including 5140/5142/5143/5144/5145/4663/4670 schemas) — https://learn.microsoft.com/windows/security/threat-protection/auditing/basic-audit-object-access
- Microsoft Learn — DFS Namespaces and DFS Replication overview — https://learn.microsoft.com/windows-server/storage/dfs-namespaces/dfs-overview
- Microsoft Learn — File Server Resource Manager overview — https://learn.microsoft.com/windows-server/storage/fsrm/fsrm-overview
- Microsoft Learn — Volume Shadow Copy Service / Previous Versions and Shadow Copies for Shared Folders — https://learn.microsoft.com/windows-server/storage/file-server/volume-shadow-copy-service
- Sysinternals AccessEnum — https://learn.microsoft.com/sysinternals/downloads/accessenum
- Sysinternals ShareEnum — https://learn.microsoft.com/sysinternals/downloads/shareenum
- MITRE ATT&CK **T1486** (Data Encrypted for Impact) — https://attack.mitre.org/techniques/T1486/
- MITRE ATT&CK **T1135** (Network Share Discovery) — https://attack.mitre.org/techniques/T1135/
- MITRE ATT&CK **T1083** (File and Directory Discovery) — https://attack.mitre.org/techniques/T1083/
- MITRE ATT&CK **T1021.002** (Remote Services: SMB/Windows Admin Shares) — https://attack.mitre.org/techniques/T1021/002/
- MITRE ATT&CK **T1039** (Data from Network Shared Drive) — https://attack.mitre.org/techniques/T1039/
- MITRE ATT&CK **T1048** (Exfiltration Over Alternative Protocol) — https://attack.mitre.org/techniques/T1048/
- MITRE ATT&CK **T1567.002** (Exfiltration to Cloud Storage) — https://attack.mitre.org/techniques/T1567/002/
- MITRE ATT&CK **T1222.001** (Windows File and Directory Permissions Modification) — https://attack.mitre.org/techniques/T1222/001/
- MITRE ATT&CK **T1490** (Inhibit System Recovery) — https://attack.mitre.org/techniques/T1490/
