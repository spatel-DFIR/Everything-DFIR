# Domain Controller — Role-Specific Forensics

Everything about *what the domain does* — Kerberos ticket issuance, DCSync/replication abuse, GPO tampering, trust/SID history abuse — already has a full-depth home in [`05b - Active Directory & Domain Forensic Artifacts`](<../05b - Active Directory & Domain Forensic Artifacts.md>). This note answers a narrower, physically-grounded question: **the box you're standing on is a Domain Controller — what does that fact alone change about how you work the host?** A DC is simultaneously an ordinary Windows Server (everything in notes 01-22 still applies) and a single point of failure for the whole domain's trust model, running services no member server or workstation ever runs, holding a database no other host holds a copy of, and generating a log volume no other host generates. This note is the DC-host-specific layer that sits on top of 05b, not a replacement for it.

> 🔴 **The single costliest mistake specific to this host type: treating a Domain Controller like "a server that happens to run AD" instead of "the domain's trust anchor."** A rogue/unauthorized DC, a DCShadow-style forged replication partner, or a stolen `ntds.dit` doesn't compromise one host — it compromises every credential and every trust decision the domain has ever made or will make until remediated. Scope every DC engagement accordingly: identify *which* DC-specific roles are actually running (Step 1) before anything else, because that list determines which of the sections below even apply to this box.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [DC Service Fundamentals](#dc-service-fundamentals)
- [Investigation Workflow](#investigation-workflow)
  - [Step 1 — Identify DC-Only Services/Roles Actually Running](#step-1--identify-dc-only-servicesroles-actually-running)
  - [Step 2 — NTDS.dit: Locating and Acquiring the Database Itself](#step-2--ntdsdit-locating-and-acquiring-the-database-itself)
  - [Step 3 — SYSVOL/DFSR Replication Health](#step-3--sysvoldfsr-replication-health)
  - [Step 4 — AD-Integrated DNS as a Stealth Persistence/MITM Vector](#step-4--ad-integrated-dns-as-a-stealth-persistencemitm-vector)
  - [Step 5 — DC-Side Log-Volume Triage](#step-5--dc-side-log-volume-triage)
  - [Step 6 — DC Promotion/Demotion Evidence and Rogue DC Detection](#step-6--dc-promotiondemotion-evidence-and-rogue-dc-detection)
  - [Step 7 — What NTDS/AD-Database-Dumping Looks Like on the Host Itself](#step-7--what-ntdsad-database-dumping-looks-like-on-the-host-itself)
- [Investigative Sequence Summary](#investigative-sequence-summary)
- [Persistence Patterns Specific to This Role](#persistence-patterns-specific-to-this-role)
- [Red Flags](#red-flags)
- [Tooling](#tooling)
- [MITRE ATT&CK Techniques Covered](#mitre-attck-techniques-covered)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native tooling first-class here — `repadmin`, `dfsrdiag`, `dcdiag`, and `ntdsutil` are DC-specific binaries with no full PowerShell replacement, so this Hunt Evil block leans on them alongside PowerShell rather than defaulting to PowerShell-only.

```powershell
# Which DC-only roles are actually live on this box - determines which sections of this note apply (Step 1)
Get-Service NTDS,Netlogon,DNS,DFSR,NTFRS,W32Time,kdc -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType

# Replication health at a glance - the fastest single command for "is this DC's view of the domain consistent with its peers" (Step 6)
repadmin /replsummary

# Every server object actually registered in the site topology - compare against your known-DC inventory, anything extra is a finding (Step 6)
Get-ADObject -SearchBase "CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" -Filter {objectClass -eq 'server'} -Properties whenCreated |
    Select-Object Name,DistinguishedName,whenCreated | Sort-Object whenCreated -Descending

# NTDS.dit's own file metadata - a size/LastWriteTime wildly out of step with your backup schedule is itself a lead (Step 2/7)
Get-Item "$env:SystemRoot\NTDS\ntds.dit" | Select-Object FullName,Length,LastWriteTime,CreationTime

# ntdsutil.exe / vssadmin.exe process-creation events outside a documented backup window - the NTDS-theft process-tree tell (Step 7)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'ntdsutil\.exe|vssadmin\.exe' } | Select-Object TimeCreated,Message

# Recently-created/updated DNS records in the AD-integrated zone - rogue A/CNAME injection hunt (Step 4)
Get-DnsServerResourceRecord -ZoneName (Get-ADDomain).DNSRoot -RRType A |
    Where-Object { $_.Timestamp -and $_.Timestamp -gt (Get-Date).AddDays(-2) } | Select-Object HostName,RecordData,Timestamp

# One-shot health check across every classic DC-fundamentals test - fast triage before deciding where to dig deeper
dcdiag /q
```

## DC Service Fundamentals

| Service | Hosting process | Role | DC-exclusive? | Notes |
|---|---|---|---|---|
| **Active Directory Domain Services** (`NTDS`) | `lsass.exe` (loads `ntdsai.dll`) | The directory database engine (an ESE/JET database) — answers LDAP, backs Kerberos issuance, drives replication | Yes — this service does not exist on a non-DC | Its data file is `ntds.dit`, covered in depth in Step 2 |
| **Kerberos Key Distribution Center** (`KDC`) | `lsass.exe` (loads `kdcsvc.dll`) | Authentication Service (AS) + Ticket Granting Service (TGS) roles — see [`05b`](<../05b - Active Directory & Domain Forensic Artifacts.md#kerberos-fundamentals-for-dfir>) for the full flow and abuse techniques | Yes — the KDC runs *only* on Domain Controllers, nowhere else in a Windows domain | This note's job stops at "this service is DC-exclusive"; every ticket-abuse detail (Golden/Silver Ticket, Kerberoasting, AS-REP Roasting, DCSync) is `05b`'s territory |
| **Netlogon** | `lsass.exe` (loads `netlogon.dll`) | Secure channel setup/maintenance between DCs and member computers, DC-locator (`DCLocator`) responses, pass-through NTLM authentication | The server-side "locate/authenticate against a DC" function is DC-only; a lightweight client-side Netlogon also runs on member computers | `netlogon.log` under `%SystemRoot%\debug\` is the classic troubleshooting log for secure-channel failures |
| **Windows Time** (`W32Time`) | `svchost.exe -k LocalService` | Time synchronization | Runs on every Windows host, but the **DC's role in the hierarchy is structurally special** — see below | The domain's **PDC emulator** is the root of the domain's internal time hierarchy by default; all other DCs sync to it (or to a configured upstream), and all domain-joined member computers sync to their authenticating DC via NT5DS |
| **DNS Server** | `dns.exe` | Name resolution; in most AD deployments the zone data itself is **AD-integrated** — stored as objects in the directory (`DomainDnsZones`/`ForestDnsZones` application partitions) rather than a flat zone file | Not exclusive to DCs as a Windows role, but frequently co-located on DCs specifically because AD-integrated zones need a DC to host the directory partition they live in | Step 4 covers the abuse angle this co-location creates |
| **DFS Replication** (`DFSR`) | `dfsrs.exe` | Modern (2008+ domain functional level) multi-master replication engine — replicates SYSVOL between DCs, among other DFS-R uses | The general DFSR service isn't DC-exclusive (file servers use it too), but its **SYSVOL replication group** is DC-specific | Step 3 |
| **File Replication Service** (`FRS`, legacy) | `ntfrs.exe` | The pre-2008 SYSVOL replication mechanism, superseded by DFSR | Same DC-specific carve-out as DFSR, for domains that never migrated | A real-world gotcha — see Step 3 |

🔴 **Why time matters more here than on any other host: the DC is the domain's authoritative time source, and Kerberos has a hard clock-skew tolerance (default 5 minutes) baked into ticket validation.** Tampering with a DC's system clock — directly, or by feeding it a malicious upstream NTP source — doesn't just skew that one box's local timestamps; it can push every ticket-based authentication decision domain-wide outside Kerberos's replay/skew window, or, at the other extreme, be used deliberately to keep a forged ticket's timestamps inside the tolerance window. The clock-skew *attack mechanics* themselves (how skew interacts with Golden Ticket lifetimes, replay detection, etc.) belong to [`05b`'s Kerberos section](<../05b - Active Directory & Domain Forensic Artifacts.md#kerberos-fundamentals-for-dfir>) — this note's job is flagging that the DC is *where* that exposure physically lives and why W32Time configuration/integrity on a DC deserves scrutiny that it wouldn't on an ordinary member server.

## Investigation Workflow

### Step 1 — Identify DC-Only Services/Roles Actually Running

Before anything else, confirm which of the DC-Exclusive services above are actually present and running on this specific box — a domain can have DCs that are also DNS servers and others that aren't, DCs still on legacy FRS alongside DCs already migrated to DFSR, and (rarely, but it happens) a Server Core DC with a much smaller running-service footprint than a GUI installation. This list gates which of the remaining steps apply.

```powershell
Get-WindowsFeature AD-Domain-Services,DNS,FS-DFS-Replication -ErrorAction SilentlyContinue | Select-Object Name,InstallState
Get-Service NTDS,Netlogon,DNS,DFSR,NTFRS,W32Time -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType
dcdiag /q
```

`dcdiag` with no arguments runs the full classic test suite (connectivity, replications, advertising, KnowsOfRoleHolders, NCSecDesc, and more) and is the fastest single native command for "is this DC structurally healthy" before deciding where in the rest of this note to focus.

### Step 2 — NTDS.dit: Locating and Acquiring the Database Itself

This step is about **getting safe, forensically-sound access to the database file** — not about what to do with it once you have it. What to query and how to interpret AD object data is `05b`'s territory (its `Get-AD*` cmdlet examples query the directory service live, over LDAP); this step is purely acquisition mechanics for the file itself.

| Fact | Detail |
|---|---|
| Default location | `%SystemRoot%\NTDS\ntds.dit` (commonly `C:\Windows\NTDS\ntds.dit`) — can be relocated to a separate volume at promotion time or later via `ntdsutil "activate instance ntds" "files" "move db to <path>"`; confirm actual path with `ntdsutil "activate instance ntds" "files" "info"` rather than assuming the default |
| Companion files | `edb.log` / `edb*.log` (ESE transaction logs), `edb.chk` (checkpoint file), `temp.edb` — a forensically complete acquisition needs the database *and* its log files if you want to capture uncommitted transactions, though a clean `ifm` or VSS-based pull (below) already produces a consistent, committed-state copy |
| Why you can't just copy it live | `ntds.dit` is held open and locked by `lsass.exe` (the NTDS service) for the entire time the DC is running — a plain file copy fails outright, and even if it didn't, a raw copy of a live, actively-written ESE database risks internal inconsistency |

**Acquisition mechanics — two supported paths:**

1. **`ntdsutil` IFM (Install From Media)** — the field-standard, purpose-built export:

```
ntdsutil "activate instance ntds" "ifm" "create full <output-path>" quit quit
```

   This produces a self-consistent snapshot of `ntds.dit` plus the registry hives IFM also captures (`SYSTEM`, and optionally `SYSVOL` content) in the target directory, using VSS internally to get a point-in-time consistent copy without stopping the NTDS service. `create full` is the everything-included option; `create sysvol full` additionally includes SYSVOL content in the export.

2. **Direct VSS snapshot** — for when you want a broader point-in-time capture of the whole volume (registry hives, event logs, and `ntds.dit` together) rather than an NTDS-specific export:

```
vssadmin create shadow /for=C:
```

   followed by copying `ntds.dit` out of the shadow-copy device path (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\Windows\NTDS\ntds.dit`). General VSS access mechanics (the `mklink`/`GLOBALROOT` technique, `Get-CimInstance Win32_ShadowCopy`) are already covered in full in [`19 - Anti-Forensics and Evidence Destruction` § Volume Shadow Copy Analysis](<../19 - Anti-Forensics and Evidence Destruction.md#volume-shadow-copy-analysis>) — this step only adds that `ntds.dit` is one of the highest-value files to specifically pull out of a shadow copy on a DC, alongside `SYSTEM`/`SECURITY`/`SAM` for the registry side.

🔴 Never stop the NTDS service to force a copy on a production DC unless you fully understand the domain-wide availability impact (that DC stops servicing authentication/replication for the outage duration) — IFM and VSS both exist specifically so you never have to.

Once acquired, everything downstream — offline extraction of password hashes for a forensic timeline (not for cracking-as-attack), attribute-level review, replication metadata — is the same directory-object analysis `05b` already covers in depth; this step's job ends at "you now have a safe, consistent copy of the file."

### Step 3 — SYSVOL/DFSR Replication Health

This step is about **replication plumbing and health** — whether GPO content is actually consistent and current across DCs. Full mechanics (`dfsrdiag replicationstate`/`backlog`, `dfsrmig /getmigrationstate` and the FRS→DFSR migration-state gotcha, the GPT/GPC version-desync detection this replication-health check feeds into) now live in [`GPO/01 - Storage, Replication and Version Synchronization`](<../GPO/01 - Storage, Replication and Version Synchronization.md#replication-health-checking>) — not re-derived here. Interpreting *what's inside* a given GPO (logon scripts, GPP, Restricted Groups, `gPLink`) and the DC-side malicious-change detection workflow built on top of this replication-health check live in [`GPO/03 - Domain Controller GPO Investigation`](<../GPO/03 - Domain Controller GPO Investigation.md>).

### Step 4 — AD-Integrated DNS as a Stealth Persistence/MITM Vector

Because AD-integrated DNS zone data is stored *as directory objects*, any principal with sufficient write access to the zone (which, depending on zone update-security settings, can be broader than expected) can inject DNS records that ride on top of the DC's DNS role — a technique that requires no code execution on the DC itself, just directory write access, and blends into a large population of legitimate dynamic-update records.

| Technique | What it looks like | Hunt command |
|---|---|---|
| Rogue A/CNAME record | A record pointing a plausible-looking hostname (e.g. mimicking a real internal service name) at attacker-controlled infrastructure — used for MITM, credential capture, or as a persistence pointer that survives cleanup of the original compromised host | `Get-DnsServerResourceRecord -ZoneName <domain> -RRType A` — filter by `Timestamp` (dynamic-update records carry a non-zero timestamp; static/manually-created records show `0`, itself worth a second look if unexpected) |
| Wildcard record (`*.domain.com`) | Causes *every* unmatched subdomain query to resolve to the attacker's IP — a single record with domain-wide blast radius, and an unusual enough configuration that its mere presence is close to a de facto finding | `Get-DnsServerResourceRecord -ZoneName <domain> -RRType A \| Where-Object HostName -eq '*'` |
| WPAD-abuse-adjacent entries | Injected/re-enabled `wpad` or `isatap` records used to coax clients into using an attacker-controlled proxy — Windows normally blocks dynamic registration of these specific names via the DNS global query block list (`dnscmd /config /globalqueryblocklist`), so a `wpad` record actually resolving is itself a strong signal that the block list was disabled or bypassed | `Get-DnsServerGlobalQueryBlockList` to confirm the block list is intact; `Get-DnsServerResourceRecord -ZoneName <domain> -Name wpad` to check whether it resolves anyway |
| Dynamic-update security gap | AD-integrated zones configured for "Nonsecure and secure" updates (rather than "Secure only") let *any* client on the network attempt a dynamic update without Kerberos/GSS-TSIG authentication — an underlying config weakness that makes several of the above trivially easier | `Get-DnsServerZone \| Select-Object ZoneName,DynamicUpdate` |

Corroborate with the DNS Server event log (`Microsoft-Windows-DNS-Server/Audit`, or the classic DNS Server log under Applications and Services Logs) for dynamic-update and zone-transfer events:

```powershell
Get-WinEvent -FilterHashtable @{LogName='DNS Server'} -MaxEvents 200 | Where-Object { $_.Message -match 'dynamic update|zone transfer' }
```

### Step 5 — DC-Side Log-Volume Triage

The DC-side event IDs 05b already covers in depth (4768/4769/4770/4771, 4662, 5136) and the workstation-side IDs notes 05/11 cover (4624/4625/4740/etc.) are not re-explained here — this step is exclusively about **managing the sheer volume** those events generate on a live DC during an active incident, since a DC's Security log fills orders of magnitude faster than a workstation's.

| Concern | What to actually do |
|---|---|
| **Log-size/rotation risk under load** | A DC servicing hundreds or thousands of authentications per hour can roll a default-sized Security log over in **hours rather than days or weeks** — a much shorter effective retention window than an analyst used to workstation-scale volume expects. Check current configured max size and retention behavior *before* assuming last week's activity is still in the log: `Get-WinEvent -ListLog Security \| Select-Object MaximumSizeInBytes,LogMode,RecordCount`. If retention is a live concern mid-incident, increase max size (`wevtutil sl Security /ms:<bytes>`) immediately — this doesn't recover already-overwritten records, but it stops further loss for the remainder of the engagement. |
| **Establishing a baseline "normal" throughput** | You cannot recognize a spike without knowing the DC's ordinary event rate. Pull a same-time-of-day/same-day-of-week comparison window before concluding an observed volume is anomalous: `Get-WinEvent -FilterHashtable @{LogName='Security';StartTime=(Get-Date).AddDays(-7).Date;EndTime=(Get-Date).AddDays(-7).Date.AddDays(1)} \| Group-Object {$_.TimeCreated.Hour} \| Select-Object Name,Count` — compare hour-by-hour against the incident window's own hourly counts. A DC's normal profile is also **bursty and predictable** in ways a workstation's isn't: sharp spikes at business-hours start (mass logon), around scheduled tasks/GPO refresh intervals (default 90 min ± offset), and near backup windows — know your environment's shape before flagging a burst as suspicious. |
| **Export/collection strategy given the volume** | Do not attempt to pull a multi-gigabyte live Security.evtx off a production DC with a broad, unbounded query mid-incident — the I/O and query cost can itself degrade authentication service for the domain. Time-box every export to the narrowest window the investigation actually needs (`wevtutil epl Security export.evtx /q:"*[System[TimeCreated[@SystemTime>='...' and @SystemTime<='...']]]"` or the `StartTime`/`EndTime` parameters on `Get-WinEvent`), and prefer pulling from an existing centralized log-forwarding/WEF collector over the live DC directly if one exists in the environment — it removes both the I/O concern and the rotation-loss race entirely. |

Full field-level meaning of every event mentioned above, log-analysis mechanics generally, and audit-policy prerequisites live in [`11 - Event Log Analysis`](<../11 - Event Log Analysis.md>); live-collection technique and evidence-handling discipline live in [`16 - Live Response and Volatile Data`](<../16 - Live Response and Volatile Data.md>) — this step only adds the DC-scale volume-management judgment calls those notes don't need to make for a single workstation.

### Step 6 — DC Promotion/Demotion Evidence and Rogue DC Detection

This is the highest-value section in this note. Standing up an unauthorized Domain Controller — or temporarily forging one via a DCShadow-style technique — hands an attacker a full, persistent replication partner inside the domain's trust boundary: it will legitimately receive replicated password-hash data going forward, can inject changes that other DCs then dutifully replicate onward as if they were normal administrative changes, and blends into an inventory that most organizations under-audit (`Get-ADDomainController -Filter *` is checked far less often than it should be).

**Legitimate promotion/demotion evidence** (baseline, to know what "normal" looks like before hunting for what isn't):

| Artifact | What it shows |
|---|---|
| `Install-ADDSDomainController` / `dcpromo` (legacy) execution | Standard cmdlet/tool for promoting a member server to a DC — expect this to correlate with a documented change ticket |
| Directory Service event log creation | The **Directory Service** event log (Applications and Services Logs) only exists on a machine that is, or has been, a DC — its mere presence on a host is itself informative when reviewing an unfamiliar server's role history |
| Security 4741 / 4742 | Computer account created (4741) / computer account changed (4742) — a promotion flips `userAccountControl` to include the `SERVER_TRUST_ACCOUNT` flag, which surfaces as a 4742 on the computer object |
| Security 4928–4937 (directory-service-replication auditing) | The Windows Security event range specifically covering replication topology changes — naming-context established/removed (4928/4929), source/destination naming-context modified (4930/4931), replication begin/end (4932/4933), attribute replication (4934), replication failure begin/end (4935/4936), lingering-object removal (4937). Requires directory-service-replication auditing enabled to generate — confirm audit policy before treating an absence as "nothing happened," the same caveat `05b` already applies to 4662/5136 |
| New `nTDSDSA` object under `CN=Servers,CN=<site>,CN=Sites,CN=Configuration,...` | Every real DC has a corresponding NTDS Settings object here — a newly-appeared one is either a legitimate new DC or the first thing to investigate |

**Rogue/unauthorized DC detection:**

```powershell
# Full inventory of DCs AD itself believes exist - compare against your actual known-good inventory line by line
Get-ADDomainController -Filter * | Select-Object Name,Site,OperatingSystem,IPv4Address

# Server objects in the site topology - a lower-level view than Get-ADDomainController, catches an object that hasn't
# fully completed promotion or is deliberately incomplete (a DCShadow-style transient object)
Get-ADObject -SearchBase "CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" -Filter {objectClass -eq 'server'} -Properties whenCreated |
    Select-Object Name,DistinguishedName,whenCreated | Sort-Object whenCreated -Descending

# Replication partner list for a specific DC - an unexpected inbound/outbound partner (or one that appears then
# disappears across repeated runs) is the core rogue-DC/DCShadow signature
repadmin /showrepl <DC-name>

# Replication summary across the whole domain - flags DCs with stale or failing replication, which includes
# a rogue DC that only partially completed its promotion
repadmin /replsummary
```

🔴 **DCShadow (a Mimikatz capability, not a Windows/AD bug) temporarily registers a rogue or compromised machine as a fake replication partner** just long enough to push a single malicious change (e.g. a Golden-Ticket-adjacent attribute, a group membership, an SPN) into the directory via the legitimate replication protocol — then deregisters, leaving a much smaller footprint than a persistent unauthorized DC. It relies on holding (or having compromised) the right AD permissions to register a server object and drive DRS replication RPCs, not on an exploit. The tell is almost always **transient**: an `nTDSDSA`/server object under `CN=Sites,...,CN=Servers` that appears and is gone by the time you look, a `repadmin /showrepl` partner list that doesn't match between two consecutive runs, or 4929/4932-range events referencing a source that never shows up in `Get-ADDomainController -Filter *`. Because the window is short, **repeated point-in-time snapshots of the site topology and replication partner list, compared against each other, catch this far more reliably than a single check.**

| Rogue-DC signal | Persistent unauthorized DC | DCShadow-style transient |
|---|---|---|
| `Get-ADDomainController -Filter *` | Shows the rogue DC as a normal-looking entry once promotion completes | Usually never appears here — the technique avoids full, durable promotion |
| Site topology (`CN=Servers`) | New server/`nTDSDSA` object persists | Object appears and is removed within the same operational window — catch it via repeated snapshots |
| `repadmin /showrepl` | Rogue DC shows as a stable, recurring replication partner | Appears once, may not recur — compare consecutive runs rather than trusting a single pull |
| Security 4929-4937 | Present, ordinary-looking replication events once established | Present around the injection window, source identity is the anomaly to chase |
| Downstream impact | Full, ongoing replication — the rogue DC receives password-hash data going forward like any real DC | Single injected change replicates outward from a legitimate DC as if it were routine — the forged object itself may already be gone by the time you're looking |

### Step 7 — What NTDS/AD-Database-Dumping Looks Like on the Host Itself

`05b`'s DCSync coverage is about the **replication-rights abuse angle** — an attacker who never touches the DC's disk or memory at all, abusing legitimate replication permissions remotely. This step is the complementary, host-centric angle: what it looks like when an attacker is **on the DC itself**, physically extracting `ntds.dit` (or its in-memory equivalent) rather than abusing replication rights remotely.

The core red flag is a process-tree/context mismatch: `ntdsutil.exe` and `vssadmin.exe` are legitimate, expected tools — the entire question is whether their invocation matches a documented backup/maintenance context or not.

```
ntdsutil.exe / vssadmin.exe execution observed on a DC
        │
        ▼
Does it fall inside a documented backup window
(parent process = backup service/scheduled task,
e.g. wbengine.exe, a third-party backup agent, or
Task Scheduler's own host process)?
        │
   ┌────┴─────────────────┐
   │                       │
  YES                      NO
   │                       │
   ▼                       ▼
Parent process chain    Parent process = an interactive
matches a known backup   shell (cmd.exe / powershell.exe
job; account context =   under a logged-on session), or
the backup service       an unexpected account context,
account                  or off-hours timing
   │                       │
   ▼                       ▼
LOW concern - confirm    Does the command line reference
and document, no          "ifm" / "create full", or target
further action needed     a non-standard output path (UNC
                           share, removable media, a cloud-
                           sync folder like OneDrive/Dropbox)?
                               │
                          ┌────┴────┐
                          │         │
                         YES        NO (bare "list shadows"
                          │          / snapshot-only activity)
                          ▼               │
                    HIGH concern -         ▼
                    treat as active   MEDIUM concern - still
                    NTDS.dit theft,   verify account context and
                    escalate          watch for a follow-up mount/
                    immediately       access of the resulting VSC
                                      by an unexpected process
```

Corroborate process-tree observations with:

- **Unexpected Volume Shadow Copy creation events** — `vssadmin create shadow` outside a backup window is the same high-value signal [`19`'s VSS section](<../19 - Anti-Forensics and Evidence Destruction.md#the-attacker-countermeasure-shadow-copy-deletion>) flags for *deletion*; on a DC, unexpected shadow copy **creation** carries an equally strong, distinct meaning — it's frequently the setup step immediately preceding an `ntdsutil ifm` pull or a direct copy of `ntds.dit` out of the shadow device path.
- **Process lineage for `ntdsutil.exe`/`vssadmin.exe`** — Sysmon Event ID 1 (or Security 4688 with command-line auditing) parent/child chains; a parent of `cmd.exe`/`powershell.exe` spawned from an interactive RDP or console session is a materially different picture than a parent that's a recognized backup service.
- **`ntds.dit` file-metadata anomalies** — a `LastWriteTime`/`LastAccessTime` on the live file, or a newly-appeared copy elsewhere on disk (staging directory, `C:\Windows\Temp\`, a user profile), outside the backup schedule established in Step 2's baseline check.

## Investigative Sequence Summary

```
1. Identify DC-only roles actually running
   Get-Service NTDS/KDC/Netlogon/W32Time/DNS/DFSR + dcdiag /q
                    │
2. Acquire ntds.dit safely (if the database itself is in scope)
   ntdsutil ifm  -or-  vssadmin create shadow → copy from device path
   → hand off to 05b for what to query/interpret
                    │
3. Check SYSVOL/DFSR replication health
   dfsrdiag replicationstate/backlog · dfsrmig /getmigrationstate (legacy gotcha)
   → hand off to GPO/01 for replication mechanics, GPO/03 for GPO content interpretation
                    │
4. Hunt AD-integrated DNS for injected records
   Get-DnsServerResourceRecord · wildcard/WPAD checks · dynamic-update security review
                    │
5. Triage DC-side log volume
   Log size/rotation under load · baseline throughput · time-boxed export strategy
                    │
6. Check DC promotion/demotion evidence + rogue DC detection
   Get-ADDomainController -Filter * · site-topology server objects · repadmin /showrepl
   (repeat snapshots to catch DCShadow-style transient partners)
                    │
7. Assess NTDS-dumping activity on the host itself
   ntdsutil.exe/vssadmin.exe process-tree triage (flowchart) · unexpected VSC creation
                    │
8. Hand off
   Object-level AD/Kerberos/DCSync depth → 05b · GPO content/investigation depth → GPO/
   Registry hive handling → 04 · VSS general mechanics → 19 · onward lateral movement → 12
```

## Persistence Patterns Specific to This Role

| Pattern | Why it's DC-specific | Where to look |
|---|---|---|
| Unauthorized/rogue Domain Controller | The single highest-leverage persistence primitive available in an AD environment — durable, receives ongoing replication, blends into a normal-looking inventory if under-audited | Step 6 |
| DCShadow-style transient replication partner | Lower footprint than a persistent rogue DC; used for a single high-value directory change rather than durable access | Step 6 |
| Malicious AD-integrated DNS record | Rides entirely on the DC's DNS role, requires no code execution on the DC itself if directory write access is already held | Step 4 |
| GPO-based domain-wide persistence | Mechanism itself is the [`GPO/` folder](<../GPO/00 - GPO Fundamentals and Architecture.md>)'s territory (logon scripts, GPP, Restricted Groups) — this note's only addition is that a **stale/lagging DFSR replica** can mask a malicious GPO change on some DCs while it's already visible on others, complicating "when did this actually apply domain-wide" | Step 3 → `GPO/03` |
| `ntds.dit` exfiltration via legitimate backup tooling misuse | Attacker rides `ntdsutil`/VSS rather than deploying custom tooling, specifically to blend into expected DC administrative activity | Step 7 |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `Get-ADDomainController -Filter *` or the site-topology server-object list contains an entry not in your known-good DC inventory | Candidate rogue/unauthorized Domain Controller — escalate immediately, don't wait for corroboration |
| Site-topology `nTDSDSA`/server object present on one check and gone on a follow-up check | DCShadow-style transient replication partner — the disappearance is itself the signature, not evidence of a false positive |
| `repadmin /showrepl` partner list differs between two consecutive runs against the same DC with no documented topology change | Same as above — treat inconsistency as a lead, not noise |
| `ntdsutil.exe`/`vssadmin.exe` running with a parent process that isn't a recognized backup service, especially off-hours or under an interactive session | NTDS.dit theft in progress — see Step 7 flowchart |
| Unexpected Volume Shadow Copy creation event on a DC outside the backup schedule | Frequently the staging step immediately before an `ntds.dit` pull |
| New/modified A, CNAME, or wildcard (`*`) record in the AD-integrated zone with no change-ticket correlation | Stealth persistence/MITM riding on the DC's DNS role |
| A `wpad` record resolving despite the DNS global query block list appearing intact, or the block list itself found disabled | WPAD-abuse-adjacent persistence — investigate both the record and why the block list didn't prevent it |
| AD-integrated zone configured for "Nonsecure and secure" dynamic updates | Structural weakness that makes several of the above materially easier for any network-present client |
| DFSR backlog non-zero and growing between two DCs, or `dfsrmig /getmigrationstate` showing an incomplete FRS→DFSR migration | Some DCs are serving stale SYSVOL/GPO content — don't trust a single DC's copy as domain-authoritative until this is resolved |
| Security log rotating over in hours rather than days on a busy DC, discovered mid-incident | Active loss of evidence in progress — increase max log size immediately and prioritize export of the remaining window |
| Directory Service event log present on a host not currently believed to be (or have ever been) a DC | The host's role history doesn't match the working assumption — investigate before proceeding on the wrong premise |

## Tooling

| Tool | Use |
|---|---|
| **`ntdsutil`** | `ntds.dit` acquisition (IFM), offline database maintenance, moving the database file, metadata cleanup of decommissioned DCs |
| **`repadmin`** | Replication topology/health — `/replsummary`, `/showrepl`, `/showobjmeta` (the latter fully covered in `05b`) |
| **`dfsrdiag`** | DFSR-specific replication state and backlog checks for SYSVOL |
| **`dfsrmig`** | FRS→DFSR migration state — critical for the legacy-domain gotcha in Step 3 |
| **`dcdiag`** | One-shot classic DC health test suite — fastest way to triage overall DC health before deciding where to focus |
| **DNS Manager / `Get-DnsServerResourceRecord`** | AD-integrated zone enumeration and rogue-record hunting |
| **`vssadmin`** | Live VSS enumeration/creation — both the legitimate acquisition path (Step 2) and the abuse-detection angle (Step 7); general mechanics owned by note 19 |
| **`wevtutil` / `Get-WinEvent`** | Time-boxed, targeted log export — the volume-management workhorse for Step 5 |
| **`Get-ADDomainController` / `Get-ADObject` (site topology)** | Rogue-DC inventory comparison — Step 6 |

## MITRE ATT&CK Techniques Covered

| Technique | ID | Depth in this note vs. `05b` |
|---|---|---|
| OS Credential Dumping: NTDS | T1003.003 | This note covers the **host-side acquisition/theft mechanics** (`ntdsutil`/VSS process-tree triage, Step 7) — offline credential-material extraction and interpretation once you have the file is out of scope here |
| Rogue Domain Controller | T1207 | Full depth lives **here** — Step 6 is this note's most detailed section; `05b` does not cover rogue-DC detection at all |
| Domain Policy Modification | T1484 | GPO-content depth (what a malicious change looks like) is the **[`GPO/` folder](<../GPO/00 - GPO Fundamentals and Architecture.md>)'s territory**; this note only covers the SYSVOL/DFSR replication-plumbing angle that can mask or delay a GPO change's visibility (Step 3) |
| Steal or Forge Kerberos Tickets | T1558 | Full ticket-abuse depth (Golden/Silver Ticket, Kerberoasting, AS-REP Roasting, DC-side event signatures) lives entirely in **`05b`**; this note only notes that the KDC is DC-exclusive and flags DC time-integrity as a prerequisite concern (Service Fundamentals) |
| DNS (as a C2/persistence surface, umbrella) | T1071.004 / T1584.002-adjacent | This note's Step 4 covers **AD-integrated DNS record injection** specifically as a DC-role-specific persistence/MITM vector — not general DNS-based C2 |
| Exploitation of Remote Services / Valid Accounts (replication-rights path) | T1210 / T1078 (supporting DCSync) | DCSync itself — the replication-rights abuse angle — is fully owned by **`05b`**; this note's Step 6/7 cover the adjacent-but-distinct host-presence and rogue-partner angles |

## Correlate With

| To go deeper on… | Open | Division of labor |
|---|---|---|
| Kerberos fundamentals/abuse, DCSync (replication-rights angle), AD replication metadata, domain trust/SID history | [`05b - Active Directory & Domain Forensic Artifacts`](<../05b - Active Directory & Domain Forensic Artifacts.md>) | Primary sibling note — `05b` owns *what the domain does*; this note owns *what's different because the box is a DC*. Every Kerberos event ID and DCSync detail referenced here points back to `05b` rather than being re-explained |
| GPO fundamentals through abuse/hunting — the content interpretation and DC-side investigation workflow this note's Step 3 hands off to | [`GPO/ folder`](<../GPO/00 - GPO Fundamentals and Architecture.md>), starting at 00 | GPO-content depth moved out of `05b` into its own folder — this note's replication-plumbing angle (Step 3) feeds `GPO/03`'s DC-side investigation |
| Registry hive structure, offline hive access, `SYSTEM`/`SECURITY` handling for a pulled IFM/VSS export | [`04 - Registry Forensics Fundamentals`](<../04 - Registry Forensics Fundamentals.md>) | This note's Step 2 acquires the hives; note 04 owns how to read them |
| General VSS mechanics, shadow-copy access techniques, shadow-copy deletion as anti-forensics | [`19 - Anti-Forensics and Evidence Destruction`](<../19 - Anti-Forensics and Evidence Destruction.md>) | This note's VSS content (Steps 2 and 7) is narrowly about NTDS.dit acquisition/theft mechanics on a DC specifically — note 19 owns VSS theory and general anti-forensic VSS abuse |
| Full event-log field mechanics, audit-policy prerequisites, log analysis generally | [`11 - Event Log Analysis`](<../11 - Event Log Analysis.md>) | This note's Step 5 covers DC-scale volume management only, not event-field meaning |
| Onward lateral movement once a foothold on a DC is confirmed | [`12 - Lateral Movement`](<../12 - Lateral Movement.md>) | Handoff point once this note's scope (working the DC-as-a-host) is exhausted |
| Live-response collection discipline, evidence handling under time pressure | [`16 - Live Response and Volatile Data`](<../16 - Live Response and Volatile Data.md>) | Referenced in Step 5's export-strategy guidance |
| Generic services-as-persistence registry structure and hunt patterns | [`10 - Persistence Mechanisms/Services`](<../10 - Persistence Mechanisms/Services.md>) | NTDS/Netlogon/DFSR/DNS are ordinary Windows services under the hood — this note's Service Fundamentals table is the DC-specific instance of that general model |
| Ransomware/credential-theft playbook context if this DC compromise is part of a broader incident | [`Threat Landscape and Playbooks/Ransomware Playbook`](<../Threat Landscape and Playbooks/Ransomware Playbook.md>) | A compromised DC is frequently the domain-wide staging point for the deployment phase that playbook covers |

## Resources

- Microsoft Learn — `ntdsutil` command reference (IFM, database maintenance): https://learn.microsoft.com/windows-server/administration/windows-commands/ntdsutil
- Microsoft Learn — `repadmin` command reference: https://learn.microsoft.com/windows-server/administration/windows-commands/repadmin
- Microsoft Learn — DFS Replication and `dfsrdiag`/`dfsrmig`: https://learn.microsoft.com/windows-server/storage/dfs-replication/dfsr-overview
- Microsoft Learn — Windows Time Service technical reference (domain hierarchy, PDC emulator role): https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tech-ref
- Microsoft Learn — DNS global query block list (WPAD/ISATAP protection): https://learn.microsoft.com/windows-server/networking/dns/dns-top-new
- MITRE ATT&CK **T1003.003** (OS Credential Dumping: NTDS): https://attack.mitre.org/techniques/T1003/003/
- MITRE ATT&CK **T1207** (Rogue Domain Controller): https://attack.mitre.org/techniques/T1207/
- MITRE ATT&CK **T1484** (Domain Policy Modification): https://attack.mitre.org/techniques/T1484/
- MITRE ATT&CK **T1558** (Steal or Forge Kerberos Tickets): https://attack.mitre.org/techniques/T1558/
- DCShadow technique background (as popularized alongside Mimikatz) — treat any specific implementation detail against current tooling documentation rather than this note's summary alone
- SANS FOR508 course syllabus (public) — Domain Controller/AD infrastructure investigation checklist
