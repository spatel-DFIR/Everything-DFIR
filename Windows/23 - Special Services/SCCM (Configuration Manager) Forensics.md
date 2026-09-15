# SCCM (Configuration Manager) Forensics

Microsoft Endpoint Configuration Manager — SCCM, MECM, formerly "ConfigMgr" — is a systems-management platform built to do exactly one thing at massive scale: get code running on every endpoint it manages, on command, with SYSTEM-level rights, with no user interaction required. That is precisely what software deployment, OS deployment, and remote scripting are *for*. It is also precisely what an attacker wants. An intruder who compromises SCCM console rights (or the account SCCM itself uses to push its client to new machines) doesn't need to re-invent PsExec, WMI, or PowerShell Remoting — the fleet-wide, authenticated, SYSTEM-context remote-execution channel is already built, already trusted by every endpoint firewall rule, and already exempt from the scrutiny a brand-new remote-admin tool would attract. This note treats SCCM as what it actually is in a modern enterprise: a fully legitimate management platform *and* one of the highest-leverage attack platforms an adversary can gain a foothold in.

> 🔴 **A working SCCM deployment IS a working "run code on any/every managed endpoint" primitive — including Domain Controllers, if they're managed clients.** The question mid-incident is never "could an attacker use SCCM to move around" (they always could, that's the product's job) — it's "did *this* deployment/script/collection change go through change management, or did it originate from an account or timing pattern nobody can account for."

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [SCCM Architecture & Site Roles](#sccm-architecture--site-roles)
- [Reading CMTrace-Format Logs](#reading-cmtrace-format-logs)
- [Investigation Workflow](#investigation-workflow)
  - [Step 1 — Identify the Site Role(s) in Play](#step-1--identify-the-site-roles-in-play)
  - [Step 2 — Locate the Logs](#step-2--locate-the-logs)
  - [Step 3 — Authorized Change vs Attacker Activity](#step-3--authorized-change-vs-attacker-activity)
  - [Step 4 — Application/Package Deployment Abuse (T1072)](#step-4--applicationpackage-deployment-abuse-t1072)
  - [Step 5 — Collection Membership Abuse](#step-5--collection-membership-abuse)
  - [Step 6 — Run Scripts / CMPivot Abuse](#step-6--run-scripts--cmpivot-abuse)
  - [Step 7 — Network Access Account (NAA) Credential Theft](#step-7--network-access-account-naa-credential-theft)
  - [Step 8 — OSD / Task Sequence Credential Exposure](#step-8--osd--task-sequence-credential-exposure)
  - [Step 9 — Client Push Installation Account Abuse](#step-9--client-push-installation-account-abuse)
  - [Step 10 — Status Message / Audit Review for Attribution](#step-10--status-message--audit-review-for-attribution)
- [SCCM Site Server as a Tier-0-Adjacent Asset](#sccm-site-server-as-a-tier-0-adjacent-asset)
- [Investigative Sequence Summary](#investigative-sequence-summary)
- [Persistence / Backdoor Patterns Specific to SCCM](#persistence--backdoor-patterns-specific-to-sccm)
- [Red Flags](#red-flags)
- [Tooling](#tooling)
- [MITRE ATT&CK Techniques Covered](#mitre-attck-techniques-covered)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Unlike most notes in this module, several of these are **not purely native** — they assume the ConfigMgr PowerShell module (ships with the console install, not a separate download; import via `Import-Module (Join-Path (Split-Path $env:SMS_ADMIN_UI_PATH) ConfigurationManager.psd1)` then `cd` into the site's PSDrive, e.g. `cd XYZ:`) is loaded on an admin workstation or the site server itself. Where a check is genuinely native (plain log reads, WMI), it's called out.

```powershell
# Every Application, newest-first, with who created/last touched it - the fastest way to spot an out-of-cycle addition
Get-CMApplication | Select-Object LocalizedDisplayName, DateCreated, DateLastModified, CreatedBy | Sort-Object DateCreated -Descending

# Deployments currently targeted at the broadest collections in the hierarchy - maximum blast radius, check every one
Get-CMDeployment | Where-Object { $_.CollectionName -in @('All Systems','All Desktop and Server Clients','All Users and User Groups') } |
    Select-Object ApplicationName, PackageName, CollectionName, DeploymentTime

# Every script in the Run Scripts library with its author AND approver - author == approver is a two-person-rule bypass
Get-CMScript | Select-Object ScriptName, Author, Approver, ApprovalState, LastUpdateTime

# Collections sorted by most recent membership change - a newly-touched, narrowly-scoped collection is the "stay under the radar" pattern (Step 5)
Get-CMCollection | Select-Object Name, CollectionType, LastMemberChangeTime, MemberCount | Sort-Object LastMemberChangeTime -Descending

# Native, no module required: tail a client's execution-enforcement log for script-interpreter/LOLBAS command lines
Get-Content "$env:WinDir\CCM\Logs\AppEnforce.log" -Tail 200 | Select-String 'powershell\.exe|cmd\.exe|cscript|wscript'

# Native: does this client have a cached Network Access Account policy secret? (Presence check only - this is the same query attacker tooling runs; see Step 7)
Get-CimInstance -Namespace 'root\ccm\policy\Machine\ActualConfig' -ClassName CCM_NetworkAccessAccount -ErrorAction SilentlyContinue

# Native: recent client-push install activity landing on this endpoint, source site server and account context
Get-Content "$env:WinDir\ccmsetup\Logs\ccmsetup.log" -Tail 200 -ErrorAction SilentlyContinue | Select-String 'Successfully|Remote Client|Executing install'

# Server-side: recent object-change status messages for Application/Package/Script/Collection classes (Step 10) - requires the SMS Provider / ConfigMgr module
Get-CMStatusMessage -ViewName 'v_StatusMessage' -MessageID 30001,30002,30003 -ErrorAction SilentlyContinue |
    Select-Object Time, Component, MachineName, MessageID | Sort-Object Time -Descending
```

## SCCM Architecture & Site Roles

SCCM is a **hierarchy**, not a single server — an attacker's reach, and an analyst's blast-radius question, depend entirely on which role in that hierarchy has been touched. Orient here before doing anything else.

```
┌───────────────────────────────────────────┐
│  CAS — Central Administration Site         │   Optional: only present in hierarchies
│  (no clients assigned directly;            │   large enough to need multiple Primaries
│   aggregates data from all Primaries)      │   (historically ~150K+ clients)
└───────────────────┬─────────────────────────┘
                     │
        ┌────────────┴─────────────┐
        │                           │
┌───────▼─────────┐       ┌─────────▼────────┐
│  Primary Site A   │       │  Primary Site B   │   Manages clients directly; owns a
│  (+ site DB on     │       │  (+ site DB on     │   SQL Server backend (local or remote —
│   SQL Server)       │       │   SQL Server)       │   see SQL Server Forensics.md, this folder)
└───────┬───────────┘       └───────────────────┘
        │
┌───────▼───────────┐
│  Secondary Site     │   Optional: extends a Primary to a bandwidth-
│  (forwards to        │   constrained location; no console of its own
│   parent Primary)    │
└───────┬───────────┘
        │
   ┌────┴─────────────────────┐
   │                           │
┌──▼───────────────┐   ┌───────▼──────────┐
│ Management Point   │   │ Distribution Point │   MP = client policy/check-in broker.
│ (MP)                │   │ (DP)                │   DP = hosts package/app/OS-image content
└──┬────────────────┘   └───────────────────┘   for clients to pull down.
   │
┌──▼──────────────────────────────────────────┐
│   Managed Clients (ccmexec.exe / "SMS Agent Host")│  Workstations, member servers —
│   potentially thousands, potentially including      │  and, if enrolled, Domain Controllers
│   Domain Controllers                                  │
└───────────────────────────────────────────────┘
```

| Role | Function | Forensic significance |
|---|---|---|
| **CAS** (Central Administration Site) | Top of the hierarchy; no clients assigned to it directly; aggregates reporting/administration across all child Primary Sites | Compromise here means hierarchy-wide visibility and, depending on console rights granted, hierarchy-wide administrative reach |
| **Primary Site** | Manages a set of clients directly; hosts (or connects to) the site database | Compromise = control over every client assigned to this site, plus a console access point into the hierarchy |
| **Secondary Site** | Extends a Primary Site's reach into a bandwidth-constrained location; has no site database or console of its own, forwards up to its parent Primary | Smaller local blast radius, but a compromised Secondary can still push content/policy to the clients it locally serves |
| **Management Point (MP)** | The role clients talk to for policy retrieval and status/inventory reporting | A tampered MP is a policy-injection/interception surface — clients trust what the MP hands them |
| **Distribution Point (DP)** | Hosts package/application/OS-image content for clients to pull down over HTTP(S)/SMB/BranchCache | Can be used to host attacker payload content disguised as a legitimate package, or to stage the boot images used in OSD |
| **SQL Server backend (site database)** | The authoritative store for every deployment, collection, script, task sequence, discovery, and (per below) status-message/audit record in the site | Read/write access to the site database is close to equivalent to console access — see the sibling **SQL Server Forensics.md** in this folder for the general SQL-Server-as-attack-surface treatment |
| **Clients** | Endpoints running the Configuration Manager client (`ccmexec.exe`, installed as the `CcmExec` service — see **Services.md**, note 10, for the general service-persistence angle) | The end of the chain — where deployed applications, scripts, and task sequences actually execute, almost always as SYSTEM |

🔴 **The single question that sets the scope of every investigation in this note: is a Domain Controller a managed client of this hierarchy?** If yes, everything below is a domain-compromise investigation wearing an SCCM hat — see [SCCM Site Server as a Tier-0-Adjacent Asset](#sccm-site-server-as-a-tier-0-adjacent-asset).

## Reading CMTrace-Format Logs

Both server-side component logs and client-side logs use the same **CMTrace** line format — a single-line, self-describing record readable in any text editor or `Get-Content`, but far easier to triage in the actual **CMTrace.exe** tool (color-codes errors/warnings, live-tails, supports fast text search across an open log).

```
<![LOG[Message text describing what the component did]LOG]!><time="14:22:07.415+300" date="07-19-2026" component="SMS_EXECUTIVE" context="" type="1" thread="4032" file="smsexec.cpp:2841">
```

| Field | Meaning |
|---|---|
| Bracketed message body | The actual log line text — this is what you read/grep first |
| `time` | Local time, with UTC offset in minutes appended (`+300` = 5 hours behind UTC) — 🔴 note the offset, don't assume the log's local time matches your analysis workstation's |
| `date` | `MM-dd-yyyy` |
| `component` | Which SCCM component/thread family wrote this line (e.g. `SMS_EXECUTIVE`, `PolicyProvider`, `distmgr` server-side; `execmgr`, `AppEnforce`, `ccmexec` client-side) — the fastest filter when a log has interleaved output from multiple subsystems |
| `type` | `1` = Informational · `2` = Warning · `3` = Error — filter to `2`/`3` for a fast first pass, but don't stop there: the interesting line in an abuse investigation ("deployment created," "script approved and run") is routinely logged as plain Informational, not a warning or error |
| `thread` | Thread ID that wrote the line — useful for reconstructing one execution sequence out of an interleaved multi-thread log |
| `file` | Source file/line in the SCCM binary that emitted the message — mostly useful for correlating against Microsoft's own log-reference documentation when a message is cryptic |

**Key server-side logs** (default `<InstallDir>\Logs\*.log`, typically `%ProgramFiles%\Microsoft Configuration Manager\Logs\` on the site server):

| Log | What it records |
|---|---|
| `SMS_Executive.log` | The parent process log for most site-server component threads — often the first place a component-level error or unexpected startup shows up |
| `hman.log` (Hierarchy Manager) | Site configuration and hierarchy-relationship changes — new site additions, hierarchy topology changes |
| `distmgr.log` (Distribution Manager) | Content distribution to Distribution Points — package/application content being pushed, updated, or hashed for a DP |
| `policypv.log` (Policy Provider) | Policy object creation — deployments, once created, become policy that this component turns into what clients actually retrieve |
| `colleval.log` (Collection Evaluator) | Collection membership evaluation — when a collection's membership was last (re)computed and why |

**Key client-side logs** (default `%WinDir%\CCM\Logs\`):

| Log | What it records |
|---|---|
| `ccm.log` / `ccmexec.log` | The CCM client's own general-purpose activity log — client health, policy processing overview |
| `execmgr.log` | Execution Manager — tracks program/application execution requests as the client processes them |
| `AppEnforce.log` | **Application enforcement** — the actual install/run action for a deployed Application, including the exact command line executed |
| `AppDiscovery.log` | Application **detection** logic — whether the client considers an app already present/compliant |
| `PolicyAgent.log` | Policy retrieval from the Management Point — what policy (including deployments) the client just pulled down |
| `ccmsetup.log` | Client installation/reinstallation — the log to check first for Client Push Installation Account activity (Step 9) |
| `smsts.log` | **Task sequence execution** — the OSD/task-sequence log; lives at `X:\Windows\Temp\SMSTSLog\smsts.log` during WinPE, `C:\_SMSTaskSequence\Logs\Smstslog\smsts.log` immediately post-OS-install, and finally `C:\Windows\CCM\Logs\Smstslog\smsts.log` once the full client is installed — see Step 8 |

## Investigation Workflow

### Step 1 — Identify the Site Role(s) in Play

Before pulling a single log, establish which box you're standing on, using the architecture table above as the map. A workstation showing unexpected software is a *downstream symptom*; the *cause*, and the evidence that will actually explain it, lives upstream at whichever site server issued the policy. Confirm role via `Get-CMSite`/`Get-CMSiteRole` from an admin console session, or, on the box itself, check for the presence of `SMS_Executive` (any site server role) vs. just `CcmExec` (a client-only box) among installed services, and cross-reference `HKLM:\SOFTWARE\Microsoft\SMS\Identification` for site code and role flags.

### Step 2 — Locate the Logs

Pull the server-side and client-side logs named in [Reading CMTrace-Format Logs](#reading-cmtrace-format-logs) above, scoped to the incident window. For a multi-host incident, collect from **both ends** of every suspected action: the site server (what was authored/deployed) and the affected client(s) (what actually landed and ran) — a deployment that never reached a client because of a targeting scope difference is a materially different finding than one that reached and executed everywhere.

### Step 3 — Authorized Change vs Attacker Activity

The hardest part of this investigation is rarely finding *a* deployment, script, or collection change — SCCM environments have those constantly, that's the product working as intended. The hard part is separating legitimate change-management activity from attacker abuse of the same mechanism. Work every finding below through this table before escalating it:

| Signal | Looks like authorized change | Looks like attacker abuse |
|---|---|---|
| Timing | Falls inside a published change window / CAB-approved schedule | Off-hours, no corresponding ticket, or immediately following other suspicious activity on the same admin's session |
| Creator/actor account | A named admin account with a normal, established history of SCCM administration | A newly created or recently elevated console admin, or an established admin's account acting wildly outside its normal pattern |
| Target collection | Scoped and named to match a documented business purpose ("Finance-Laptops-Q3-Patch") | Targets `All Systems`/`All Desktop and Server Clients` for a mass push, **or** a newly created, narrowly-scoped collection that happens to match a set of high-value assets (see Step 5) |
| Content/source | A known, versioned software package from an established internal repository | Newly staged content in an unfamiliar source path, generic or mismatched naming, a hash that doesn't correspond to any known vendor release |
| Command line (`AppEnforce.log`) | An MSI/EXE installer with documented, expected switches | `powershell.exe -enc`, `cmd.exe /c`, `cscript`/`wscript`, or other LOLBAS-style invocation embedded in the deployment's install command |
| Approval trail (Run Scripts) | A change ticket number is referenced; script approver is a **different** admin than the author, per the two-person-rule default | No ticket, no approval record, or approver account is identical to the author account |

### Step 4 — Application/Package Deployment Abuse (T1072)

An admin (or a compromised account holding the "Application Author"/"Application Deployment Manager" role, or a broader Full Administrator grant) can create an Application or Package and deploy it to **any collection in the hierarchy — including `All Systems`.** This is the headline technique in this note: software deployment, working exactly as designed, used to run attacker code as SYSTEM on every managed endpoint in one action.

**Evidence chain:**

| Source | What it shows |
|---|---|
| `Get-CMApplication` / `Get-CMPackage` | Every current Application/Package object, creation and last-modified timestamps, creator account |
| `Get-CMDeployment` | Which collection(s) each Application/Package is actually targeted at, and when the deployment was created |
| `distmgr.log` (site server) | Content distribution events — when the package's content was pushed to which DPs, and the content hash SCCM computed for it |
| `policypv.log` (site server) | The deployment becoming policy — the point at which clients start being told about it |
| `AppDiscovery.log` / `AppEnforce.log` (client) | Detection logic result and the exact enforcement command line executed on the endpoint |
| Site database (`v_StatusMessage` and related views) | Object-creation/modification status messages, queryable by object type and time — see Step 10 |

To enumerate every deployment currently active using PowerShell, list the broadest collections first:

```powershell
Get-CMDeployment | Sort-Object DeploymentTime -Descending | Select-Object ApplicationName, PackageName, CollectionName, DeploymentTime, OfferTypeID
```

To flag deployments whose enforcement command line invokes a script interpreter rather than a normal installer using PowerShell, cross-reference the client-side enforcement log:

```powershell
Get-Content "$env:WinDir\CCM\Logs\AppEnforce.log" | Select-String 'CommandLine' |
    Where-Object { $_ -match 'powershell\.exe|cmd\.exe /c|cscript|wscript|-enc(odedcommand)?' }
```

To cross-reference every Application's creator using PowerShell against a known-admin roster, surfacing anything created by an unrecognized or unexpected account:

```powershell
$knownAdmins = Get-Content C:\hunt\known_sccm_admins.txt
Get-CMApplication | Where-Object { $_.CreatedBy -notin $knownAdmins } |
    Select-Object LocalizedDisplayName, CreatedBy, DateCreated
```

### Step 5 — Collection Membership Abuse

Deploying to `All Systems` is loud. A more careful attacker instead targets a **narrow, high-value collection** — Domain Controllers, a Tier-0 admin workstation pool, backup servers — so the malicious deployment reaches only the machines that matter, staying well under the radar of any monitoring tuned to notice fleet-wide pushes. This can happen two ways: creating a brand-new collection scoped to the target set, or quietly editing an **existing** collection's membership rule (adding a direct-membership device, or altering a query-based collection's WQL) so a target machine falls into a collection that already has a deployment attached to it.

**Hunt for:** collections created or last-modified recently, with a membership set that maps suspiciously well onto a sensitive asset class (server naming convention for DCs, an OU filter that resolves to Tier-0 systems); direct-membership additions with no corresponding change ticket; a collection's WQL query rule silently altered to widen its scope.

To list collections by most recent membership change using PowerShell, cross-referenced against member count to spot a small, recently-touched collection worth a closer look:

```powershell
Get-CMCollection | Where-Object { $_.LastMemberChangeTime -gt (Get-Date).AddDays(-7) } |
    Select-Object Name, CollectionType, MemberCount, LastMemberChangeTime | Sort-Object LastMemberChangeTime -Descending
```

For a specific suspect collection, pull its direct-membership rules and WQL query rule using PowerShell (if any) to see exactly what defines membership:

```powershell
Get-CMDeviceCollectionDirectMembershipRule -CollectionName '<SuspectCollectionName>'
Get-CMDeviceCollectionQueryMembershipRule -CollectionName '<SuspectCollectionName>' | Select-Object QueryExpression
```

### Step 6 — Run Scripts / CMPivot Abuse

🔴 **This is the single highest-value attacker primitive covered in this note.** CMPivot (real-time, ad hoc query against live device state across a collection) and the **Run Scripts** feature (author, approve, and execute an arbitrary PowerShell script against any device or collection, on demand, with results streamed back to the console) both do the same thing an attacker ultimately wants from any lateral-movement or remote-execution technique — run code on managed endpoints, as SYSTEM by default — **without creating an Application/Package object, without staging content on a Distribution Point, and without the distribution-latency that Step 4's technique requires.** Where deployment abuse leaves a content-distribution and policy trail across `distmgr.log`/DPs, Run Scripts/CMPivot rides the existing client policy/command channel directly — a thinner trail, and a genuine blind spot for defenders who are only watching for new Application/Package objects.

**The built-in control**, and the finding that matters most: by default, a newly authored script requires **approval by an administrator other than its author** before it can run (a hierarchy-wide setting, togglable — confirm it's actually enabled in the environment under investigation rather than assuming it). An attacker who controls two console-privileged accounts (or a single account with a permissive custom role that grants both author and approve rights) can self-approve; an attacker who controls only one properly-scoped account cannot run a new script at all without a second admin unknowingly approving it — making the approval trail itself one of the most valuable pieces of evidence in this whole note.

**Evidence chain:** the script library (content, author, approval state, approver, last-run history) lives in the site database, browsable via the console's Monitoring workspace → Scripts node, or queried directly — see the sibling **SQL Server Forensics.md** in this folder for the general technique of querying the site database directly for a longer retention window than the console UI's default filtered view. Client-side, a Run Scripts execution rides the same policy/execution channel as any other client-side script activity — confirm current component-log naming for the specific ConfigMgr version in scope (this has shifted across releases; don't hard-code a single log name from memory), and correlate against the endpoint's own execution evidence: a `powershell.exe` process spawned under the CCM client's context around the reported execution time, Prefetch/ShimCache/Amcache for that process (see note 06), and PowerShell Script Block Logging (4104, note 11) if enabled on the endpoint.

To pull the full script library with its approval metadata using PowerShell:

```powershell
Get-CMScript | Select-Object ScriptName, Author, Approver, ApprovalState, LastUpdateTime, ScriptGuid
```

To flag the two highest-value findings directly using PowerShell — self-approved scripts and scripts approved but never actually reviewed against their content:

```powershell
Get-CMScript | Where-Object { $_.Author -eq $_.Approver -and $_.ApprovalState -eq 'Approved' } |
    Select-Object ScriptName, Author, Approver, LastUpdateTime
```

For a specific suspect script, pull its execution history using PowerShell (which devices/collections it ran against and when) to bound the affected-host list:

```powershell
Get-CMScriptExecutionStatus -ScriptGuid '<ScriptGuid>' | Select-Object DeviceName, ScriptExecutionState, LastUpdateTime
```

To revoke approval and remove a script using PowerShell once its content and execution scope are fully documented as evidence:

```powershell
Set-CMScript -ScriptGuid '<ScriptGuid>' -ApprovalState Denied
Remove-CMScript -ScriptGuid '<ScriptGuid>' -Force
```

### Step 7 — Network Access Account (NAA) Credential Theft

The **Network Access Account** is a long-documented SCCM credential-theft vector, configured at the site level (Site Configuration → Sites → Configure Site Components → Software Distribution → Network Access Account) for the narrow case where a client needs to reach content on a Distribution Point but has no computer-account identity yet to authenticate with — chiefly during OS Deployment in WinPE, before the machine has joined the domain or has a client identity of its own.

That credential is cached client-side as an encrypted policy secret, in WMI under the `CCM_NetworkAccessAccount` class in the `root\ccm\policy\Machine\ActualConfig` namespace. It is protected, but decryptable by **any account with local administrator rights on that client** — which is a materially low bar across a large managed estate, and is the entire reason this is a well-established attack vector rather than a theoretical one.

🔴 **Whether NAA extraction is a low-severity local finding or a domain-wide incident depends entirely on what the NAA account is actually permitted to do in AD.** Best practice is a dedicated, minimally-privileged account limited to read access on DP content shares — but real environments routinely provision an overly broad account (sometimes even a domain-privileged one) for convenience. Confirm the NAA's actual AD group memberships and effective rights as part of this step; do not assume "just a content-read account" without checking.

To perform a presence check on a client using PowerShell (native, no module — this is also exactly what attacker tooling queries, so treat a hit as scope-relevant, not as proof of abuse on its own):

```powershell
Get-CimInstance -Namespace 'root\ccm\policy\Machine\ActualConfig' -ClassName CCM_NetworkAccessAccount -ErrorAction SilentlyContinue
```

Once the NAA account name is known using PowerShell (from site configuration, not from the encrypted client-side blob), pull its actual AD group memberships to scope real-world impact:

```powershell
Get-ADUser -Identity '<NAA-SamAccountName>' -Properties MemberOf | Select-Object -ExpandProperty MemberOf
```

To rotate the NAA credential at the site using PowerShell (native console/PowerShell action) and re-scope its AD rights to least-privilege if the review above found it over-provisioned, consult note 21 for full account-remediation sequencing.

### Step 8 — OSD / Task Sequence Credential Exposure

Task sequences used for Operating System Deployment routinely embed credentials needed mid-build, before the machine has any other way to authenticate — most notably a **domain-join account** (via the "Join Domain or Workgroup" step, or `OSDJoinAccount`/`OSDJoinPassword` task sequence variables), and sometimes local administrator password–setting steps or alternate credentials for an "Install Software"/"Run Command Line" step. These values are stored with light, reversible obfuscation in the task sequence definition — not strong encryption — and historically could also leak into `smsts.log` itself if a variable wasn't explicitly flagged as sensitive/hidden, or if logging verbosity was left too high during troubleshooting.

**Hunt for:** any `Set Task Sequence Variable` step whose variable is not marked sensitive; exported task sequence XML (`Get-CMTaskSequence` + export) containing recoverable credential material; `smsts.log` files — including ones left behind on decommissioned or re-imaged machines under `C:\_SMSTaskSequence\Logs\Smstslog\` or `C:\Windows\CCM\Logs\Smstslog\` — containing cleartext values that should never have been logged.

**Attack path:** an attacker with read access to the task sequence definition (via console rights) or to boot media/PXE content extracts the embedded domain-join credential directly — no client compromise required at all, since the credential lives in the deployment artifact itself.

To export a task sequence using PowerShell for manual review of embedded variables:

```powershell
Get-CMTaskSequence | Select-Object Name, LastRefreshTime
Export-CMTaskSequence -Name '<TaskSequenceName>' -ExportFilePath 'C:\hunt\ts_export.xml'
```

To grep an exported task sequence or an `smsts.log` using PowerShell for the classic leaked-variable pattern:

```powershell
Select-String -Path 'C:\hunt\ts_export.xml' -Pattern 'OSDJoinAccount|OSDJoinPassword|password' -SimpleMatch
Select-String -Path '<path-to-smsts.log>' -Pattern 'password' -SimpleMatch
```

### Step 9 — Client Push Installation Account Abuse

The **Client Push Installation Account** is a privileged account SCCM itself uses to remotely install the CCM client onto newly discovered systems, mechanically identical to how PsExec/`sc create` push a service onto a remote host — the account needs, and uses, local administrator rights on the target over `ADMIN$`/SMB (see **Services.md** and **12 - Lateral Movement**, note 12, for the general remote-service-install evidence chain this rides on top of). If an attacker compromises this account — cached on the site server, and sometimes configured as a small pool of fallback accounts — they gain **push-based lateral movement against every system the site has discovery data and rights for**, entirely independent of the Application/Package deployment channel covered in Step 4.

**Evidence:** on the target, `ccmsetup.log` records an inbound client-push install with the source site server and account context; server-side, the push originates from the SMS Client Configuration Manager component. Correlate `ADMIN$` share-access events (Security 5140, note 12) sourced from the site server against the expected discovery/push schedule — a push to an already-managed client, or a push targeted at a host with no legitimate reason to be freshly enrolled, is the tell.

To check a target's client-push install history using PowerShell natively:

```powershell
Get-Content "$env:WinDir\ccmsetup\Logs\ccmsetup.log" -ErrorAction SilentlyContinue | Select-String 'Remote Client|Executing install|CCMSetup'
```

To pair `ADMIN$` share access from the site server using PowerShell (note 12's evidence chain) against unexpected/repeat client-push events, using the same timing-pairing logic as PsExec detection elsewhere in this module:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5140} -MaxEvents 200 |
    Where-Object { $_.Message -match 'ADMIN\$' -and $_.Message -match '<SiteServerName>' }
```

### Step 10 — Status Message / Audit Review for Attribution

Every finding above eventually needs to answer "who did this, and when." SCCM's built-in status-message subsystem records object creation/modification/deletion — Applications, Packages, Deployments, Collections, Scripts — with the acting account, timestamp, and site, browsable through the console's **Monitoring → System Status → Status Message Queries** workspace, or queryable directly against the site database for a longer retention window and more flexible filtering than the console's default views (see the sibling **SQL Server Forensics.md**, this folder, for the general technique of querying the site database directly).

**Process:** pull every object-creation/modification status message inside the incident window, resolve each to an account and a change-ticket reference, and treat any entry with **no corresponding ticket** as the working hypothesis for attacker activity — to be confirmed or ruled out against the Step 4–9 findings above. This is the step that turns a pile of individual findings ("a suspicious deployment," "a self-approved script") into an attributed timeline.

## SCCM Site Server as a Tier-0-Adjacent Asset

A site server (or its SQL Server backend, which holds the authoritative record of every deployment, collection, script, and task sequence the site will act on) that is fully compromised — and where the attacker has, or can obtain, unconstrained deployment rights against a collection containing Domain Controllers — is functionally equivalent to domain compromise. The mechanism doesn't need to be exotic: Step 4's deployment-abuse technique, pointed at a DC collection, runs attacker code as SYSTEM on a Domain Controller using functionality SCCM ships with by default. This is why SCCM site servers (and, by extension, their SQL Server backends) are properly classified as Tier-0 or Tier-0-adjacent assets in a well-run AD administrative-tiering model — see **05b - Active Directory & Domain Forensic Artifacts.md** for the tiering model itself; this note doesn't re-derive that theory, only makes explicit that SCCM is one of the more common ways an environment ends up violating it in practice, often without anyone having framed the site server that way beforehand.

## Investigative Sequence Summary

```
1. Identify site role(s) in play
   Console/Get-CMSite, or local role indicators on the box itself
   → CAS / Primary / Secondary / MP / DP / SQL backend / client-only
                    │
2. Locate the logs
   Server: <InstallDir>\Logs\*.log  ·  Client: %WinDir%\CCM\Logs\*.log
   → read CMTrace format (time/date/component/type/thread)
                    │
3. Authorized change vs attacker activity baseline
   Timing · creator account · target collection · content source ·
   command line · approval trail
                    │
4. Application/Package deployment abuse (T1072)
   Get-CMApplication/Get-CMDeployment · distmgr.log · AppEnforce/AppDiscovery.log
                    │
5. Collection membership abuse
   Get-CMCollection · direct-membership/query-rule changes · narrow
   high-value targeting pattern
                    │
6. Run Scripts / CMPivot abuse  (highest-value primitive in this note)
   Get-CMScript · author == approver check · execution history
                    │
7. Network Access Account credential theft
   CCM_NetworkAccessAccount WMI class · NAA's real AD privileges
                    │
8. OSD / task sequence credential exposure
   Get-CMTaskSequence export · smsts.log leak check
                    │
9. Client Push Installation Account abuse
   ccmsetup.log push events · ADMIN$ (Security 5140) correlation (note 12)
                    │
10. Status message / audit review for attribution
   Status Message Queries / site DB · tie every finding to a ticket or
   flag it as unattributed
                    │
11. Scope the blast radius
   Is a DC a managed client of this hierarchy? → Tier-0-adjacent
   escalation (note 05b)
                    │
12. Hand off
   Lateral movement (note 12) if client-push/NAA reached other hosts ·
   SQL Server Forensics.md for site-database deep-dive ·
   Remediation and Containment (note 21)
```

## Persistence / Backdoor Patterns Specific to SCCM

| Pattern | Why it persists |
|---|---|
| A malicious deployment set to **Required** (not Available) | Reasserts itself at every machine policy polling cycle (commonly ~60 minutes, site-configurable) — removing the payload from an endpoint doesn't stop it from being reinstalled at the next policy refresh; the deployment object itself has to be found and deleted at the site, the direct SCCM analogue of a GPO-pushed logon script (see note 05b's GPO section for the AD-side equivalent) |
| A dynamic, **query-based collection** whose WQL rule auto-adds newly built/joined machines | A persistent deployment attached to that collection self-propagates to new assets with zero further attacker action — no need to re-target manually as the estate changes |
| A **Run Scripts** entry left in an Approved state in the script library | A rearmable, on-demand, fleet-wide execution capability that can be invoked again at any time without touching content distribution or Distribution Points at all |
| A rotated/altered Network Access Account or Client Push Installation Account credential | Denies legitimate admins the ability to use the account for its intended purpose while the attacker retains sole knowledge of the new value — a persistence-and-denial combination |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Deployment targeted at `All Systems`/`All Desktop and Server Clients` with no change ticket | Maximum blast-radius push through a channel most monitoring isn't tuned to watch |
| A newly created, narrowly-scoped collection whose membership maps onto a high-value asset class (DCs, Tier-0 workstations) | The "stay under the radar" targeting pattern — quieter than a broad push, but aimed at what matters most |
| Run Scripts entry where Author and Approver are the same account | Two-person-rule bypass — either a misconfiguration or an attacker controlling (or self-approving via) two privileged identities |
| Deployment/script command line invoking `powershell.exe -enc`, `cmd.exe /c`, or other LOLBAS-style syntax where a normal installer switch set is expected | Doesn't match the shape of legitimate software deployment |
| `CCM_NetworkAccessAccount` extracted or queried from a client with no legitimate OSD/PXE activity in progress | Credential-theft attempt against an account whose real domain privilege needs immediate verification |
| Task sequence variable holding a credential (`OSDJoinPassword` etc.) not flagged as sensitive/hidden | Recoverable cleartext-equivalent credential embedded in the deployment artifact itself |
| Unexpected Client Push Installation Account activity (`ccmsetup.log`) against an already-managed or unexplained target host | Push-based lateral movement using SCCM's own privileged installation account |
| Status-message object creation/modification with no corresponding change ticket | The core attribution gap this note's Step 10 is built to close |
| Object creation/modification status messages absent entirely for a period where deployments clearly changed | Possible auditing gap or log tampering — treat as its own finding, cross-reference note 19 for evidence-destruction indicators on the site server itself |

## Tooling

| Tool | Use |
|---|---|
| **SCCM/MECM Console** | Primary, native triage surface — Applications, Packages, Deployments, Collections, Scripts, and Monitoring/Status Message Queries all live here first |
| **CMTrace.exe** | Purpose-built viewer for the CMTrace log format — color-codes warnings/errors and live-tails; every log it reads is also plain-text readable via `Get-Content`/any text editor when CMTrace isn't available |
| **ConfigMgr PowerShell module** (`ConfigurationManager.psd1`, ships with the console) | `Get-CMApplication`, `Get-CMPackage`, `Get-CMDeployment`, `Get-CMCollection`, `Get-CMScript`, `Get-CMTaskSequence`, and the rest of the cmdlets used throughout this note's Investigation Workflow |
| **SQL Server Management Studio / `sqlcmd`** against the site database | Direct querying of the `CM_<SiteCode>` database — deployment history, status messages, and audit data beyond what the console UI's default filtered views surface; see the sibling **SQL Server Forensics.md**, this folder, for the general technique |
| **Status Message Viewer** (console, Monitoring workspace) | GUI front-end for the Step 10 audit-review process |
| **KAPE** (or equivalent log-collection tooling) | Bulk collection of `<InstallDir>\Logs\*.log` from site servers and `%WinDir%\CCM\Logs\*.log` from clients across an estate in one pass |

## MITRE ATT&CK Techniques Covered

| Technique | ID | Where in this note |
|---|---|---|
| Software Deployment Tools | T1072 | Step 4 (Application/Package deployment abuse) and Step 6 (Run Scripts/CMPivot) — the headline technique this note is built around |
| Valid Accounts | T1078 | Every step depends on a compromised console-privileged, NAA, or Client Push Installation account — Steps 4, 6, 7, 9 |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | Step 9 — Client Push Installation Account abuse rides the same `ADMIN$`/SMB mechanism as PsExec-style remote service installation |
| Unsecured Credentials | T1552 | Step 7 (NAA credential extraction from a locally-decryptable WMI policy secret) and Step 8 (task sequence variables holding domain-join/local-admin credentials) |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Step 6 — Run Scripts executes arbitrary PowerShell against managed endpoints |

## Correlate With

| To go deeper on… | Open |
|---|---|
| The `ADMIN$`/SMB mechanism Client Push Installation rides on, and the general remote-service evidence chain | [**12 - Lateral Movement**](<../12 - Lateral Movement.md>) and [**10 - Persistence Mechanisms/Services.md**](<../10 - Persistence Mechanisms/Services.md>) |
| Whether a Domain Controller being a managed client makes this a Tier-0 incident, and AD administrative-tiering theory generally | [**05b - Active Directory & Domain Forensic Artifacts.md**](<../05b - Active Directory & Domain Forensic Artifacts.md>) |
| The general remote-execution/scheduled-task parallel for reasoning about SCCM's Required-deployment persistence pattern | [**10 - Persistence Mechanisms/Scheduled Tasks.md**](<../10 - Persistence Mechanisms/Scheduled Tasks.md>) |
| Direct querying of the SCCM site database itself — the same SQL-Server-as-attack-surface techniques apply to the `CM_<SiteCode>` database | [**SQL Server Forensics.md**](<SQL Server Forensics.md>) (this folder) |
| SCCM/Intune as a fleet-wide software-inventory baseline source (the defensive-use angle, distinct from this note's attack-platform angle) | [**22 - Enterprise Management and Baseline.md**](<../22 - Enterprise Management and Baseline.md>) |
| Execution evidence (Prefetch/ShimCache/Amcache) for whatever a deployment or script actually launched on an endpoint | [**06 - Evidence of Program Execution**](<../06 - Evidence of Program Execution>) |
| Log clearing or evidence tampering on a compromised site server | [**19 - Anti-Forensics and Evidence Destruction.md**](<../19 - Anti-Forensics and Evidence Destruction.md>) |
| General Windows event-log mechanics for the Security-log evidence (5140, 4624) cited throughout this note | [**11 - Event Log Analysis.md**](<../11 - Event Log Analysis.md>) |

## Resources

- MITRE ATT&CK T1072 (Software Deployment Tools) — https://attack.mitre.org/techniques/T1072/
- MITRE ATT&CK T1078 (Valid Accounts) — https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK T1021.002 (Remote Services: SMB/Windows Admin Shares) — https://attack.mitre.org/techniques/T1021/002/
- MITRE ATT&CK T1552 (Unsecured Credentials) — https://attack.mitre.org/techniques/T1552/
- MITRE ATT&CK T1059.001 (Command and Scripting Interpreter: PowerShell) — https://attack.mitre.org/techniques/T1059/001/
- Microsoft Learn — Configuration Manager technical reference and log-file reference documentation (consult current documentation for the exact component-log set and behavior for the ConfigMgr version in scope — component logging has evolved across releases)
- Microsoft Learn — Network Access Account and Client Push Installation Account planning guidance
- SCCM/MECM's viability as an attack platform is well-documented in public offensive- and defensive-security research, including dedicated ConfigMgr attack/defense knowledge bases and open-source tooling built specifically around these techniques — consult current sources for tool-specific TTPs; the technique shapes described in this note reflect that established body of public research, written in original prose rather than reproduced from any single source
