# Microsoft Exchange Server Forensics

On-premises Microsoft Exchange Server (2016/2019, and the Exchange 2019-based "Subscription Edition" going forward) is one of the highest-value, highest-frequency intrusion targets in the entire Windows estate: it's internet-facing by design, it holds every mailbox in the organization, and — because of how deeply it's woven into Active Directory — a foothold on Exchange has repeatedly turned into a foothold on the domain. This note is written for the moment an analyst opens a shell on a compromised (or possibly-compromised) Exchange server and has to work the box top-to-bottom: what topology am I looking at, where are the logs, how do I read them, what does an intrusion actually look like in them, and what's the well-documented persistence/privilege-escalation playbook attackers have run against this platform for years.

> 🔴 **Scope boundary — read this first.** [`15 - Email Forensics`](<../15 - Email Forensics.md#on-premises-exchange-server-edbstmese>) already owns the mailbox-*format* and e-discovery angle of Exchange: EDB/STM/ESE internals, `eseutil`, `New-MailboxExportRequest`/`New-MailboxImportRequest`/ExMerge as collection mechanisms, and Compliance Search. **This note does not re-derive any of that.** This note's job is the **live-server intrusion-investigation angle** — Exchange's own operational logs, live hunting commands, and the specific attack/persistence patterns that show up on a compromised Exchange box. Where the two notes overlap (mailbox export, for example), this note treats the cmdlet as a hunting target ("did someone abuse this") rather than re-explaining the mechanic itself.

Exchange also runs entirely on top of **IIS** — every client protocol (OWA, ECP, EWS, ActiveSync, MAPI, Autodiscover) is an IIS-hosted web application under the hood. The general mechanics of IIS logging, application pools, and web-server compromise investigation belong to the sibling note [`IIS - Web Server Forensics.md`](<IIS - Web Server Forensics.md>) in this same folder — read that for the IIS layer generically. This note focuses on what's Exchange-specific sitting on top of that IIS foundation.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Investigation Workflow](#investigation-workflow)
  - [Step 1 — Identify the Topology](#step-1--identify-the-topology)
  - [Step 2 — Exchange on IIS: Virtual Directories](#step-2--exchange-on-iis-virtual-directories)
  - [Step 3 — Locate the Exchange-Specific Logs](#step-3--locate-the-exchange-specific-logs)
  - [Step 4 — Read the Logs Correctly](#step-4--read-the-logs-correctly)
  - [Step 5 — Hunt Commands](#step-5--hunt-commands)
  - [Step 6 — Web Shell and Transport Agent Persistence](#step-6--web-shell-and-transport-agent-persistence)
  - [Step 7 — Service Account and AD Permissions Abuse](#step-7--service-account-and-ad-permissions-abuse)
- [Investigative Sequence Summary](#investigative-sequence-summary)
- [Red Flags](#red-flags)
- [MITRE ATT&CK Techniques Covered](#mitre-attck-techniques-covered)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, Exchange Management Shell (EMS) one-liners for fast triage on a live Exchange server — run these from the Exchange Management Shell (or an EMS-loaded PowerShell session), not base Windows PowerShell; the `*-Mailbox*`, `*-TransportAgent`, `*-TransportRule`, and `*VirtualDirectory` cmdlet families are Exchange's own snap-in, not part of the OS.

```powershell
# Topology at a glance - server roles, DAG membership, and mounted databases in one pass (Step 1)
Get-ExchangeServer | Select-Object Name, Edition, ServerRole, AdminDisplayVersion
Get-DatabaseAvailabilityGroup | Select-Object Name, Servers
Get-MailboxDatabase -Status | Select-Object Name, Server, Mounted, MasterServerOrAvailabilityGroup

# HttpProxy log rows where AnchorMailbox doesn't match AuthenticatedUser - the single highest-value field pair for ProxyLogon/ProxyShell-class abuse (Step 4/5)
Get-ChildItem "$env:ExchangeInstallPath\Logging\HttpProxy" -Recurse -Filter *.log | ForEach-Object {
    $hdr = (Select-String -Path $_.FullName -Pattern '^#Fields: ' -List).Line -replace '#Fields: ',''
    if ($hdr) {
        Import-Csv -Path $_.FullName -Header ($hdr -split ',') |
            Where-Object { $_.AnchorMailbox -and $_.AuthenticatedUser -and $_.AnchorMailbox -ne $_.AuthenticatedUser -and $_.AnchorMailbox -notmatch '^Servername=' }
    }
} | Select-Object DateTime, ClientIpAddress, AuthenticatedUser, AnchorMailbox, UrlStem, HttpStatus

# Every enabled inbox rule across all mailboxes that forwards/redirects off-box AND silently deletes the copy - the classic BEC persistence shape (Step 5)
Get-Mailbox -ResultSize Unlimited | ForEach-Object {
    Get-InboxRule -Mailbox $_.Identity | Where-Object {
        ($_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo) -and $_.Enabled -eq $true
    } | Select-Object @{N='Mailbox';E={$_.MailboxOwnerId}}, Name, ForwardTo, RedirectTo, DeleteMessage, StopProcessingRules
}

# Org-wide transport rules with a redirect/BCC/forward action - the mailbox-count-agnostic, much-larger-blast-radius version of the rule above (Step 5)
Get-TransportRule | Where-Object { $_.RedirectMessageTo -or $_.BlindCopyTo -or $_.CopyTo } |
    Select-Object Name, State, Priority, RedirectMessageTo, BlindCopyTo, CopyTo

# Registered transport agents outside the small set Exchange ships by default - code-execution persistence inside the mail pipeline itself (Step 6)
Get-TransportAgent | Select-Object Name, Enabled, Priority, TransportAgentFactory

# Non-owner (Delegate/Admin) mailbox access in the last 14 days across every audited mailbox - flags silent access to a mailbox that isn't the account's own (Step 5)
Get-Mailbox -ResultSize Unlimited | Where-Object AuditEnabled -eq $true | ForEach-Object {
    Search-MailboxAuditLog -Identity $_.Identity -LogonTypes Delegate,Admin -StartDate (Get-Date).AddDays(-14) -EndDate (Get-Date) -ShowDetails
}

# Any unexpected .aspx under the physical directories backing OWA/ECP - treat every hit as critical until proven otherwise (Step 6)
Get-ChildItem "$env:ExchangeInstallPath\FrontEnd\HttpProxy\owa","$env:ExchangeInstallPath\FrontEnd\HttpProxy\ecp" -Recurse -Filter *.aspx -ErrorAction SilentlyContinue |
    Select-Object FullName, CreationTime, LastWriteTime, Length
```

## Investigation Workflow

### Step 1 — Identify the Topology

Before touching a single log, establish what you're actually looking at. Since Exchange 2013, the separate Client Access Server (CAS) role is gone as a distinct installable role — every Mailbox server runs both the mailbox databases **and** the full set of Client Access protocol front-ends (OWA, ECP, EWS, etc.) locally via IIS, then internally proxies requests to whichever server actually holds the mailbox's active database copy if it isn't the server that received the request. That internal front-end-to-back-end proxy behavior is exactly what makes the HTTP Proxy logs (Step 3/4) so valuable — every client request, no matter which server received it, gets logged with both where it came in and where it was routed to.

Mailbox databases sit inside a **Database Availability Group (DAG)** — a set of up to 16 Mailbox servers that host one or more databases, each database replicated as an active copy plus one or more passive copies kept in sync via continuous log shipping/replay (conceptually the mailbox-database analogue of AD's own multi-master replication). A DAG gives Exchange automatic database-level failover: if the server hosting the active copy of a database goes down, a passive copy on another DAG member can be activated. For an investigation this matters twice over: (1) the mailbox/data an attacker touched may have moved between physical servers over the incident timeline as failovers occurred, and (2) log collection has to span every DAG member, not just the server that happens to answer a given client request today.

| Cmdlet | What it tells you |
|---|---|
| `Get-ExchangeServer` | Every Exchange server in the org, its edition, version, and server role |
| `Get-ExchangeServer <name> \| fl` | Full detail on one server — useful for confirming CU/build level against known-vulnerable version ranges |
| `Get-DatabaseAvailabilityGroup` | DAG name and full member-server list |
| `Get-DatabaseAvailabilityGroupNetwork` | DAG replication/MAPI network configuration — relevant if replication traffic itself is in scope |
| `Get-MailboxDatabase -Status` | Every database, which server currently holds it, mount status |
| `Get-MailboxDatabaseCopyStatus -Server <name>` | Active vs. passive copy status per database on a given DAG member — tells you where the *live* database actually is right now |
| `(Get-ExchangeServer).AdminDisplayVersion` | Build number — cross-reference against Microsoft's published Cumulative Update/Security Update table to confirm patch level for the incident timeframe |

🔴 **Confirm the CU/SU (Cumulative Update / Security Update) level before assuming a given CVE-class attack does or doesn't apply.** Exchange patch level is a build number, not a version name — don't eyeball "Exchange 2019" and assume currency; pull the actual `AdminDisplayVersion` and cross-check it.

To identify topology and patch level in one pass, use this PowerShell:

```powershell
Get-ExchangeServer | Select-Object Name, Edition, ServerRole, AdminDisplayVersion, Site
Get-DatabaseAvailabilityGroup | Select-Object Name, @{N='Members';E={$_.Servers -join ', '}}
```

For each database, resolve which DAG member currently holds the active copy using PowerShell, so log collection can be scoped to the right servers instead of just the one an analyst happened to log into:

```powershell
Get-MailboxDatabase | ForEach-Object {
    Get-MailboxDatabaseCopyStatus -Identity $_.Name | Where-Object Status -eq 'Mounted' |
        Select-Object DatabaseName, Name, Status, ActivationSuspended
}
```

### Step 2 — Exchange on IIS: Virtual Directories

Every client protocol Exchange exposes is an IIS virtual directory, hosted across **two IIS sites on the same server**: `Default Web Site` (the front end, bound to the standard public-facing ports) and `Exchange Back End` (bound to 81/444, doing the actual mailbox work). A client request lands on the front end and, per Step 1, gets internally proxied to whichever server's back end actually holds the active database copy. General IIS site/app-pool/log mechanics belong to [`IIS - Web Server Forensics.md`](<IIS - Web Server Forensics.md>) — this section is only the Exchange-specific virtual directories layered on top of that.

| Virtual Directory | Protocol / Purpose | Get-* cmdlet |
|---|---|---|
| `/owa` | Outlook Web App — browser mailbox access | `Get-OwaVirtualDirectory` |
| `/ecp` | Exchange Control Panel — admin console and end-user self-service (password/delegate changes); also the endpoint behind several well-documented post-auth exploitation chains | `Get-EcpVirtualDirectory` |
| `/ews` | Exchange Web Services — the SOAP/XML API used by Outlook, mobile clients, and third-party integrations; also a favorite programmatic-access vector for attackers who've obtained credentials, since EWS is scriptable and doesn't require a browser session | `Get-WebServicesVirtualDirectory` |
| `/Microsoft-Server-ActiveSync` | Mobile device sync (EAS) | `Get-ActiveSyncVirtualDirectory` |
| `/autodiscover` | Client auto-configuration — historically the **first hop** in several well-documented pre-auth-to-post-auth exploitation chains, since it's reachable before a client has any other server information | `Get-AutodiscoverVirtualDirectory` |
| `/mapi` | MAPI over HTTP — the modern Outlook connectivity protocol | `Get-MapiVirtualDirectory` |
| `/rpc` | Outlook Anywhere (RPC over HTTP) — legacy, still present in 2016/2019 for backward compatibility | `Get-OutlookAnywhere` |
| `/powershell` | Remote PowerShell endpoint — the Exchange Management Shell's own remoting transport, and therefore an attack surface in its own right when reachable pre-auth or with weak auth | `Get-PowerShellVirtualDirectory` |
| `/oab` | Offline Address Book distribution | `Get-OabVirtualDirectory` |

🔴 **Check `InternalUrl`/`ExternalUrl` on every virtual directory for unexpected tampering.** Redirecting a virtual directory's advertised URL is a documented defense-evasion/redirection technique — a value pointing off-server or to an unfamiliar host is worth immediate follow-up.

To pull URL and auth configuration across every client protocol in one pass, use this PowerShell:

```powershell
'Owa','Ecp','WebServices','ActiveSync','Autodiscover','Mapi','OutlookAnywhere','PowerShell','Oab' | ForEach-Object {
    $cmd = "Get-${_}VirtualDirectory"
    if (Get-Command $cmd -ErrorAction SilentlyContinue) {
        & $cmd | Select-Object @{N='Type';E={$_}}, Server, InternalUrl, ExternalUrl
    }
}
```

### Step 3 — Locate the Exchange-Specific Logs

All paths below are relative to `$env:ExchangeInstallPath` (default `C:\Program Files\Microsoft\Exchange Server\V15\`).

| Log | Path | Value |
|---|---|---|
| **HTTP Proxy logs** | `Logging\HttpProxy\<Protocol>\` (subfolders: `Autodiscover`, `Owa`, `OwaCalendar`, `Ecp`, `Ews`, `Mapi`, `RpcHttp`, `PowerShell`, `Rpc`, `ActiveSync`, etc.) | 🔴 **The single highest-value log on the box for post-2021 CVE-driven intrusions.** Every client-protocol request, front-end to back-end, is recorded here with the `AnchorMailbox`/`AuthenticatedUser` field pair that is the direct smoking gun for the ProxyLogon/ProxyShell/ProxyNotShell class of pre-auth-to-post-auth exploitation chains — see Step 4 |
| **Message Tracking Logs** | `TransportRoles\Logs\MessageTracking\` | Every message that transited this server's transport pipeline — the mail-flow equivalent of a firewall connection log. Primary source for mass-mail/BEC-pattern hunting (Step 5) |
| **SMTP Protocol logs** | `TransportRoles\Logs\ProtocolLog\SmtpReceive\` and `\SmtpSend\` | Raw SMTP conversation-level logging (per-connector, off by default at verbose levels) — useful when message tracking alone doesn't show enough of the actual SMTP dialogue (e.g., confirming HELO/EHLO identity, TLS negotiation, or an anomalous connecting client) |
| **RPC Client Access logs** | `Logging\RPC Client Access\` | Legacy Outlook Anywhere/MAPI RPC connection logging — still relevant wherever `/rpc` is still in active use |
| **ECP logs** | `Logging\ECP\Server\` (admin-console-side) in addition to `Logging\HttpProxy\Ecp\` (proxy-side) | Exchange Control Panel activity — admin console usage is high-value given ECP's documented post-auth RCE history |
| **Admin Audit Log** | Queried via `Search-AdminAuditLog` / `New-AdminAuditLogSearch` (stored as hidden items inside the arbitration mailbox, not a flat file) | **Records every Exchange Management Shell cmdlet execution that changes configuration** — this is the fastest way to answer "what did the attacker actually run" once they had EMS access: `New-MailboxExportRequest`, `Install-TransportAgent`, `Set-Mailbox -ForwardingSmtpAddress`, `New-TransportRule`, permission grants, and so on all land here |
| **IIS logs** | `%SystemDrive%\inetpub\logs\LogFiles\` (both `Default Web Site` and `Exchange Back End` site folders) | The generic W3C web-server log underneath all of the above — see the sibling [`IIS - Web Server Forensics.md`](<IIS - Web Server Forensics.md>) note for general IIS log mechanics. Exchange's own HttpProxy logs are richer (application-layer, mailbox-aware) than the generic IIS log for this specific platform, but IIS logs remain useful for confirming raw connection-level detail (client IP, User-Agent, response codes) independent of the Exchange application layer |
| **Exchange Setup / ExPerfWiz / Application event log** | `ExchangeSetupLogs\`; Application log (`MSExchange*` sources) | Installation/configuration-change history and Exchange-sourced Windows Application-log events — general Application-log mechanics live in [`11 - Event Log Analysis`](<../11 - Event Log Analysis.md>) |

🔴 **Retention on these logs is short by default and independently configurable per log type** (commonly a rolling 30-day window, but this varies by log and by what an admin has changed it to) — collect early. A server under active investigation should have its `*.log`/`*.blg`-style rollover copied off before it ages out from underneath the investigation, exactly the same collection-race-condition logic that applies to Windows Event Logs generally (note 11).

To enumerate what's actually present and how far back it goes before assuming a given day's data still exists, use this PowerShell:

```powershell
Get-ChildItem "$env:ExchangeInstallPath\Logging\HttpProxy" -Recurse -Filter *.log |
    Measure-Object -Property LastWriteTime -Minimum -Maximum

Get-ChildItem "$env:ExchangeInstallPath\TransportRoles\Logs\MessageTracking" -Filter *.log |
    Sort-Object LastWriteTime | Select-Object -First 1 -Last 1 Name, LastWriteTime
```

To pull recent Admin Audit Log entries — the fastest single query to answer "what cmdlets ran here recently" — use this PowerShell:

```powershell
Search-AdminAuditLog -StartDate (Get-Date).AddDays(-14) -EndDate (Get-Date) |
    Select-Object Caller, RunDate, Cmdlet, CmdletParameters | Sort-Object RunDate -Descending
```

### Step 4 — Read the Logs Correctly

**Message Tracking Log fields** (relevant subset — the full schema is wider):

| Field | Meaning |
|---|---|
| `EventId` | What happened to the message at this hop — `RECEIVE`, `SEND`, `DELIVER`, `TRANSFER`, `FAIL`, `EXPAND`, `RESOLVE`, `REDIRECT`, `DSN` (delivery/non-delivery report), among others |
| `Source` | Which transport component logged the event — `SMTP`, `STOREDRIVER` (mailbox database delivery), `AGENT` (transport agent — see Step 6), `MAPI` |
| `Sender` | SMTP address of the sender for this hop |
| `Recipients` | SMTP address(es) of the recipient(s) for this hop — a single message can produce multiple tracking-log entries as it fans out |
| `MessageSubject` | 🔴 Only populated if subject logging is enabled — many environments disable this by default for privacy; don't assume it will be present, confirm against `Get-TransportConfig` before relying on subject-line data being there |
| `MessageId` | The message's internal SMTP Message-ID — the key to correlate the same message across multiple tracking-log hops/servers |
| `ClientIp` / `ServerIp` | Connecting client and receiving server IP for this hop |
| `TotalBytes` | Message size — useful for spotting an anomalously large outbound message (bulk exfiltration via email) |
| `ConnectorId` | Which Receive/Send connector handled this hop — useful for distinguishing internal mail flow from internet-facing connectors |

**HTTP Proxy Log fields** (relevant subset):

| Field | Meaning |
|---|---|
| `AuthenticatedUser` | The identity the client actually authenticated as for this request |
| `AnchorMailbox` | 🔴 **The routing hint the front-end proxy uses to decide which back-end server/database to forward the request to** — see explanation below |
| `ClientIpAddress` | Connecting client IP |
| `UrlHost` / `UrlStem` | Requested host and URL path |
| `HttpStatus` / `BackEndStatus` | Front-end and back-end HTTP status codes for the request — a mismatch between the two is itself sometimes diagnostic |
| `TargetServer` | The back-end server the request was actually proxied to |
| `HttpMethod` | GET/POST/PROPFIND/etc. |
| `AuthenticationType` | Basic, NTLM, Negotiate, OAuth, etc. |
| `TotalRequestTime` | Round-trip time for the request |

🔴 **Why `AnchorMailbox` is the smoking-gun field.** Exchange's front-end proxy layer doesn't itself know which back-end server holds a given mailbox's active database copy — it has to be told, and `AnchorMailbox` (populated from a request header/cookie or derived from the URL) is how. Under normal client behavior, `AnchorMailbox` correlates directly with the authenticated user's own mailbox — an authenticated user's client tells the proxy "route me based on my own mailbox," which is a boring, expected, self-referential value. The well-documented **ProxyLogon/ProxyShell/ProxyNotShell class** of pre-auth exploitation chains (publicly disclosed and widely exploited from 2021 onward) worked by manipulating this exact routing mechanism — supplying an `AnchorMailbox` (or an equivalent backend-routing header) that points at an **unrelated, unexpected, or administrative mailbox** rather than the requesting identity's own, coercing the front-end proxy into forwarding a request to a back-end target the attacker had no legitimate business reaching. Practically: any `AnchorMailbox` value that doesn't match `AuthenticatedUser`, that references a mailbox with no plausible relationship to the requesting account, or that's malformed/unusually shaped compared to the rest of the log, is one of the highest-value single-field indicators in the entire Exchange log set — treat it as a priority lead, not routine noise.

To parse an HttpProxy CSV log correctly using PowerShell (the file is prefixed with `#Fields:`/`#Software:`/etc. header comment lines before the data rows, so a naive `Import-Csv` without pulling the header first will misalign columns):

```powershell
$log = "$env:ExchangeInstallPath\Logging\HttpProxy\Ecp\<date>.log"
$header = (Select-String -Path $log -Pattern '^#Fields: ' -List).Line -replace '#Fields: ',''
Import-Csv -Path $log -Header ($header -split ',') | Where-Object { $_.DateTime -notmatch '^#' } |
    Select-Object DateTime, AuthenticatedUser, AnchorMailbox, ClientIpAddress, UrlStem, HttpStatus
```

To apply the AnchorMailbox/AuthenticatedUser mismatch logic across every protocol folder at once using PowerShell, not just one:

```powershell
Get-ChildItem "$env:ExchangeInstallPath\Logging\HttpProxy" -Recurse -Filter *.log | ForEach-Object {
    $hdr = (Select-String -Path $_.FullName -Pattern '^#Fields: ' -List).Line -replace '#Fields: ',''
    if ($hdr) {
        Import-Csv -Path $_.FullName -Header ($hdr -split ',') |
            Where-Object { $_.AnchorMailbox -and $_.AuthenticatedUser -and $_.AnchorMailbox -ne $_.AuthenticatedUser }
    }
} | Select-Object DateTime, @{N='Protocol';E={(Split-Path (Split-Path $_.PSPath -Parent) -Leaf)}}, AuthenticatedUser, AnchorMailbox, ClientIpAddress, UrlStem, HttpStatus |
    Sort-Object DateTime
```

### Step 5 — Hunt Commands

**Mass-mail / BEC-pattern hunting via Message Tracking:**

```powershell
# Outbound RECEIVE volume per sender in a short window - a compromised mailbox suddenly blasting mail looks like a volume spike from one sender
Get-MessageTrackingLog -EventId RECEIVE -Start (Get-Date).AddHours(-24) -ResultSize Unlimited |
    Group-Object Sender | Sort-Object Count -Descending | Select-Object Count, Name -First 25

# Single sender, many distinct external recipient domains in a short window - the shape of a compromised-account spam/BEC blast rather than normal business mail
Get-MessageTrackingLog -EventId RECEIVE -Sender 'user@domain.com' -Start (Get-Date).AddHours(-24) -ResultSize Unlimited |
    ForEach-Object { $_.Recipients } | ForEach-Object { ($_ -split '@')[1] } | Group-Object | Sort-Object Count -Descending
```

**HttpProxy log sweep for the CVE-class request pattern.** The well-documented shape of the pre-auth-to-webshell attack chain against Exchange is conceptually consistent across the ProxyLogon/ProxyShell/ProxyNotShell family: an initial request against `/autodiscover/` (or another pre-auth-reachable endpoint) is abused to obtain a routing/authentication primitive, which is then used against `/ecp/` or `/mapi/` to reach a normally-protected back-end function, ultimately leading to a file (frequently an `.aspx` web shell — see Step 6) being written into a web-accessible directory. Hunting for this doesn't require knowing the exact CVE number — it requires spotting the pattern:

```powershell
# Same client IP touching autodiscover, ecp, and mapi endpoints within a short window - the generic pre-auth-to-post-auth chain shape
Get-ChildItem "$env:ExchangeInstallPath\Logging\HttpProxy" -Recurse -Filter *.log | ForEach-Object {
    $hdr = (Select-String -Path $_.FullName -Pattern '^#Fields: ' -List).Line -replace '#Fields: ',''
    if ($hdr) { Import-Csv -Path $_.FullName -Header ($hdr -split ',') | Where-Object { $_.DateTime -notmatch '^#' } }
} | Where-Object { $_.UrlStem -match '/(autodiscover|ecp|mapi)/' } |
    Group-Object ClientIpAddress | Where-Object { ($_.Group.UrlStem | ForEach-Object { ($_ -split '/')[1] } | Sort-Object -Unique).Count -ge 2 } |
    Select-Object Name, Count
```

**Non-owner mailbox access:**

```powershell
Get-Mailbox -ResultSize Unlimited | Where-Object AuditEnabled -eq $true | ForEach-Object {
    Search-MailboxAuditLog -Identity $_.Identity -LogonTypes Delegate,Admin -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) -ShowDetails
} | Select-Object MailboxOwnerUPN, LogonUserDisplayName, LogonType, Operation, LastAccessed
```

🔴 Mailbox audit logging must actually be enabled (`AuditEnabled`) per mailbox for `Search-MailboxAuditLog` to return anything — confirm coverage with `Get-Mailbox -ResultSize Unlimited | Select Name, AuditEnabled` before treating an empty result as "no non-owner access occurred." An absence of audit data is a coverage gap, not a clean bill of health.

**Hidden inbox rules — BEC persistence, in depth.** This is the single most common mechanism for durable, quiet mailbox compromise once an attacker has valid credentials or an active session: create a rule that silently forwards or redirects incoming mail matching some condition (often a broad "match everything" or targeted at subject-line keywords like invoice/payment/wire) to an attacker-controlled address, then **delete the local copy** (or move it into an obscure, rarely-checked folder such as the RSS Feeds folder) so the mailbox owner never sees the forwarded message and has no reason to suspect anything. This survives password resets that don't also revoke the rule, and it's cheap and easy to set up compared to maintaining persistent authenticated access.

```powershell
# Every enabled rule with a forward/redirect action, across every mailbox
Get-Mailbox -ResultSize Unlimited | ForEach-Object {
    Get-InboxRule -Mailbox $_.Identity | Where-Object { $_.Enabled -and ($_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo) } |
        Select-Object @{N='Mailbox';E={$_.MailboxOwnerId}}, Name, ForwardTo, RedirectTo, DeleteMessage, MoveToFolder, StopProcessingRules
}
```

🔴 **`Get-InboxRule` only surfaces rules visible through normal client-facing rule mechanisms.** Attackers have used direct MAPI-level rule creation to plant rules that don't surface through the standard OWA/Outlook rules UI (and, in some cases, not through `Get-InboxRule` either) — if a case has a strong signal of mail leaking with no corresponding rule showing up in the cmdlet output, that mismatch is itself a finding, and escalating to a MAPI-level inspection tool (see Tooling) is warranted rather than concluding no rule exists.

**Transport rule abuse — the org-wide version of the same idea:**

```powershell
Get-TransportRule | Where-Object { $_.RedirectMessageTo -or $_.BlindCopyTo -or $_.CopyTo -or $_.AddToRecipients } |
    Select-Object Name, State, Priority, Description, RedirectMessageTo, BlindCopyTo, CopyTo
```

A malicious transport rule is a strictly bigger problem than a malicious inbox rule — it applies at the organization mail-flow level rather than to one mailbox, so a single planted rule (often disguised with an innocuous name, or set to a very narrow/rarely-triggered condition to stay under the radar) can quietly BCC or redirect a chosen slice of **all** company mail to an external address.

**Mailbox export abuse for exfiltration.** Full mechanics of `New-MailboxExportRequest`/`Get-MailboxExportRequest` belong to [`15 - Email Forensics`](<../15 - Email Forensics.md#mailbox-exportimport-new-mailboxexportrequest-exmerge-compliance-search>) — from the intrusion-hunting angle here, treat any export request not tied to a documented legal-hold, migration, or e-discovery ticket as a candidate mass-exfiltration event, especially a batch of exports across many mailboxes in a short window, or a `FilePath` target that resolves to a network share reachable from outside the organization:

```powershell
Get-MailboxExportRequest | Get-MailboxExportRequestStatistics | Select-Object Name, SourceAlias, FilePath, StatusDetail, OverallDuration
```

### Step 6 — Web Shell and Transport Agent Persistence

**Web shells in OWA/ECP.** Attackers have repeatedly, and across multiple well-documented Exchange-targeting campaigns, dropped ASPX web shells directly into the physical directories that back the `/owa` and `/ecp` virtual directories (`%ExchangeInstallPath%FrontEnd\HttpProxy\owa\` and the `\ecp\` equivalent) once they've achieved enough access to write a file there — these directories are already IIS-served and internet-reachable by design, which is exactly what makes them attractive: no separate listener or firewall rule is needed, the web shell simply becomes another URL on an already-exposed server. **Treat any unexpected `.aspx` (or other server-executable extension) appearing in these directories as a critical finding until proven otherwise** — legitimate Exchange updates to these paths come from Cumulative Update installation, not ad hoc file drops.

```powershell
Get-ChildItem "$env:ExchangeInstallPath\FrontEnd\HttpProxy" -Recurse -Include *.aspx,*.asp,*.ashx |
    Select-Object FullName, CreationTime, LastWriteTime, Length |
    Sort-Object CreationTime -Descending
```

Cross-reference any hit against Prefetch/ShimCache/Amcache (note 06) for execution evidence, and against the HttpProxy/IIS logs (Steps 3–4) for the request that likely wrote the file in the first place — the file-write is frequently the *last* step of the pre-auth chain described in Step 5, so working backward from the file's creation timestamp into the surrounding log window is usually the fastest way to reconstruct how it got there.

**Malicious Transport Agents.** A Transport Agent is a .NET assembly registered into Exchange's own message-processing pipeline (`Get-TransportAgent`, `Install-TransportAgent`, `Enable-TransportAgent`) — legitimate ones do things like anti-spam scoring or disclaimer insertion, running inline on every message that flows through the transport service. That's exactly what makes a malicious one so powerful as a persistence primitive: it's arbitrary attacker code executing inside a trusted, always-running Exchange process (the transport service), with the ability to inspect, modify, or exfiltrate every message that passes through — and, unlike an OWA/ECP web shell, it isn't sitting in a web-reachable directory waiting to be noticed by a file-integrity check of the front-end paths.

```powershell
Get-TransportAgent | Select-Object Name, Enabled, Priority, TransportAgentFactory, AssemblyPath
```

🔴 Compare the returned list against the small set of agents Exchange installs by default (transport rules agent, anti-spam agents if enabled, DLP agent if licensed) — any unfamiliar name, or a familiar-sounding name pointed at an assembly path outside Exchange's own installation directories, warrants immediate follow-up.

### Step 7 — Service Account and AD Permissions Abuse

Exchange's integration with Active Directory has historically granted the Exchange servers' own computer accounts (via groups such as Exchange Windows Permissions / Exchange Trusted Subsystem) unusually broad write permissions on Active Directory objects — in some environments' default configurations, extending to permissions on the domain object itself. This has been a well-documented privilege-escalation vector: an attacker who can coerce or relay an Exchange server's own machine authentication can potentially leverage those AD permissions for domain-level escalation, independent of any Exchange-application-layer vulnerability at all.

**This note does not re-derive AD ACL forensics** — auditing DACL changes, enumerating dangerous permission grants, AdminSDHolder/SDProp mechanics, and the general methodology for finding an abused permission chain all belong to [`05b - Active Directory & Domain Forensic Artifacts`](<../05b - Active Directory & Domain Forensic Artifacts.md>). What matters here is recognizing that **the Exchange server's own computer account and its associated groups are themselves a privilege-escalation surface** worth including whenever 05b's ACL-enumeration techniques are run against a domain that has (or has ever had) Exchange installed — Exchange's AD footprint doesn't necessarily go away cleanly even after decommissioning.

## Investigative Sequence Summary

```
1. Identify topology
   Get-ExchangeServer / Get-DatabaseAvailabilityGroup / Get-MailboxDatabase -Status
   → confirm CU/SU build level, scope log collection to every relevant DAG member
                    │
2. Confirm the IIS layer
   Front-End (Default Web Site) vs. Back-End (Exchange Back End, 81/444)
   → check virtual-directory InternalUrl/ExternalUrl for tampering
                    │
3. Collect Exchange-specific logs before rollover
   HttpProxy · Message Tracking · SMTP Protocol · RPC Client Access · ECP
   · Admin Audit Log · IIS logs (see sibling IIS note)
                    │
4. Read AnchorMailbox vs. AuthenticatedUser in HttpProxy logs
   Mismatch = priority lead for ProxyLogon/ProxyShell/ProxyNotShell-class abuse
                    │
5. Hunt
   Mass-mail pattern (Message Tracking) · pre-auth chain shape (autodiscover→ecp/mapi)
   · non-owner mailbox access (Search-MailboxAuditLog) · hidden inbox rules (BEC)
   · transport rule abuse · mailbox export abuse
                    │
6. Check for web shells and malicious transport agents
   FrontEnd\HttpProxy\owa|ecp for unexpected .aspx · Get-TransportAgent for
   unfamiliar registered agents
                    │
7. Check the AD angle
   Exchange Windows Permissions / Trusted Subsystem AD footprint
   → hand off to 05b for full ACL forensics
                    │
8. Hand off
   Cross-artifact correlation (note 00) · Event Log Analysis (note 11)
   · Active Directory (05b) · Email Forensics format/e-discovery (15)
   · hybrid/Exchange Online continuation (Cloud/Microsoft/)
```

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `AnchorMailbox` in an HttpProxy log entry doesn't match `AuthenticatedUser`, or references an unrelated/administrative mailbox | The direct field-level signature of ProxyLogon/ProxyShell/ProxyNotShell-class pre-auth-to-post-auth proxy abuse |
| Same client IP touching `/autodiscover/`, then `/ecp/` or `/mapi/`, within a short window | The generic pre-auth-to-post-auth request-chain shape documented across this CVE class |
| Unexpected `.aspx`/`.ashx` file under `FrontEnd\HttpProxy\owa\` or `\ecp\` | Web shell drop zone — legitimate changes here come from CU installation, not ad hoc writes |
| Unfamiliar entry in `Get-TransportAgent` output, or a familiar name pointed at an assembly path outside Exchange's own install directories | Code-execution persistence inside the trusted, always-running transport pipeline |
| Enabled inbox rule with a forward/redirect action **and** `DeleteMessage`/an obscure `MoveToFolder` target | Classic BEC persistence — the owner never sees the exfiltrated copy |
| `Get-TransportRule` entry with `RedirectMessageTo`/`BlindCopyTo`/`CopyTo` pointing at an unfamiliar external address | Org-wide mail redirection — far larger blast radius than a single-mailbox inbox rule |
| Strong signal of ongoing mail leakage with no corresponding rule surfaced by `Get-InboxRule` | Possible MAPI-level hidden rule not visible through normal client/cmdlet listings — escalate to MAPI-level inspection |
| `New-MailboxExportRequest`/`Get-MailboxExportRequest` entry with no matching legal-hold/migration ticket, especially a batch across many mailboxes | Mass-exfiltration candidate |
| `Search-MailboxAuditLog` shows Delegate/Admin (non-owner) logons the mailbox owner can't account for | Direct evidence of unauthorized mailbox access |
| Mailbox audit logging (`AuditEnabled`) disabled fleet-wide or on specific high-value mailboxes | Coverage gap, not a clean result — absence of findings doesn't mean absence of access |
| Virtual directory `InternalUrl`/`ExternalUrl` pointed at an unfamiliar host | Redirection/defense-evasion tampering on the client-configuration layer |

## MITRE ATT&CK Techniques Covered

| Technique | ID | Where covered here |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Step 4/5 — ProxyLogon/ProxyShell/ProxyNotShell-class pre-auth exploitation via OWA/ECP/EWS/Autodiscover |
| Server Software Component: Web Shell | T1505.003 | Step 6 — ASPX web shells in the OWA/ECP physical directories |
| Server Software Component (parent — no dedicated sub-technique for mail transport agents) | T1505 | Step 6 — malicious Transport Agent registered into the message pipeline |
| Email Collection: Remote Email Collection | T1114.002 | Step 5 — mailbox export abuse for bulk exfiltration |
| Email Collection: Email Forwarding Rule | T1114.003 | Step 5 — hidden/malicious inbox rules, the BEC persistence mechanism covered in depth |
| Account Manipulation: Additional Email Delegate Permissions | T1098.002 | Step 5 — non-owner mailbox access via delegate/admin permission grants |
| Valid Accounts | T1078 | Throughout — compromised credentials used against OWA/ECP/EWS/ActiveSync |

Verify sub-technique numbering against the current MITRE ATT&CK Enterprise matrix before citing in a report — sub-technique IDs are occasionally reorganized.

## Tooling

| Tool | Use |
|---|---|
| **Exchange Management Shell (EMS)** | The primary interface for nearly every hunt command in this note — not base Windows PowerShell |
| **Log Parser / Log Parser Studio** | SQL-like querying across large volumes of HttpProxy/IIS CSV logs — practical at scale where line-by-line `Import-Csv` parsing becomes slow |
| **CSS-Exchange tooling (Microsoft Exchange product team, GitHub)** | Microsoft's own published incident-response and health-check scripts for Exchange, including bulk log collection (`ExchangeLogCollector`) and server health/configuration checks (`HealthChecker`) — verify current script names/repository location against Microsoft's GitHub before relying on a specific script name in a runbook, this tooling has been reorganized over time |
| **MFCMAPI** | Low-level MAPI browsing tool — the escalation path when `Get-InboxRule` output doesn't account for observed mail leakage and a MAPI-level hidden-rule check is warranted |
| **Sysinternals / note 06 tooling (Prefetch, ShimCache, Amcache)** | Execution evidence for a dropped web shell or any tool run on the Exchange server itself |
| **Eric Zimmerman's tools (EvtxECmd, etc.)** | Offline EVTX parsing for the Application/System log side of an Exchange investigation — see note 11 |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Mailbox format internals (EDB/STM/ESE), `eseutil`, mailbox export/import mechanics, Compliance Search, M365/Google Workspace mailbox layers | [`15 - Email Forensics`](<../15 - Email Forensics.md>) |
| General IIS log mechanics, application pools, web-server compromise investigation underneath Exchange's virtual directories | [`IIS - Web Server Forensics.md`](<IIS - Web Server Forensics.md>) (this folder) |
| AD ACL forensics — dangerous permission enumeration, AdminSDHolder/SDProp, DACL change auditing for the Exchange-AD privilege-escalation angle in Step 7 | [`05b - Active Directory & Domain Forensic Artifacts`](<../05b - Active Directory & Domain Forensic Artifacts.md>) |
| Windows Event Log mechanics (Application/System log, EVTX collection race conditions) underlying the Exchange-sourced Application log events | [`11 - Event Log Analysis`](<../11 - Event Log Analysis.md>) |
| Execution evidence (Prefetch/ShimCache/Amcache) for a dropped web shell or attacker-run tool | [`06 - Evidence of Program Execution`](<../06 - Evidence of Program Execution>) |
| Hybrid or fully cloud Exchange Online / Microsoft 365 mailbox investigation once the environment extends past on-prem | the relevant Microsoft 365/Exchange Online notes under `Cloud/Microsoft/` |
| Cross-artifact correlation methodology tying this note's findings into a broader host/enterprise timeline | [`00 - Cross-Artifact Correlation`](<../00 - Cross-Artifact Correlation.md>) |
| Reverse ATT&CK-technique-to-evidence lookup across the whole Windows module | [`00b - ATT&CK Windows to Evidence Map`](<../00b - ATT&CK Windows to Evidence Map.md>) |

## Resources

- Microsoft Learn — Exchange Server architecture, Database Availability Groups, and virtual directory documentation (consult current Microsoft Learn directly; Exchange documentation has been reorganized across releases)
- Microsoft Learn — `Get-MessageTrackingLog`, `Search-MailboxAuditLog`, `Search-AdminAuditLog`, `Get-TransportAgent`/`Install-TransportAgent` cmdlet reference
- CSS-Exchange (Microsoft Exchange product team's public GitHub tooling repository) — health-check and log-collection tooling; verify current repository location and script names before citing a specific tool name in a report
- MITRE ATT&CK T1190 (Exploit Public-Facing Application) — https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK T1505.003 (Server Software Component: Web Shell) — https://attack.mitre.org/techniques/T1505/003/
- MITRE ATT&CK T1114.002 (Email Collection: Remote Email Collection) — https://attack.mitre.org/techniques/T1114/002/
- MITRE ATT&CK T1114.003 (Email Collection: Email Forwarding Rule) — https://attack.mitre.org/techniques/T1114/003/
- MITRE ATT&CK T1098.002 (Account Manipulation: Additional Email Delegate Permissions) — https://attack.mitre.org/techniques/T1098/002/
- MITRE ATT&CK T1078 (Valid Accounts) — https://attack.mitre.org/techniques/T1078/
