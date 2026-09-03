# Potato Family — Overview

> 🔴 **Red Flag Principle:** The **Potato Family** is a lineage of local privilege escalation exploits (PrintSpoofer, JuicyPotato, RoguePotato) that all abuse the **`SeImpersonate` privilege** — a Windows capability granted to many service accounts (IIS, MSSQL, WinRM) — to escalate from a low-privilege process context to `NT AUTHORITY\SYSTEM`. The shared mechanism: coerce or trick a SYSTEM-context service into exposing its authentication token, capture it, then spawn a SYSTEM-privileged child process. **The key distinction between the three tools is how they trick that SYSTEM service.** PrintSpoofer coerces the Print Spooler's RPC endpoint (simplest, reliable on unpatched systems); JuicyPotato abuses COM object instantiation (complex, legacy, unreliable on modern systems); RoguePotato relays RPC traffic through an external redirector (most complex, requires additional infrastructure but reliable on patched systems). All three leave a **characteristic process tree: service-account parent → SYSTEM-context child** — the smoking gun on the target, but three different attack sources to hunt on the attacker's machine.

## About the Potato Family

The **Potato Family** is a lineage of Windows local privilege escalation exploits that abuse token-impersonation privileges (`SeImpersonate`, `SeAssignPrimaryToken`) to escalate from a low-privilege service account context to `NT AUTHORITY\SYSTEM`. All three tools in this family share a common theme: **they exploit the Windows privilege impersonation model**, where a process holding the `SeImpersonate` privilege can capture and impersonate SYSTEM-context tokens, then spawn a SYSTEM-privileged child process.

## Contents

- [About the Potato Family](#about-the-potato-family)
- [Comparison table: Which tool when?](#comparison-table-which-tool-when)
- [Shared mechanics: SeImpersonate privilege exploitation](#shared-mechanics-seimpersonate-privilege-exploitation)
- [Shared remediation & mitigation](#shared-remediation--mitigation)
- [Evidence synthesis: Post-compromise investigation](#evidence-synthesis-post-compromise-investigation)
- [Cross-links to related content](#cross-links-to-related-content)
- [Sub-Tool Table of Contents](#sub-tool-table-of-contents)
- [Summary](#summary)

**Historical lineage:**
- **RottenPotato (2016)** — Original COM-based token impersonation exploit by Stephen Breen.
- **JuicyPotato (2018)** — Enhanced RottenPotato with per-OS CLSID enumeration and multi-method token support.
- **PrintSpoofer (2021)** — RPC coercion via Print Spooler, simpler and more reliable on modern systems.
- **RoguePotato (2019, concurrent with PrintSpoofer)** — RPC relay approach, targets multiple RPC services, requires external redirector.

This folder groups these three tools (PrintSpoofer, JuicyPotato, RoguePotato) as a unified family because:
1. They all exploit the same privilege escalation mechanism (SeImpersonate token impersonation).
2. They share similar evidence signatures (SYSTEM-context child process spawns).
3. They address the same operational need (service account → SYSTEM escalation).
4. Understanding the technical differences is crucial for both offensive and defensive practitioners.

**Scope of this folder:**
- **PrintSpoofer/** — Print Spooler RPC coercion; simple, reliable on unpatched Print Spooler.
- **JuicyPotato/** — COM object CLSID enumeration; complex, legacy (2018), unreliable on patched systems.
- **RoguePotato/** — RPC relay via external redirector; reliable on patched systems, requires additional infrastructure.

## Install & Setup: Quick reference per tool

Each tool is deployed differently due to its exploit mechanism and infrastructure requirements.

| Tool | Binary/Source | Setup | Notes |
|---|---|---|---|
| **PrintSpoofer** | Standalone `.exe` compiled binary | Drop binary on target, run directly (no setup required) | Easiest deployment. Relies on Print Spooler being running. No redirector or external infrastructure. |
| **JuicyPotato** | Standalone `.exe` compiled binary | Drop binary on target, enumerate CLSIDs, trial-and-error execution | Requires knowledge of target OS version to select working CLSIDs. Per-OS tuning necessary. |
| **RoguePotato** | Standalone `.exe` compiled binary on target + Chisel/relay on attacker machine | 1. Deploy Chisel server on attacker (e.g., `chisel server -p 9999`). 2. On target, run with `-r <attacker-ip>:9999` | Requires bidirectional network connectivity (target to attacker). Higher infrastructure complexity. |

**Deployment scenarios:**

- **Offline engagement (no internet from target):** PrintSpoofer only (local-only). JuicyPotato works but requires manual CLSID research. RoguePotato won't work without a redirector on the internal network.
- **Network-isolated lab:** All three work if a redirector is set up inside the isolated network for RoguePotato.
- **Live network (full internet):** RoguePotato preferred if PrintSpooler/COM are patched, assuming external redirector is available.

---

## Comparison table: Which tool when?

| Aspect | PrintSpoofer | JuicyPotato | RoguePotato |
|---|---|---|---|
| **Release year** | 2021 | 2018 | 2019 |
| **Status** | Archived (2024), read-only | Inactive (2020) | Low maintenance (active repo) |
| **Exploit mechanism** | RPC coercion (Print Spooler) | COM object instantiation (CLSID-dependent) | RPC relay via external redirector |
| **Token capture method** | Direct RPC interception | COM marshalling | RPC relay interception |
| **Requirements** | SeImpersonate, Print Spooler running | SeImpersonate/SeAssignPrimaryToken, usable CLSID | SeImpersonate, external redirector reachable |
| **Complexity** | Simplest (1-liner) | Medium (CLSID trial-and-error) | Most complex (requires Chisel setup) |
| **Reliability on Windows 10 (2019H1+)** | High | Low (CLSIDs removed/patched) | High (WER services still vulnerable) |
| **Reliability on Windows 7 / Server 2008 R2** | Medium | High | Medium |
| **Network traffic required** | No (local-only) | No (local-only) | **Yes (target → redirector)** |
| **Detectability** | High (spoolsv.exe parent distinctive) | Medium (variable COM parent) | **Very High (network traffic visible)** |
| **Command-line exposure** | Minimal | CLSID in command line | Redirector IP in command line |
| **Best-use scenario** | Modern Windows (10/2019+) without Print Spooler patch | Legacy Windows (7/2008 R2) where CLSIDs still work | Patched modern systems where PrintSpooler/COM are hardened |

---

## Shared mechanics: SeImpersonate privilege exploitation

All three tools exploit **the same underlying Windows capability: token impersonation**. Here's the shared workflow:

```
1. Attacker gains code execution as a service account (IIS, MSSQL, WinRM, etc.)
2. Service account holds SeImpersonate privilege
3. Tool (PrintSpoofer/JuicyPotato/RoguePotato) coerces/tricks SYSTEM service into exposing its token
4. Tool captures the SYSTEM-context token
5. Tool calls CreateProcessAsUser() or CreateProcessWithTokenW() with the SYSTEM token
6. Spawned process runs as SYSTEM
7. Attacker has SYSTEM-context code execution
```

**The divergence is in step 3** — how each tool tricks a SYSTEM service into exposing its token:
- **PrintSpoofer:** Coerces Print Spooler RPC endpoint.
- **JuicyPotato:** Tricks COM object instantiation.
- **RoguePotato:** Relays RPC traffic through an external redirector.

### Token impersonation via COM+ and DCOM

**COM+ (Component Object Model Plus)** is Windows' distributed object framework, built atop DCOM (Distributed COM). Both PrintSpoofer and JuicyPotato leverage COM+ in different ways:

**JuicyPotato's COM+ approach:**
- Instantiates a COM object by its CLSID (Class ID).
- The CLSID belongs to a Windows system service (e.g., `{6B3B8D23-FA8D-40B9-8DBD-B950333E2C52}` for Windows Error Reporting).
- The COM service is created/runs as SYSTEM.
- JuicyPotato hooks/proxies the COM object creation and intercepts the authentication handshake.
- The SYSTEM-context service exposes its token during object instantiation.
- JuicyPotato captures and impersonates that token.
- **Reliability:** Depends on the CLSID being available and not patched. Many CLSIDs have been removed in newer Windows versions, making this approach less reliable over time.

**PrintSpoofer's RPC coercion approach:**
- Targets the Print Spooler service (spoolsv.exe), which is a well-known system service.
- Uses RPC calls (not COM+, but similar auth handshake) to force the Print Spooler to authenticate back to the attacker's RPC server.
- The Print Spooler service runs as SYSTEM.
- During the authentication callback, PrintSpoofer captures the SYSTEM-context token.
- **Reliability:** Depends on Print Spooler being enabled and not patched. CVE-2021-1732 patched this on newer systems.

**RoguePotato's RPC relay approach:**
- Similar to PrintSpoofer but uses an external redirector.
- Targets any RPC service (default: WER) via a local RPC endpoint.
- Relays the RPC traffic through an external machine (Chisel, custom relay).
- The external redirector captures the SYSTEM-context NTLM authentication from the RPC handshake.
- Relays it back to a second RPC endpoint on the target.
- RoguePotato impersonates the relayed SYSTEM token.
- **Reliability:** Highest on patched systems because it's not service-specific; any RPC service can be exploited.

### SeImpersonate privilege: The prerequisite

The `SeImpersonate` privilege is the key that unlocks token impersonation at the OS level. Here's what it means:

- **Granted to:** Service accounts (IIS app pools, MSSQL service account, WinRM service, etc.).
- **What it does:** Allows a process to create a child process with an impersonated (different) security context.
- **API calls it enables:** `ImpersonateLoggedOnUser()`, `ImpersonateNamedPipeClient()`, `CreateProcessAsUser()`, `CreateProcessWithTokenW()`.
- **Can't do without it:** A process without `SeImpersonate` cannot assume a different security token; it's stuck in its own context.

**Why service accounts get it:** Many Windows services need to interact with network clients or subsystems as if they were different users (e.g., IIS running a website that connects to SQL Server as a different account). The `SeImpersonate` privilege enables this impersonation workflow. However, **this same privilege is what Potato-family exploits abuse** — a process with `SeImpersonate` can impersonate ANY token it can capture, including SYSTEM.

### The token capture and escalation chain

1. **Token exposure:** PrintSpoofer/JuicyPotato/RoguePotato trick a SYSTEM service into exposing its authentication token (via RPC/COM handshake).
2. **Token capture:** The tool intercepts the token (via RPC relay, COM proxy, or authentication callback).
3. **Token impersonation:** The attacker's process (running as service account, with `SeImpersonate`) calls `ImpersonateLoggedOnUser()` or equivalent to assume the SYSTEM token.
4. **Privileged child spawn:** While impersonating SYSTEM, the tool calls `CreateProcessAsUser()` or `CreateProcessWithTokenW()` to spawn a new process (cmd.exe, PowerShell, etc.).
5. **Execution:** The new child process inherits the impersonated SYSTEM token and runs with full system privileges.
6. **Evidence:** Windows logs the child process creation (Event 4688, Sysmon Event 1) as SYSTEM-context, with the service account as the parent.

---

## Shared remediation & mitigation

### 1. Disable SeImpersonate privilege (application hardening)

**Most effective but often impractical.** Many Windows applications (IIS, MSSQL) require SeImpersonate to function.

```powershell
# Remove SeImpersonate from an application's service account
# (Not recommended for IIS/MSSQL; will break functionality)
Set-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC" -AclObject $acl
```

**Practical alternative:** Run applications in **AppContainer** or **Virtual User Accounts** (if supported), which forbid token impersonation entirely. However, most applications don't support AppContainer.

### 2. Patching & hardening (OS level)

**Windows 10 2019H1+ and Server 2019+:**
- Print Spooler RPC has been hardened; PrintSpoofer reliability decreases.
- Many COM CLSIDs used by JuicyPotato have been removed or patched; JuicyPotato reliability decreases further.
- Ensure all updates are installed.

**Specific patches:**
- **CVE-2021-1732** (Print Spooler RPC vulnerability underlying PrintSpoofer) — patched in Windows 10 updates.
- **COM object removals** — Various CLSIDs removed in Windows 10 1909+.

### 3. Disable Print Spooler (if not needed)

```powershell
Set-Service -Name spooler -StartupType Disabled
Stop-Service -Name spooler -Force
```

**Caveat:** Some Windows 10 features (cloud printing, enterprise printing scenarios) may depend on Print Spooler being available. Test before deploying.

### 4. Process Privilege Level (PPL) & Protected Process Light

**For high-value services (LSASS, CSRSS):** Enable RunAsPPL to prevent token theft by non-privileged code.

```powershell
# Enable RunAsPPL for LSASS
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1
```

**Scope:** LSASS (credential storage) is often the target after SYSTEM escalation. PPL prevents even SYSTEM-context code from dumping LSASS without a second vulnerability.

### 5. Network-based detection (for RoguePotato)

**Monitor outbound RPC from service accounts to external IPs** — RoguePotato's Achilles' heel is its network visibility.

```
Firewall Rule: Block outbound RPC from MSSQL/IIS service accounts to Internet
Port Range: >1024 (ephemeral)
```

### 6. Centralized logging & EDR

**Deploy Sysmon + centralized SIEM** to detect the characteristic process tree (service account → SYSTEM child) and command-line indicators.

```xml
<!-- Sysmon config: Alert on unexpected SYSTEM process spawn -->
<RuleGroup name="Token Impersonation" groupRelation="or">
  <ProcessCreate onmatch="include">
    <User condition="contains">NT AUTHORITY\SYSTEM</User>
    <ParentImage condition="image">JuicyPotato.exe|PrintSpoofer.exe|RoguePotato.exe|potato|jp|ps</ParentImage>
  </ProcessCreate>
</RuleGroup>
```

### 7. Application containment strategies

**For web applications (IIS):**
- Run app pools as **custom low-privilege accounts** without SeImpersonate (if application supports it).
- Use **Application Request Routing (ARR)** to route requests through a proxy, isolating the app pool from network access.

**For databases (MSSQL):**
- Restrict **xp_cmdshell** usage (stored procedure that executes OS commands).
- Use **SQL Server-managed accounts** with minimal OS-level privileges.

### 8. Monitoring and hunting

**See individual tool folders for detailed hunting strategies:**
- **PrintSpoofer:** Hunt for spoolsv.exe spawning interactive shells.
- **JuicyPotato:** Hunt for COM object instantiation + CLSID in command lines.
- **RoguePotato:** Hunt for outbound RPC to external redirector IPs.

---

## Evidence synthesis: Post-compromise investigation

If you suspect Potato-family exploitation:

1. **Check Sysmon Event 1 / Windows Event 4688** for unexpected SYSTEM process spawns.
2. **Check network logs (Zeek, NetFlow, firewall)** for outbound RPC connections (RoguePotato indicator).
3. **Check process command lines** for Potato binary names or suspicious flags (`-r`, `-c`, `-l`, `-p`).
4. **Check event logs** for Event 4672 (token privilege escalation) coinciding with process creation.
5. **Correlate source → target timeline** to identify the service account compromised and the SYSTEM-context actions performed.

**Key forensic principle:** The three tools leave **very similar target-side evidence** (a SYSTEM-context child process), but **different source-side and network-side evidence**:
- PrintSpoofer: Local-only, Print Spooler parent.
- JuicyPotato: Local-only, variable COM parent, CLSID in command line.
- RoguePotato: Network-visible RPC to redirector, Service account parent.

## Forensic analysis and timeline correlation

**Typical Potato-family attack timeline:**

1. **T-N (days/weeks before):** Initial access (web app compromise, RDP brute-force, etc.). Attacker gains code execution as IIS/MSSQL/WinRM service account.
2. **T-0: Potato execution:** RoguePotato binary is dropped/staged, or PrintSpoofer/JuicyPotato command is executed inline.
   - Event 4688/Sysmon 1: Potato binary process created (as service account).
   - Registry 13 (Sysmon): Command line may appear in process execution logs.
3. **T+0.1-2 seconds:** Token impersonation and escalation.
   - PrintSpoofer: Coerces spoolsv.exe; WER service or other RPC target initiates outbound RPC.
   - JuicyPotato: COM object instantiation by the Potato binary (appears as the binary spawning a COM service).
   - RoguePotato: Creates named pipe, initiates connection to external redirector IP.
   - **Critical event: Child process spawned as SYSTEM.** Event 4688/Sysmon 1 with SYSTEM context, parent = service account or system process.
4. **T+2-30 seconds:** Operator issues commands in the SYSTEM-context shell.
   - Credential dumping (Mimikatz, secretsdump).
   - Lateral movement (PsExec to other hosts, Kerberos ticket creation).
   - Persistence (scheduled tasks, services, registry modifications).
5. **T+30+ seconds to hours:** Post-escalation activity as SYSTEM.
   - Any SYSTEM-context process spawned AFTER T+2 seconds is post-escalation activity.
   - Timeline correlation: Anything happening at the same time as the Potato SYSTEM process is suspicious.

**Evidence differentiation by tool:**

| Tool | Observable on Source | Observable on Target | Network Observable | Blind Spot |
|---|---|---|---|---|
| PrintSpoofer | Potato binary execution (Event 4688) | spoolsv.exe spawning child (distinctive parent) | None | `-file` flag hides binary, making command-line matching weaker |
| JuicyPotato | Potato binary + CLSID in command line | COM service (variable) spawning child | None | CLSID enumeration requires per-target research; common to defenders |
| RoguePotato | Potato binary, redirector IP in command line (if `-r` exposed) | Service account → SYSTEM child + WER service initiation | **Outbound RPC to external IP (firewall 5156, Sysmon 3)** | Randomized/hidden redirector IP obscures the attack source |

## Operational context: Why operators choose Potato-family tools

**Operators pick a tool based on this decision tree:**

```
Scenario 1: Modern Windows (10/2019+), not patched?
└─ PrintSpoofer → simplest, one-liner, local-only, high reliability.

Scenario 2: Legacy Windows (7/2008 R2) or known CLSID available?
└─ JuicyPotato → higher complexity, but often works on older systems.

Scenario 3: Modern Windows, Print Spooler is patched/disabled, no known CLSIDs?
└─ RoguePotato → highest complexity, but most reliable on hardened systems.

Scenario 4: Offline/air-gapped target (no internet, no redirector available)?
└─ PrintSpooler or JuicyPotato only (RoguePotato won't work without redirector).

Scenario 5: Attacker has internal redirector (compromised DMZ, proxy)?
└─ RoguePotato via internal IP (still network-observable, but less externally visible).
```

**Defenders should recognize** that operators treat these tools as **fallback chain**: start with PrintSpoofer, move to JuicyPotato if patched, use RoguePotato as a last resort if both are unavailable. A network with robust monitoring of outbound RPC, file-based integrity checks on system binaries, and active patching of Print Spooler and COM vulnerabilities **effectively forces attackers up this complexity chain.**

## Detection strategy by deployment model

**Defenders should tier their detection strategy based on their visibility into each tool's attack surface:**

### Detection tier 1: Network monitoring (highest confidence for RoguePotato)

**What to hunt:** Outbound RPC connections from service accounts to external/redirector IPs.

- **Tool most vulnerable:** RoguePotato (network-observable relay).
- **Tools least vulnerable:** PrintSpoofer, JuicyPotato (local-only, no network traffic).
- **Deployment requirement:** Network monitoring (Zeek, NetFlow, firewall logs with event logging enabled).
- **Configuration:** Firewall rule to block outbound RPC from service accounts; SIEM alert on breaches.

**Command to validate:** On your firewall/SIEM, query for Event 5156 (Windows Security) or Zeek flow logs with source = service account process and destination = external IP, port > 1024.

### Detection tier 2: Endpoint process monitoring (all three tools)

**What to hunt:** Unexpected SYSTEM-context process spawned by service account.

- **Tool coverage:** All three (PrintSpoofer, JuicyPotato, RoguePotato).
- **Deployment requirement:** Sysmon (Event 1) or EDR agent, with **centralized logging enabled.**
- **Configuration:** Alert rule on SYSTEM-context process creation where parent = service-account process.
- **Caveat:** Requires Sysmon/EDR; vanilla Windows Event 4688 may not have detailed command-line logging.

**Command to validate:** On target, `Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -FilterXPath "*[System[EventID=1] and EventData[Data[@Name='User']='NT AUTHORITY\\SYSTEM']]"` should show recent SYSTEM processes with service-account parents during investigation window.

### Detection tier 3: RPC service monitoring (medium confidence)

**What to hunt:** RPC service (WER, Print Spooler, or custom) making unexpected outbound calls or spawning children.

- **Tool coverage:** All three trigger some RPC service.
- **Deployment requirement:** Sysmon Event 1 (process tree) + network monitoring.
- **Configuration:** Alert on WER.exe or spoolsv.exe (or other RPC service) spawning child processes during unusual hours.
- **Caveat:** Requires understanding your environment's baseline RPC behavior.

### Detection tier 4: Application-level monitoring (tool-specific)

**PrintSpoofer:**
- Hunt for Print Spooler service (spoolsv.exe) spawning unusual children (cmd.exe, PowerShell).
- Monitor Print Spooler's configuration changes (registry).

**JuicyPotato:**
- Hunt for the tool binary's process creation (look for known names: juicypotato.exe, jp.exe, or renamed variants).
- Monitor COM object registration/access.
- Check command-line arguments for CLSID patterns.

**RoguePotato:**
- Hunt for the tool binary's process creation (look for known names: roguepotato.exe, rp.exe, or renamed variants).
- Monitor for Chisel or relay infrastructure on attacker's side.
- Check command-line arguments for `-r` flag (redirector IP).

---

## Cross-links to related content

- **SeImpersonate privilege mechanics:** See `Windows/05 - Users, Groups & Authentication.md` for token-impersonation fundamentals, including the `SeImpersonate` privilege grant, `ImpersonateLoggedOnUser()` API, and why service accounts need this privilege. Also see `Windows/10 - Persistence Mechanisms.md` for AppContainer/PPL caveats and privilege boundary enforcement.
- **WinPEAS integration:** See `Purple Teaming/WinPEAS-LinPEAS/` for privilege enumeration that identifies SeImpersonate-holding accounts and validates whether a compromised service account can escalate.
- **Post-escalation credential dumping:** See `Purple Teaming/Impacket/secretsdump/`, `Purple Teaming/Mimikatz/sekurlsa/`, and `Purple Teaming/LaZagne/` for SYSTEM-context credential access patterns following Potato-family escalation.
- **Remediation and hardening:** See `Windows/10 - Persistence Mechanisms.md` for RunAsPPL, AppContainer, and privilege-isolation strategies. Also see `Windows/12 - Lateral Movement.md` for defenses against the lateral movement that typically follows SYSTEM escalation.
- **RPC and NTLM relay:** See `Purple Teaming/Impacket/ntlmrelayx/` for broader RPC-relay detection context, which overlaps with RoguePotato's relay mechanism.
- **Lateral movement via compromised SYSTEM:** See `Windows/12 - Lateral Movement.md` for PsExec, WMI remote execution, and lateral movement techniques that attackers deploy after Potato-family escalation.

---

## Incident Response Workflow

**If you suspect Potato-family exploitation on your network, follow this IR workflow:**

### Phase 1: Detection & Triage (first 10-15 minutes)

1. **Identify the suspicious event:**
   - Firewall alert: outbound RPC from service account to external IP? (→ RoguePotato likely)
   - EDR alert: SYSTEM-context process spawned by service account? (→ Any Potato tool)
   - Event 7045 on target: unexpected service creation? (→ PrintSpoofer or JuicyPotato)

2. **Correlate to process tree:**
   - Confirm the SYSTEM child process and its parent.
   - Check timing: how close is the Potato binary execution to the SYSTEM-context child?

3. **Contain immediately:**
   - Isolate the compromised host from the network (if SYSTEM escalation is confirmed).
   - Disable the compromised service account (may break services; have rollback plan).
   - Block the external redirector IP at the firewall (if RoguePotato).

### Phase 2: Investigation (next 30-60 minutes)

1. **Determine which Potato tool:**
   - Check for network traffic to external IP → RoguePotato.
   - Check for Print Spooler involvement (spoolsv.exe parent) → PrintSpoofer.
   - Check command-line for CLSID patterns → JuicyPotato.

2. **Establish timeline:**
   - When did the compromised service account first execute the Potato binary?
   - When did the SYSTEM-context child process spawn?
   - When did post-escalation activity begin (credential dumps, lateral movement)?

3. **Hunt for post-escalation activity:**
   - Mimikatz execution (SYSTEM-context process dump)?
   - Lateral movement to other hosts (PsExec, WMI)?
   - Persistence creation (scheduled tasks, services, registry run keys)?

4. **Cross-check related forensic artifacts:**
   - Prefetch files (C:\Windows\Prefetch) for binary and tool names.
   - MFT (Master File Table) for file creation/modification times.
   - Registry keys for service/task persistence.

### Phase 3: Remediation & Recovery (ongoing)

1. **Kill the active session:**
   - Terminate the SYSTEM-context shell/agent.
   - Kill any Mimikatz or credential-dumping processes.

2. **Investigate initial access:**
   - How did the attacker first compromise the service account?
   - Web app exploit? RDP brute-force? Stolen credentials?
   - (Requires pivoting to separate analysis, see `Windows/Threat Landscape and Playbooks/`.)

3. **Patch and rebuild:**
   - Patch Print Spooler (if using PrintSpoofer).
   - Patch COM vulnerabilities (if using JuicyPotato).
   - Hardening: enable AppContainer, RunAsPPL, network monitoring (if using RoguePotato).

4. **Validate recovery:**
   - Confirm the service account's `SeImpersonate` privilege remains or is restored if intentionally removed.
   - Restart the service.
   - Monitor for re-exploitation.

---

## Sub-Tool Table of Contents

| Sub-Tool | Exploit Mechanism | Use Case | Best On |
|---|---|---|---|
| **[`PrintSpoofer/`](PrintSpoofer/01%20-%20Overview.md)** | RPC coercion to Print Spooler (CVE-2021-1732 adjacent) — simple, direct, local-only | Modern Windows (10/Server 2019+) without Print Spooler patch. Simplest to execute; one-liner feasible. | Unpatched Print Spooler, high reliability, minimal external infrastructure. |
| **[`JuicyPotato/`](JuicyPotato/01%20-%20Overview.md)** | COM object instantiation via CLSID enumeration — complex, per-OS CLSID trial-and-error | Legacy Windows (7/Server 2008 R2) where CLSIDs are still available. High complexity; requires per-target CLSID research. | Legacy systems where COM CLSIDs haven't been removed, moderate-to-high infrastructure investment. |
| **[`RoguePotato/`](RoguePotato/01%20-%20Overview.md)** | RPC relay through external redirector (Chisel, custom relay) — most complex, requires attacker infrastructure | Patched modern systems where PrintSpooler/COM are hardened. Highest complexity; requires external redirector setup. Highest reliability on patched systems. | Patched modern systems, but requires external network redirector (highest infrastructure complexity). **Most network-visible.** |

All three share:
- **Target requirement:** `SeImpersonate` privilege on the service account.
- **Target evidence:** Single Event 7045 (service creation) or Sysmon 1 (SYSTEM-context child process).
- **Source evidence:** Binary execution, command-line flags, staging artifacts (distinct per tool).
- **Mitigation:** SeImpersonate removal (impractical), Print Spooler disable (if applicable), AppContainer/PPL for sensitive services.

---

## Summary

The **Potato Family** represents a stable, well-understood privilege-escalation attack surface:

- **PrintSpoofer (2021):** Preferred on modern, unpatched systems; simplest to execute.
- **JuicyPotato (2018):** Fallback on legacy systems; requires per-OS CLSID enumeration.
- **RoguePotato (2019):** Preferred on patched modern systems; requires external redirector infrastructure.

**Operators choose based on:**
- Target OS version.
- Patch level (Print Spooler status, COM availability).
- Network access (redirector reachability, for RoguePotato).

**Defenders should:**
- Monitor for characteristic process trees (service account → SYSTEM child).
- Hunt for network-visible RPC relay (RoguePotato).
- Enforce AppContainer/PPL on high-value services.
- Maintain centralized logging and EDR to detect exploitation post-fact.

All three tools remain operationally relevant as of 2026, even on fully patched Windows systems, because the underlying **SeImpersonate privilege is difficult to remove without breaking application functionality**.
