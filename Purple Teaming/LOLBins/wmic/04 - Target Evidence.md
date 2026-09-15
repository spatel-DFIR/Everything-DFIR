# LOLBins — wmic.exe — Target Evidence

Evidence left on whichever host actually services the WMI call. For local-only use, that's the same host `wmic.exe` ran on; for `/node:` remote use, it's the separate machine named. Per `01 - Overview.md`'s red-flag callout, `wmic.exe`'s abuse splits into **two structurally distinct evidence families that this file keeps separate throughout**:

- **The `Win32_Process.Create()` execution family** (local execution, ADS execution, `/node:` remote execution) — leaves a `WmiPrvSE.exe`-unexpected-child process-tree signature.
- **The XSL-transform ("SquiblyTwo") family** — never calls `Win32_Process.Create()` at all, so it **never produces a `WmiPrvSE.exe` child process**. Its execution happens inside `wmic.exe`'s own process space via a CLR-hosted script engine, and its signature artifact is a `.NET CLR usage-log entry instead.

Conflating these two families is the single easiest mistake to make when reading this file — a host showing WMI-Activity 5857 with no `WmiPrvSE.exe` child process is not "wmic that failed to execute," it may be the XSL family working exactly as designed.

## Contents
- [Filesystem](#filesystem)
- [Registry](#registry)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon (if deployed)](#sysmon-if-deployed)
- [DCOM / RPC Detail](#dcom--rpc-detail)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Signatures](#endpoint-security-product-signatures)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)
- [Contrast Across wmic.exe's Three Execution Paths](#contrast-across-wmicexes-three-execution-paths)

---

## Filesystem

| Artifact | Detail |
|---|---|
| Output-relay file | **None.** Unlike `wmiexec.py`'s transient `__<timestamp>` loopback-SMB file, `wmic.exe` has no built-in output-relay mechanism at all — per `01 - Overview.md`, `process call create` returns only `ReturnValue`/`ProcessId` to the console. If an operator redirected a remote command's output to a file (`cmd.exe /c whoami > C:\Windows\Temp\out.txt`, per `02`'s remote-execution example), that's an ordinary file-create at whatever path was chosen, with no `wmic`-specific naming convention to hunt for |
| **`wmic.exe.log` CLR usage log** | `%LOCALAPPDATA%\Microsoft\CLR_v4.0[_32]\UsageLogs\wmic.exe.log` — **the single strongest artifact for the XSL family specifically.** Per `01 - Overview.md`'s red-flag callout, `wmic.exe` has no legitimate reason to ever load the .NET CLR outside the XSL-transform technique. The log records only that the CLR was loaded by this process (with a timestamp and CLR version), **not** the script content itself |
| ADS-execution payload | Invisible to a default directory listing — the technique *executes* a payload already stored as an NTFS Alternate Data Stream, it doesn't create a new visible file. `Get-Item -Stream *` (PowerShell) or `dir /r` is required to enumerate. See `Windows/08 - Deleted Items and File Existence.md` for the general ADS-enumeration technique this note doesn't re-derive |
| `datafile ... call Copy` output | An ordinary new file at whatever destination path the operator gave — no special naming convention, just a `CIM_DataFile.Copy()` method call producing a normal file-create event |
| Prefetch | `WMIC.EXE-<HASH>.pf`, updated on every run — low-uniqueness on its own (see `Windows/06 - Evidence of Program Execution/Prefetch.md`), but corroborates that `wmic.exe` actually executed on this host, which matters for the local-use case where no network evidence exists at all |
| Amcache / ShimCache | Record `wmic.exe` executions. See `Windows/06 - Evidence of Program Execution/Amcache.md` and `.../ShimCache (AppCompatCache).md` |
| Zone.Identifier / MOTW on the fetched `.xsl` | **Not verified either way** across the sources reviewed for this note — no source consulted confirms whether the XSL stylesheet is ever persisted to disk as a standalone file (as opposed to being processed in-memory as part of formatting the query output) or, if it is, whether it carries a Mark-of-the-Web stream. Treat as unconfirmed rather than assuming either outcome |

## Registry

**No new service key, no WBEM/repository touch, for any `Win32_Process.Create()`-based technique in this file** — identical to `wmiexec.py`'s finding in [`Impacket/wmiexec/04 - Target Evidence.md`](<../../Impacket/wmiexec/04 - Target Evidence.md>): a one-shot method call doesn't register anything under `CurrentControlSet\Services` or touch `HKLM\SOFTWARE\Microsoft\WBEM`. The XSL family touches the registry even less — it's a pure query-and-format operation with no `CREATE`/`SET` verb involved. **Don't confuse either of these with WMI permanent-event-subscription persistence** (`__EventFilter`/`__EventConsumer`/`__FilterToConsumerBinding` via `/namespace:\\root\subscription`) — a genuinely different `wmic.exe` use case, covered by `01 - Overview.md`'s How It Works §6 and `02`'s dedicated use case, with its full registry/repository footprint already covered in depth in `Windows/10 - Persistence Mechanisms/WMI Event Consumers.md`, which this note cross-links to rather than re-deriving.

## Windows Event Logs

| Log | Event ID | Signal |
|---|---|---|
| **Microsoft-Windows-WMI-Activity/Operational** | **5857** | `Operation_Started` — fires for **every** WMI provider operation, which means it fires for **all three** execution paths in this note: local `Create()`, remote `Create()` via `/node:`, and the XSL family's underlying `process get brief` query (a query is still a WMI operation against the CIMWin32 provider, even though it never calls `Create()`). `HostProcess` is set to `wmiprvse.exe` in every case. High-recall, low-precision on its own — correlate against source IP/account before treating it as a finding |
| Microsoft-Windows-WMI-Activity/Operational | 5858 | `Operation_ClientFailure` — only on error (access denied, malformed query, blocked by EDR). Won't appear on a clean run; useful for catching *attempted but blocked* execution |
| Security | 4624 (Logon Type 3 — Network) | **Only for `/node:` remote use** — absent entirely for local-only execution, since local COM activation requires no network logon at all. Check `AuthenticationPackageName` for `NTLM` vs `Kerberos` |
| Security | 4672 | Special privileges assigned to the new logon — confirms an admin-equivalent token, required for `Win32_Process.Create()` to succeed against the target. `/node:` remote use only |
| Security | 4688 | Process creation, execution family only — with command-line auditing enabled, shows `WmiPrvSE.exe` launching `cmd.exe` (or the payload directly, for ADS execution) as a child. **Does not fire for the XSL family**, since no child process is ever created |
| Security | 4689 | Process termination — end of the spawned command, execution family only |
| System | 10016 (Microsoft-Windows-DistributedCOM) | Fires when an account lacks the DCOM launch/activation permissions WMI needs — a common, frequently-noisy System-log event, but worth checking as a *failed-attempt* indicator alongside WMI-Activity 5858 for `/node:` remote use. Not exclusive to this tool |

**Accuracy note, matching the precedent already set in this repo:** [`Impacket/wmiexec/04 - Target Evidence.md`](<../../Impacket/wmiexec/04 - Target Evidence.md>) flags that WMI-Activity **5860** (`Operation_TemporaryEssStarted`) and **5861** (`Operation_ESStoConsumerBinding`) belong to permanent WMI event-subscription registration, not transient `Win32_Process.Create()` execution. The same holds here for every technique in this file: local execution, ADS execution, `/node:` remote execution, and the XSL family all leave **5857/5858 only** — never 5859/5860/5861. Those three IDs belong exclusively to the separate persistence use case in `02 - Hands-On Use Cases.md`'s "WMI Permanent-Event-Subscription Persistence" section, covered in `Windows/10 - Persistence Mechanisms/WMI Event Consumers.md`. Including 5859-5861 in a hunt scoped to this file's execution techniques would be a false-confidence signal.

## Sysmon (if deployed)

| Event ID | Signal |
|---|---|
| 1 (Process Create) | **Execution family:** `WmiPrvSE.exe` launching `cmd.exe /c <command>` (or the raw payload directly, for ADS execution) as a **direct child** — `ParentImage` = `WmiPrvSE.exe` regardless of whether the triggering call was local or via `/node:`. **XSL family:** no corresponding child-process event exists, because no child is ever created — see the callout at the top of this file |
| 7 (Image Loaded) | **XSL family only, if Sysmon is configured to log DLL loads for this image** (Sysmon 7 is high-volume and frequently filtered/excluded by default — a targeted rule keyed on `Image` = `wmic.exe` is required to make this practical). Shows `clr.dll`/`mscoree.dll`/`clrjit.dll` loading into `wmic.exe`'s **own** process — a directly corroborating, near-real-time equivalent of the `wmic.exe.log` filesystem artifact, catchable before the log file is even written |
| 3 (Network Connect) | DCOM/RPC (135 + dynamic high port) for `/node:` remote use; HTTP(S) or SMB for the XSL family's stylesheet fetch, from `wmic.exe`'s own PID in both cases |
| 11 (File Create) | The `wmic.exe.log` CLR usage-log write (XSL family), or the `datafile ... call Copy` destination file — **not** generated for local/remote/ADS execution, since none of those create a new file by default |
| 13 (Registry Value Set) | **Not generated** for anything in this file — consistent with the Registry section above |
| 22 (DNS Query) | Hostname resolution preceding either the `/node:` target connection or the XSL remote-URL fetch |

## DCOM / RPC Detail

The `/node:` execution channel is DCE/RPC over TCP: a bind to the RPC endpoint mapper on **TCP 135**, which hands back a dynamically assigned high port for the `IWbemServices`/`IWbemLevel1Login` calls that actually carry the query or method invocation. Per Microsoft's own [KB929851, "The default dynamic port range for TCP/IP has changed in Windows Vista and in Windows Server 2008"](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/default-dynamic-port-range-tcpip-chang), the default dynamic port range on Vista/Server 2008 and later is **49152-65535** (up from the pre-Vista default of 1025-5000) — this is the general Windows ephemeral-port range, not a WMI-specific one, but it's what the RPC endpoint mapper draws its assigned high port from absent a narrower configured range. This is the same architecture already covered destination-side in `Windows/10 - Persistence Mechanisms/WMI Event Consumers.md`'s "Remote WMI as a Lateral-Movement Primitive" section and `Windows/12 - Lateral Movement.md`'s dedicated WMI/WMIC subsection — this note doesn't re-derive either table, only adds the verified port-range detail neither currently states explicitly.

## Network-Layer Evidence

| Source | What It Shows |
|---|---|
| Zeek `dce_rpc.log` | The RPC bind to the endpoint mapper and subsequent WMI-interface operations — `/node:` remote use only. Full `IWbemServices::ExecMethod`/query-level decoding may require an additional Zeek WMI-decode script beyond the stock `dce_rpc` analyzer |
| Zeek `http.log` | The `.xsl` stylesheet fetch, for the URL-sourced XSL variant — full request URI recoverable. No `wmic`-specific User-Agent string is verified/confirmed for this note; correlate on destination reputation and the requested filename instead |
| Zeek `smb_files.log` | The `.xsl` stylesheet fetch, for the SMB-sourced XSL variant — generates **zero** outbound HTTP(S) traffic, per `02 - Hands-On Use Cases.md`'s framing, defeating any hunt or proxy control keyed purely on web egress |
| NetFlow / firewall logs | A short TCP 135 + dynamic-high-port burst (`/node:` use), and/or an HTTP(S)/SMB session to the stylesheet source (XSL use) — the two are independent and can appear together or separately depending on which technique(s) were combined |

## Endpoint Security Product Signatures

Because `wmic.exe` is a signed, first-party Microsoft binary, static file-signature detection doesn't apply to either family — detection depends on behavioral heuristics: `WmiPrvSE.exe` spawning a command interpreter (execution family), or `wmic.exe` itself loading the CLR and making unexpected network egress (XSL family). The XSL technique is a **documented AppLocker/application-whitelisting bypass** specifically because the payload is never written to disk as a standalone executable and the process performing the "unexpected" action is a trusted, signed system utility — see `02 - Hands-On Use Cases.md`'s SquiblyTwo section and Casey Smith's original research cited there. **AMSI-instrumentation coverage of `wmic.exe`'s CLR-hosted XSL script execution could not be confirmed from a clean source within this note's research footprint** — this is flagged as an open question rather than asserted either way, consistent with how `LOLBins/msbuild/`'s sibling note handles the same open question for `RoslynCodeTaskFactory`'s comparable in-memory-compile scripting path. A modern EDR product should still generate a WMI-execution- or CLR-load-specific behavioral alert independent of AMSI; the absence of such an alert on a host that otherwise shows the WMI-Activity/Sysmon pattern above is worth investigating on its own.

## Memory Forensics

`WmiPrvSE.exe` and its spawned child (execution family) run as ordinary, non-hidden, typically short-lived processes — standard process-listing/injection-detection tooling (see `Windows/17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md`) shows nothing structurally unusual. For the **XSL family**, the more interesting angle is `wmic.exe`'s own process memory: the `wmic.exe.log` usage-log entry records only that the CLR was loaded, **not** the script content itself, and no source reviewed for this note confirms a persistent on-disk cache of the fetched `.xsl` file. That makes a live memory capture of `wmic.exe` — or a network capture of the original stylesheet fetch — the only reliable way to recover the **actual JScript/VBScript payload** after the fact, since neither the filesystem nor the WMI-Activity/Sysmon event trail preserves the script text.

## Building a Timeline

**Execution family (local, ADS, `/node:` remote):** `[Security 4624 Type 3 + 4672, `/node:` remote only]` → WMI-Activity 5857 → Sysmon 1 (`WmiPrvSE.exe` → child process) → Security 4688 (child process, if command-line auditing enabled) → Security 4689 (termination). All typically land within seconds on a clean run.

**XSL family (SquiblyTwo):** Source-host Sysmon 1/Security 4688 for the initiating `wmic.exe` launch → Sysmon 3 / Zeek `http.log`/`smb_files.log` (stylesheet fetch) → WMI-Activity 5857 (the underlying `process get brief` query) → Sysmon 7 (CLR image load into `wmic.exe`, if configured) → Sysmon 11 (`wmic.exe.log` write). **No further process-creation event follows unless the embedded script itself spawns a process** — and if it does, that new process's parent is `wmic.exe` **itself**, not `WmiPrvSE.exe`, since the script executes inside `wmic.exe`'s own CLR-hosted process space rather than inside the WMI provider host. This is a genuinely useful discriminator when triaging an unfamiliar `wmic.exe`-parented child process: it points at the XSL family specifically, not at `Win32_Process.Create()`.

## Contrast Across wmic.exe's Three Execution Paths

| Dimension | Local `process call create` | `/node:` remote `process call create` | XSL / SquiblyTwo |
|---|---|---|---|
| Calls `Win32_Process.Create()`? | Yes | Yes | **No** — pure `process get brief` query |
| `WmiPrvSE.exe` gets an unexpected child? | Yes | Yes | **No** |
| Network evidence | None | TCP 135 + dynamic high port (DCOM/RPC) | HTTP(S) or SMB (stylesheet fetch) |
| Security 4624/4672 | No | Yes | Only if the stylesheet source itself requires authentication (SMB variant) |
| WMI-Activity 5857 | Yes | Yes | Yes |
| Primary distinguishing artifact | Sysmon 1, `WmiPrvSE.exe` parent | Same, plus DCOM network evidence | `wmic.exe.log` CLR usage-log entry |
| AppLocker/WDAC-bypass property | No | No | **Yes** — signed binary, no standalone payload written to disk |
| Execution context | Authenticating user (current token) | Authenticating user (current token or explicit `/user:`) | The user running `wmic.exe` — script runs inside `wmic.exe`'s own process |

See `Windows/12 - Lateral Movement.md` for the broader WMI/WMIC-vs.-PsExec-vs.-WinRM lateral-movement comparison and `Windows/10 - Persistence Mechanisms/WMI Event Consumers.md` for the separate permanent-event-subscription evidence chain this note deliberately doesn't re-derive.
