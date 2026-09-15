# LOLBins — sc.exe — Target Evidence

Evidence left on whichever host the SCM call actually lands on — the source host itself for local use, or the separate `\\target` for remote use. Per `01 - Overview.md`'s red-flag callout, this file keeps two paths structurally separate throughout:

- **The `create` path** — a brand-new service registration, which reliably fires System **7045** (and Security **4697** if audited).
- **The `config` path** — reconfiguring an already-installed service's `binPath`/account/start-type, which does **not** fire 7045 or 4697. Its only native install/config-family System-log signal is **7040**, and that fires **only when the start type itself changes** — an operator who only swaps `binPath=` and leaves `start=` untouched triggers neither event.

Confusing these two is the easiest mistake to make reading this file — a host with no 7045/4697 in its retained window has **not** ruled out a service-based persistence/execution technique, only the `create` variant of it.

## Contents
- [Filesystem](#filesystem)
- [Registry](#registry)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon (if deployed)](#sysmon-if-deployed)
- [MS-SCMR / RPC Detail](#ms-scmr--rpc-detail)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Signatures](#endpoint-security-product-signatures)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)
- [Contrast With PsExec / psexec.py / smbexec.py](#contrast-with-psexec--psexecpy--smbexecpy)

---

## Filesystem

| Artifact | Detail |
|---|---|
| Dropped payload | **`sc.exe` drops nothing itself** — per `01 - Overview.md`, `binPath` must already point at something reachable. Whatever staged the payload (a separate SMB copy over `ADMIN$`/`C$`, `certutil`/`bitsadmin`, an ADS-embedded stream) is where the real filesystem artifact and its own creation-timestamp/hash evidence live — see that mechanism's own `LOLBins/` note for its filesystem footprint |
| ADS-embedded `binPath` payload | Invisible to a default directory listing, since it's a data stream on an existing file rather than a new visible file. `Get-Item -Stream *` (PowerShell) or `dir /r` is required to enumerate — same general technique documented in `Windows/08 - Deleted Items and File Existence.md`, not re-derived here |
| Prefetch (for the spawned payload) | `<PAYLOAD>.EXE-<HASH>.pf`, confirming the service's binary actually executed, with run count and timestamps. **`sc.exe`'s own Prefetch entry only exists on the source host** — for remote use, `sc.exe` never runs on the target at all, so there's no `SC.EXE-<HASH>.pf` to find there |
| Amcache / ShimCache (for the spawned payload) | Records the payload executable's first/last-seen and (Amcache) SHA1 hash — see `Windows/06 - Evidence of Program Execution/Amcache.md` and `.../ShimCache (AppCompatCache).md`. Both are bypassed if the payload is a shared-process service DLL rather than a standalone executable, per the general caveat already documented in `Windows/10 - Persistence Mechanisms/Services.md`'s "Service DLL Abuse" section |

## Registry

| Key / Value | Detail |
|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>` | The service's full configuration — `ImagePath` (= `binPath`), `Start`, `Type`, `ObjectName`, `DisplayName` — created fresh by `sc create`, individual values overwritten in place by `sc config`. Full value-meaning table already documented in `Windows/10 - Persistence Mechanisms/Services.md`'s "Services as Persistence — Registry Structure" section, cross-linked here rather than re-derived |
| `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\Security` | Binary-encoded security descriptor — the value `sc sdset`/`sc sdshow` read and write. **This is the artifact a hidden or backdoored service's DACL actually lives in** — a raw registry read of this key (bypassing `sc sdshow`'s own SCM-mediated read path) is one of the few ways to inspect a hidden service's permissions without first proving the service exists through some other channel; see `05 - Detection and Hunting.md` |
| `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\Parameters\ServiceDll` | Only present for `type= share` services — the actual code lives in this DLL, hosted inside an ordinary-looking `svchost.exe -k <group>`, rather than in `ImagePath`. Full mechanic already covered in `Windows/10 - Persistence Mechanisms/Services.md`'s "Service DLL Abuse" section |
| **No dedicated key for `sc failure`'s settings** | Failure/recovery actions are stored as binary values (`FailureActions`, `FailureCommand`, `FailureActionsFlag`) directly under the same `Services\<ServiceName>` key, not a separate subkey — a `sc qfailure <name>` or a direct read of `FailureCommand` is the way to recover the `command=` payload from a live or offline host |

## Windows Event Logs

| Log | Event ID | Signal |
|---|---|---|
| System | **7045** | **`create`-path only.** "A service was installed in the system" — Service Control Manager, enabled by default, no audit policy required. Names the service, its `ImagePath`, and the account it runs as. **The primary, most reliable native detection signal for new-service creation** — but see the red-flag callout: it does not fire for `sc config` |
| Security | **4697** | **`create`-path only**, and requires the non-default **"Audit Security System Extension"** subcategory. Per Microsoft's own [event-4697 reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697), captures `SubjectUserSid`/`SubjectUserName` (who installed it), `ServiceName`, `ServiceFileName`, `ServiceType`, `ServiceStartType`, and `ServiceAccount` — richer than 7045 (ties the install to a specific authenticated account) but present far less often in practice, since the audit subcategory is off by default |
| System | **7040** | **`config`-path, start-type changes only.** "The start type of the *X* service was changed from *Y* to *Z*." Fires when `sc config <name> start= ...` changes the start type. **Does not fire for a `binPath`-only reconfiguration** — multiple independent security-research write-ups flag this as an actively-exploited detection gap: hijacking an existing service's `binPath` while leaving `start=` untouched produces **no native System-log signal at all** |
| System | **7036** | "The *X* service entered the running/stopped state." Fires on every start/stop, regardless of which path (`create`+`start`, or a `stop`/`start` cycle after a `config` hijack) put the service there. High-volume/noisy on a typical host — hundreds of legitimate services start and stop routinely — but the timestamp is useful once a specific service name is already the focus |
| System | **7034** | "The *X* service terminated unexpectedly." Relevant to the failure-action persistence use case — a crash here is the trigger event for whatever `sc failure ... command=` configured |
| System | **7031** | "The *X* service terminated unexpectedly. It has done this *N* time(s)." — the counted/recovery-eligible variant of 7034, fires once the SCM is about to (or has) invoked a configured failure action |
| Security | 4624 (Logon Type 3) + 4672 | The inbound authenticated session backing a remote `sc \\target` call — see `01 - Overview.md`'s red-flag callout: this pair, not `sc.exe`'s own command line, is where the credential/authentication evidence actually lives on the target |
| Security | 5140 / 5145 | Share access to `IPC$` (session negotiation) and, if the payload was staged over `ADMIN$`/`C$`, that share access too — the same general admin-share evidence chain [`Impacket/psexec/04 - Target Evidence.md`](<../../Impacket/psexec/04 - Target Evidence.md>) documents for PsExec-style tooling |
| Security | 4670 | "Permissions on an object were changed" — Microsoft's own documentation scopes this event's examples to file, registry, and token objects; **whether `sc sdset` against a service object reliably generates 4670 could not be confirmed from a clean, authoritative source within this note's research footprint.** Security-vendor detection content for `sc sdset` (e.g. Splunk's published analytic) keys on the `sc.exe`/`sdset` **command line** instead of a dedicated permissions-changed event, which is a practical signal this note does confirm — treat 4670 coverage for services as an open question, not a relied-upon signal, until independently verified against a live test host |
| Security | 4688 (spawned payload) | With command-line auditing enabled, shows the service's actual payload process being created — `ParentImage` is `services.exe` (own-process service) or a `svchost.exe -k <group>` instance (shared-process service), **never `sc.exe`**, since `sc.exe` itself only ever runs on the machine issuing the command, not on the target it points at |

## Sysmon (if deployed)

| Event ID | Signal |
|---|---|
| 1 (Process Create) | The spawned payload, with `ParentImage` = `services.exe` or the hosting `svchost.exe -k <group>` — **not** `sc.exe`. For the local-use case (no `\\target`), Sysmon 1 also captures `sc.exe`'s own invocation on the same host, with its full command line including `binpath=`/`sdset` arguments |
| 12 / 13 / 14 (Registry Create/Set/Rename) | **Config-dependent, not automatic.** Sysmon's stock/default configurations do not include `Services\<Name>\ImagePath` or `\Security` in their registry-monitoring scope by default — a deliberately-added include rule targeting `HKLM\SYSTEM\CurrentControlSet\Services\\` is required to make Sysmon 13 catch a `sc config` `ImagePath` change or a `sc sdset` security-descriptor overwrite. Where present, this is the single best target-side signal for the `config`-path detection gap described above, since it fires regardless of whether the start type also changed |
| 17 / 18 (Pipe Created/Connected) | `\svcctl`/`\ntsvcs` named-pipe activity for RPC-over-SMB remote use, if Sysmon's pipe-monitoring rules aren't scoped to exclude system pipes (many stock configs do exclude `\svcctl` as high-volume/expected — verify local configuration before relying on this) |
| 3 (Network Connect) | TCP 445 or TCP 135 + dynamic high port, source = the calling host, for remote `\\target` use — visible target-side as an inbound connection |

## MS-SCMR / RPC Detail

Per the [MS-SCMR specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f), the server interface binds to the well-known named pipe `\PIPE\svcctl` (alias `\PIPE\ntsvcs`), reachable over either RPC/SMB (`ncacn_np`, TCP 445) or RPC/TCP (`ncacn_ip_tcp`, TCP 135 endpoint mapper + a dynamically negotiated high port — Vista+ clients default to this transport). The RPC calls that matter for reconstructing intent from a packet capture or Zeek log, in the order a `create`+`start` sequence issues them: `OpenSCManagerW` (get a handle to the SCM database, requesting `SC_MANAGER_CREATE_SERVICE`), `CreateServiceW` (register the new service, returns a service handle), `StartServiceW` (launch it). A `config`-path hijack instead issues `OpenServiceW` (open the existing service by name) followed by `ChangeServiceConfigW`. `sc sdset`/`sdshow` correspond to `SetServiceObjectSecurity`/`QueryServiceObjectSecurity`. This is the identical transport and interface family already covered destination-side in `Windows/10 - Persistence Mechanisms/Services.md`'s "Remote Service Creation for Lateral Movement" section — this note adds the RPC-operation-name-level detail that table doesn't spell out, rather than re-deriving the event/registry chain it already documents.

## Network-Layer Evidence

| Source | What It Shows |
|---|---|
| Zeek `dce_rpc.log` | The MS-SCMR bind (interface UUID `367ABB81-9844-35F1-AD32-98F038001003`) and the named RPC operation (`OpenSCManagerW`, `CreateServiceW`, `ChangeServiceConfigW`, `StartServiceW`, `SetServiceObjectSecurity`, etc.) — the single richest network-layer signal available, since it names the exact SCM call rather than just "some SMB/RPC traffic occurred" |
| Zeek `smb_files.log` / `smb_mapping.log` | `IPC$`/`ADMIN$`/`C$` share-mapping activity around the same connection window, if the payload was staged over SMB rather than already present on the target |
| NetFlow / firewall logs | A short TCP 445 or TCP 135 + dynamic-high-port session between the two hosts — without payload decoding, this alone can't distinguish `sc.exe` from any other SCM client (`services.msc`, PowerShell's `*-Service` cmdlets used remotely, or a completely different SCM-based tool like PsExec), so it's a corroborating signal, not a standalone one |

## Endpoint Security Product Signatures

`sc.exe` is a signed, first-party Microsoft binary — static file-signature detection has no purchase here, and neither does the LOLBAS-catalogued ADS technique change that (the ADS payload itself may well be unsigned, but `sc.exe` still is). Detection realistically depends on behavioral heuristics layered on top of the native/Sysmon evidence above: a new service whose `binPath` sits outside `%SystemRoot%`/`%ProgramFiles%`, an existing service's `ImagePath` changing to a value that doesn't match its historical baseline, or `services.exe`/`svchost.exe` spawning a process from `%TEMP%`/`%APPDATA%`/a user profile. A modern EDR product commonly ships a specific rule for the `sc sdset ... DCLCWPDTSD ...` service-hiding pattern given how widely SANS's write-up and the corresponding SigmaHQ rules have circulated — but this note found no single authoritative source confirming universal EDR coverage of the DACL-backdoor-grant variant (the inverse pattern, granting rather than denying access), which is flagged here as comparatively less likely to be covered out of the box.

## Memory Forensics

- **Volatility's `svcscan` plugin** enumerates the live SCM service list from a memory image, independent of whatever the on-disk registry currently shows or whatever a hidden service's DACL currently blocks — a memory image captured while a `sdset`-hidden service is still registered will still show it via `svcscan`, since the plugin walks the SCM's in-memory service database directly rather than going through the same enumeration APIs `sc query`/`Get-Service` use (and which the DACL denial blocks).
- **The spawned payload's process memory** — standard process/DLL/injected-code forensics apply once the service's binary is identified via the registry/event-log chain above; no `sc.exe`-specific memory artifact exists beyond confirming the service's presence via `svcscan`.

## Building a Timeline

A representative remote `create`+`start` sequence, correlated across both hosts:

1. **Source host:** Security 4648 (explicit-credential logon attempt) or an existing token used, moments before —
2. **Source host:** Sysmon 1 / Security 4688 for `sc.exe`'s own invocation, full `\\target create ...` command line captured
3. **Target host:** Security 4624 (Logon Type 3) + 4672 — the authenticated session backing the RPC call arrives
4. **Target host:** Zeek `dce_rpc.log` — `OpenSCManagerW` → `CreateServiceW` bind and call sequence
5. **Target host:** System **7045** (+ Security **4697** if audited) — the new service registration lands in the event log
6. **Target host:** Zeek `dce_rpc.log` — `StartServiceW` call
7. **Target host:** System **7036** (service entered running state) + Sysmon 1 / Security 4688 for the spawned payload, parented by `services.exe`/`svchost.exe`
8. **Target host:** Prefetch/Amcache/ShimCache entries for the payload confirm actual execution
9. *(if cleaned up)* **Target host:** registry key removal for `sc delete` — no dedicated "service deleted" event exists, so this step is only visible via registry-timeline analysis (last-write-time gaps) or a before/after live-response diff, not a single log line

For the `config`-path hijack variant, steps 5-6 collapse: no 7045/4697 fires, and unless `start=` also changed, no 7040 fires either — step 4's `ChangeServiceConfigW` RPC call (network-layer only) and, if deployed, a Sysmon 13 registry-set event become the *only* target-side signals proving the reconfiguration happened at all, ahead of the eventual 7036 start/stop pair.

## Contrast With PsExec / psexec.py / smbexec.py

| | `sc.exe` (raw) | Sysinternals PsExec | Impacket `psexec.py` | Impacket `smbexec.py` |
|---|---|---|---|---|
| Payload delivery | **None built in** — `binPath` must already be reachable | Uploads its own service binary over `ADMIN$` | Uploads a RemCom-derived binary over `ADMIN$`/writable share | No binary upload — drives everything through `cmd.exe /c echo ... > batch file` |
| Service lifecycle | **Fully operator-driven** — persists indefinitely unless the operator explicitly `stop`s/`delete`s it | Created, started, and removed automatically per session | Created, started, and removed automatically per session (best-effort cleanup) | A **fresh service created/started/deleted per command**, not once per session |
| Service name | Whatever the operator specifies — no randomization | `PSEXESVC` by default (renamable via `-r`) | Random 4-character mixed-case string | Impacket's own naming convention — see [`Impacket/smbexec/01 - Overview.md`](<../../Impacket/smbexec/01 - Overview.md>) |
| Credential handling | **None of its own** — rides a pre-existing session (this note's central finding) | `-u`/`-p` switches, its own SMB auth negotiation | `-hashes`/`-k`/`-aesKey`/password — full alternate-auth support | Same auth-flag surface as `psexec.py` |
| DACL manipulation | **Native, first-class** (`sdset`/`sdshow`) — no equivalent in any of the other three tools | None | None | None |

`sc.exe` is the raw primitive every column to its right is built on top of — see `Windows/10 - Persistence Mechanisms/Services.md`'s "Remote Service Creation for Lateral Movement" and "PsExec Special Case" sections for the general-services framing, and [`Impacket/psexec/04 - Target Evidence.md`](<../../Impacket/psexec/04 - Target Evidence.md>) / [`Impacket/smbexec/04 - Target Evidence.md`](<../../Impacket/smbexec/04 - Target Evidence.md>) for each wrapper's own distinctive artifact chain.
