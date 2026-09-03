# Metasploit — Meterpreter — Target Evidence

Evidence left on the **target/destination** host. Meterpreter is deliberately thin on disk by design (see `01 - Overview.md`'s reflective-loading mechanics) — the deep end of this evidence trail is **process memory** and the **network layer**, not the filesystem. Filesystem/registry artifacts only appear where a specific feature (initial delivery, `getsystem` technique 2, `extapi`'s NTDS parsing, `lanattacks`, or a `run persistence`-style post module) chose to write or touch something.

## Contents
- [Filesystem](#filesystem)
- [Process Memory Artifacts](#process-memory-artifacts)
- [Registry](#registry)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon (if deployed)](#sysmon-if-deployed)
- [Extension-Specific Artifacts](#extension-specific-artifacts)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Signatures](#endpoint-security-product-signatures)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)

---

## Filesystem

| Artifact | Detail |
|---|---|
| Initial delivery vector | If delivered as a **stageless** `msfvenom`-generated executable, or a **staged** dropper stub, that initial file does land on disk with a normal path/name (whatever the operator/delivery mechanism chose) — this is the one filesystem artifact this note can generalize about. If Meterpreter was injected directly by an exploit into an already-running vulnerable process's memory (no dropper file at all), there may be **no filesystem artifact for delivery whatsoever** |
| `metsrv.dll` itself | **Never written to disk under normal operation** — reflectively loaded straight into process memory (see `01 - Overview.md`). This is the core reason file-hash-based detection doesn't work against Meterpreter the way it does against tools like Impacket's `psexec.py` that drop a consistent binary every run |
| Extension DLLs (`kiwi`, `incognito`, `extapi`, `espia`, `sniffer`, `lanattacks`) | Also never written to disk — uploaded over the live TLV channel and reflectively mapped into the current process, same as `metsrv.dll` |
| `getsystem -t 2` (Named Pipe Impersonation, Dropper variant) | **The one `getsystem` technique that does write a file** — drops a DLL to disk and launches it via `rundll32.exe`. If technique 1 (fully in-memory) succeeded, this file never appears; it's specifically the fallback path |
| `extapi`'s `ntds_parse` | Doesn't create `NTDS.dit` itself, but presumes a copy already exists on disk (typically staged via a volume shadow copy extraction run elsewhere in the same session) — that staged `.dit`/`.jfm`/`SYSTEM` hive copy, wherever the operator placed it, is the filesystem artifact, not the parsing step |
| Persistence (if a `post`/`local` persistence module was run — see `02 - Hands-On Use Cases.md`) | Whatever launcher the chosen module writes — commonly a VBScript, a registry Run-key payload, or a scheduled task — this is bolted onto Meterpreter by a separate module, not part of the core payload's own footprint. See `Windows/10 - Persistence Mechanisms/` for the general artifact reference this note doesn't re-derive |

## Process Memory Artifacts

This is where Meterpreter actually lives. In the process it's resident in (the original delivery process, or wherever `migrate` moved it):
- A **private, executable memory region with no backing file on disk** — the hallmark of any reflectively-loaded module. Standard PE-in-memory forensics (see [Memory Forensics](#memory-forensics) below) will find `metsrv.dll`'s in-memory image here even though `ldrmodules`/module-enumeration tooling that only walks the PEB's normal loaded-module lists won't see it, since the reflective loader never registers itself with the Windows loader the way `LoadLibrary` would.
- Recognizable in-memory strings if the region is dumped: TLV-related constants, extension names (`stdapi`, `kiwi`, `incognito`, `priv`, `extapi`), and — if `kiwi` was loaded — Mimikatz-derived string material from its credential-parsing routines (see `../../Mimikatz/` for what that string material looks like and why it's there).
- After `migrate`, the **original** process no longer carries any Meterpreter memory footprint — the artifact fully relocates. Investigators triaging a single process in isolation, after a migrate has already happened, will find nothing there; the live session is in a different PID entirely by then.

## Registry

Meterpreter's core functionality makes **no registry changes of its own**. The only registry artifacts tied to this note are:

| Key | When It Appears |
|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>` | Created transiently by `getsystem` techniques 1 and 2 (both create a short-lived SYSTEM-context service to obtain the token/pipe connection) — same general shape as a `psexec`-style service-install artifact (see `Impacket/psexec/04 - Target Evidence.md` for the full pattern), though Meterpreter's service is created and torn down by the `getsystem` routine itself, not by the initial payload |
| Persistence-module Run keys | Only present if a `post`/`local` persistence module specifically wrote one — see the cross-link above |

## Windows Event Logs

| Log | Event ID | Signal |
|---|---|---|
| Security | 4688 (if command-line/process-creation auditing enabled) | The initial dropper/stageless executable launching, if one was used for delivery |
| **System** | **7045** | "A service was installed" — fires for `getsystem` techniques 1 and 2 (the transient SYSTEM-context service used for named-pipe impersonation). **Does not fire for technique 3** (token duplication doesn't create a service) or for delivery/session establishment itself |
| System | 7036 | Service start/stop notification, moments after the 7045 above, for the same transient `getsystem` service |
| Security | 4672 | Special privileges assigned — expected once `getsystem` succeeds and the session is running as SYSTEM |
| Security | 4624 (Logon Type 3) | Only relevant if Meterpreter was used as a pivot for further lateral movement (e.g. chained into `psexec.py`/`wmiexec.py` from the session) — not generated by Meterpreter's own delivery or session mechanics |
| System | Rogue DHCP lease activity (no dedicated event ID) | If `lanattacks`' `dhcp_start` succeeded, **other hosts** on the segment may show unexpected default-gateway/DNS changes in their own DHCP client event history — the transient DHCP server itself doesn't generate a Windows Event Log entry on the host running it |

Notably **absent** from this list: no dedicated "Meterpreter" or "Metasploit" event source exists in the standard Windows Event Log — every entry above is a generic Windows event that happens to be a side effect of a specific Meterpreter feature, not a purpose-built log record.

## Sysmon (if deployed)

| Event ID | Signal |
|---|---|
| 1 (Process Create) | The initial dropper/stageless executable, if any; the `rundll32.exe` launch if `getsystem -t 2`'s dropper variant fired |
| 3 (Network Connect) | Outbound connection to the operator's `LHOST:LPORT` for `reverse_tcp`/`reverse_https`/`reverse_http`; inbound connection accepted for `bind_tcp` |
| **7 (Image/DLL Load)** | **Deliberately does NOT fire for `metsrv.dll` or any extension DLL** — reflective loading never calls the Windows loader APIs Sysmon 7 instruments. This negative evidence is itself diagnostic: a process making Meterpreter-shaped network connections (Event 3) with no corresponding Image Load event for anything unusual is consistent with reflective injection rather than a normally-loaded module |
| **8 (CreateRemoteThread)** | Fires when `migrate` injects into a new target process, and again if `getsystem -t 3` reflectively injects `elevator.dll` into a SYSTEM-owned service process — **one of the two strongest Sysmon signals in this note** |
| **10 (ProcessAccess)** | Fires for the `OpenProcess` call that precedes both `migrate` and `getsystem -t 3`'s token duplication — look at `GrantedAccess` for rights consistent with memory-write/thread-creation (e.g. `PROCESS_VM_WRITE`, `PROCESS_CREATE_THREAD`) rather than a benign read-only query, and note the source/target process pair (Meterpreter's current host process → the migration or token-duplication target) |
| 17 / 18 (Pipe Created / Pipe Connected) | Fires for the named pipe `getsystem` techniques 1 and 2 create for their impersonation handshake — pipe naming isn't a fixed, publicly documented string the way Impacket's `RemCom_communicaton` is, so treat this as a supporting signal (present alongside 7045/8/10) rather than a standalone hunt |
| 3 (Network Connect), unusual UDP 67/68 activity | The signal for `lanattacks`' `dhcp_start` — the host suddenly answering DHCP broadcast requests it never previously serviced |

## Extension-Specific Artifacts

Beyond the core mechanics above, several extensions leave their own narrow, feature-specific traces:

| Extension / Command | What to Look For |
|---|---|
| `sniffer` (`sniffer_start`) | Puts the target's NIC into **promiscuous mode** to capture traffic it wouldn't normally see — a change in adapter promiscuous-mode state is queryable via WMI (`Win32_NetworkAdapter`) or EDR NIC-state telemetry, and is itself an anomaly on a workstation (routinely expected on legitimate packet-capture appliances, not on an end-user machine) |
| `lanattacks` (`dhcp_start`) | The host begins answering DHCP broadcast (UDP 67/68) traffic on the local segment — visible in Sysmon Event 3/22-adjacent network telemetry on the host itself, and directly in Zeek's `dhcp.log`/packet capture from any network vantage point on the segment |
| `extapi`'s `clipboard_monitor_start` | No persistent artifact on the target beyond the process-memory hook itself — the captured clipboard text lands in the **operator's** `~/.msf4/loot/` (see `03 - Source Evidence.md`), not on the target |
| `extapi`'s `pagent_send_query` | Interacts with an already-running PuTTY Pageant process via its documented IPC mechanism — no new process or file, but Pageant's own request-handling behavior may be logged by third-party SSH-agent monitoring tools if present |
| `webcam_snap`/`record_mic` | Momentarily activates the webcam/microphone hardware — on Windows 10+, this triggers the OS's own **camera/microphone privacy indicator** (the taskbar icon/LED some hardware exposes) exactly as a legitimate application would, which is a real-time, user-visible tell independent of any log-based detection |

## Network-Layer Evidence

| Source | What It Shows |
|---|---|
| Raw TCP payload (unencrypted TLV header, or the full body on pre-6.0 Framework builds — see `01 - Overview.md`) | Every TLV packet carries a fixed-shape header — a 4-byte XOR key, a 16-byte session GUID, a 4-byte encryption-scheme flag, a 4-byte length, and a 4-byte packet type, ahead of the (AES-256-CBC-encrypted, on Framework 6.0+) TLV data itself. This fixed header shape is what community IDS rulesets (e.g. Emerging Threats/Suricata Metasploit/Meterpreter signature sets) target for stager check-in and session-traffic detection, independent of payload content |
| TLS handshake (`reverse_https`) | The handler's default self-signed certificate is generated fresh at listener start unless the operator supplies a specific cert via `HandlerSSLCert` — a self-signed cert with no real CA chain, especially one with a generic or randomly-generated CN, is a coarse indicator worth flagging, though a well-prepared operator can trivially supply a legitimate-looking cert, so don't treat cert inspection alone as a reliable invariant |
| `reverse_http`/`reverse_https` request shape | Both use the target's **WinInet API** rather than a raw socket, meaning traffic follows normal HTTP(S) request/response semantics, respects any proxy configuration already set on the host, and polls/reconnects rather than holding one continuous socket the way `reverse_tcp` does — a burst of periodic HTTP(S) requests to the same external host/URI pattern, surviving an `msfconsole` restart on the operator side, is the behavioral shape to watch for, distinct from `reverse_tcp`'s single long-lived TCP stream |
| TLS ClientHello fingerprinting (JA3) | Meterpreter's default Windows TLS stack produces a **consistent, publicly documented JA3 hash** for its `reverse_https` ClientHello in its default configuration, because it reuses the OS/runtime's default TLS library behavior rather than mimicking a real browser's cipher/extension ordering — this is a well-established detection technique in public research. Treat any specific hash value as **version- and OS-dependent** rather than a fixed constant; verify against current threat-intel/JA3 databases rather than hardcoding one into a detection rule |
| NetFlow / firewall logs | An outbound connection from an internal host to an external IP on an unusual or non-standard port, established shortly after a phishing/exploitation event and staying open for an extended, often irregular-interval session — the general shape of interactive C2 traffic rather than a fixed Meterpreter-specific pattern at the flow-metadata level alone |
| Zeek `dhcp.log` | Direct visibility into `lanattacks`' rogue DHCP server activity from any network vantage point on the segment — a DHCP server (`DHCPOFFER`/`DHCPACK`) sourced from a host that isn't the environment's real DHCP infrastructure is an unambiguous signal, independent of host-based logging entirely |

## Endpoint Security Product Signatures

Because `metsrv.dll` and its extensions never touch disk, **static file-scanning AV has nothing to scan** in the default case — detection depends entirely on **behavioral** EDR capability: reflective-loading behavior itself (a memory region executing without a corresponding on-disk/loaded module), the `CreateRemoteThread`/`OpenProcess` sequence behind `migrate` and `getsystem -t 3`, and process-behavior heuristics around the transient service creation in `getsystem` techniques 1/2. A target with a modern EDR product and no alert on an otherwise-confirmed Meterpreter session (via the Sysmon/network signals above) suggests either the product's behavioral/injection detection is disabled or misconfigured, or the operator used a custom loader/stager that doesn't trigger the product's specific heuristics — not that Meterpreter itself is inherently undetectable.

## Memory Forensics

This is the highest-value forensic angle for Meterpreter specifically:
- **Volatility's `malfind` plugin** (or equivalent VAD-scanning tooling) flags private, executable memory regions with no backing file — exactly what a reflectively-loaded `metsrv.dll` or extension DLL looks like. This is the direct memory-forensics analog to the "no disk file" problem described throughout this note.
- **`ldrmodules`** (comparing the process's PEB-reported module list against its actual VAD-mapped memory regions) surfaces the mismatch: Meterpreter's in-memory DLL occupies address space the process's own module list doesn't know about, because the reflective loader never registered it the normal way.
- Extracting the flagged memory region (`vaddump`/`memdump`-style extraction) and running community YARA rules for Meterpreter/`metsrv` string and structure signatures (`ReflectiveLoader`, TLV type constants, extension name strings) against it is the practical path to confirming Meterpreter specifically, rather than some other reflectively-loaded implant, once `malfind` has narrowed down a candidate region.
- If `migrate` occurred, the memory image needs to be captured from the **current** host process, not the original delivery process — check Sysmon 8/10 events (if available) to identify which PID Meterpreter migrated into before spending time imaging the wrong one.
- If the AES-256-CBC session key can be recovered from either endpoint's memory (see `03 - Source Evidence.md`), a captured PCAP of the TLV traffic becomes fully decryptable after the fact — worth pursuing on a live/recently-live host before the key is lost with process termination.

## Building a Timeline

Because there's no single "installation" event the way `psexec.py`'s Event 7045 provides, Meterpreter's timeline is built from a **combination of weaker signals in sequence**: initial delivery (4688/Sysmon 1, if a file was involved) → first outbound connection (Sysmon 3) → any `migrate` activity (Sysmon 8/10, process pair changes) → any `getsystem` activity (7045/7036 for techniques 1/2, or Sysmon 8/10 alone for technique 3) → any extension-driven activity with its own trail (e.g. `kiwi`'s LSASS-adjacent memory access, `sniffer`'s promiscuous-mode toggle, `lanattacks`' DHCP broadcast activity) → session termination (final Sysmon 3/network teardown). Cross-reference every timestamp against the operator-side artifacts in `03 - Source Evidence.md` — the database's `sessions.opened_at`/`closed_at` and loot-file timestamps are the most precise operator-side anchors available.
