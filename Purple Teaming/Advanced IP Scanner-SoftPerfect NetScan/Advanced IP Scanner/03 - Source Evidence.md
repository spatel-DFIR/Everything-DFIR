# Advanced IP Scanner — Source Evidence

**Scope note:** for a discovery tool, "source" is the host the operator actually ran the scanner *from* — normally an already-compromised foothold, not a fresh attacker-owned box. Every artifact below is what that foothold host retains, independent of whether the many hosts it scanned show anything at all (`04 - Target Evidence.md` covers that side, and it's comparatively thin, since no code ever executes on a scanned host).

## Contents
- [Registry MRU Trail](#registry-mru-trail)
- [Filesystem Artifacts](#filesystem-artifacts)
- [Process and Command-Line Exposure](#process-and-command-line-exposure)
- [Network State on the Source Host](#network-state-on-the-source-host)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory-Forensics Angle](#memory-forensics-angle)
- [Timeline Correlation](#timeline-correlation)

---

## Registry MRU Trail

The single most durable artifact this tool leaves, verified against the Hunt & Hackett research and corroborating community sources (the Velociraptor `Windows.Forensics.AdvancedPortScanner` artifact, built for Famatech's sibling Advanced Port Scanner, confirms the identical registry-structure pattern under the shared `Famatech` vendor key):

`HKEY_USERS\<SID>\SOFTWARE\Famatech\advanced_ip_scanner` and its `\State` subkey — written on **first use**, by **both the installer and the portable build alike**:

| Value | Forensic meaning |
|---|---|
| `run` | Version string of the instance that last ran |
| `locale_timestamp` | Epoch (UTC) timestamp of the **first-ever launch** on this profile — a hard floor for "the operator had this tool since at least this time" |
| `locale` | UI language selected — a soft, corroborating clue about an operator's background, never a standalone attribution point |
| `LastRangeUsed` | The most recent IP range scanned |
| `LastPortsUsed` | The most recent port set scanned |
| `IpRangesMruList` | **Every** IP range ever scanned from this profile, each entry prefixed with a frequency count — the richest single value for reconstructing which subnets were targeted and how many times |
| `SearchMruList` | IP addresses/hostnames searched via the GUI search box |
| `State\FavoritesTab\Headers*` | Column layout for the Favorites tab — low forensic value on its own, but its mere presence confirms the Favorites feature was actually opened/used |

Because this write happens under `HKEY_USERS\<SID>\...` rather than a machine-wide `HKLM` key, it is **per-user** — correlate the SID to a specific logged-on account, which matters directly for attributing which compromised credential/session actually ran the scan.

## Filesystem Artifacts

| Artifact | Location | Notes |
|---|---|---|
| Installed binary | `C:\Program Files (x86)\Advanced IP Scanner\` | Standard install path |
| Portable binary | `C:\Users\<user>\AppData\Local\Programs\Advanced IP Scanner Portable\` (or wherever `/portable <path>` targeted) | No Program Files/uninstall entry |
| Temp working files | `C:\Users\<user>\AppData\Local\Temp\Advanced IP Scanner 2\` | Created during scan operation, survives independent of install method |
| Exported result files | Operator-chosen path, `.xml`/`.html`/`.csv` | The single richest artifact if not deleted — a named, curated target list |
| Console output files | Operator-chosen path (`/f:` switch) | Present only for scripted/console use |

## Process and Command-Line Exposure

`advanced_ip_scanner.exe` or `advanced_ip_scanner_console.exe` appearing as a running (or recently-run, via Prefetch/Shimcache/Amcache) process on a host that has no legitimate network-admin function is itself a strong contextual flag. Console invocations carry the full `/r:`/`/s:`/`/f:` argument set on the command line — captured in full by Sysmon Event ID 1 or any command-line-logging EDR, and readable in cleartext (there's no credential-bearing switch here to worry about redacting, unlike `SoftPerfect NetScan/`'s `/mpass`).

## Network State on the Source Host

During an active scan, the source host generates a **burst of outbound ARP requests** (LAN-scoped, so visible on the local switch/segment only) plus sequential outbound TCP SYNs to every candidate port (4899, 3389, 21, 80/443, 445) across the whole configured range in a short window — this is the source-side mirror of the same signature documented for the scanned hosts in `04 - Target Evidence.md`, and if Sysmon or a host-based firewall log is present on the source machine itself, Event ID 3 (network connection) will show dozens-to-hundreds of distinct destination IP/port pairs within seconds, a pattern essentially never produced by normal user activity.

## OS-Level Audit Trail

Nothing tool-specific beyond standard process-creation logging (Sysmon 1 / Security 4688) for the binary launch itself, and Prefetch/Shimcache/Amcache entries confirming the binary executed on this host even if later deleted — the console binary's separate filename (`advanced_ip_scanner_console.exe`) means it leaves its own independent Prefetch entry distinct from the GUI build, useful for distinguishing interactive from scripted use after the fact.

## Memory-Forensics Angle

Low value relative to a credential-dumping or injection tool — Advanced IP Scanner does not inject into other processes or hold sensitive material in memory beyond its own scan-results working set. A live memory capture mainly confirms the process was running and can recover in-memory scan-result state if the process is still resident and no export was ever written to disk.

## Timeline Correlation

`locale_timestamp` anchors "earliest possible use on this profile." `IpRangesMruList`/`LastRangeUsed` timestamps (via registry key `LastWriteTime`, not a value inside the data itself) anchor "most recent use." Between those two bounds, correlate exported result-file `LastWriteTime` values and any console-mode output-file timestamps against the network-layer ARP/port-probe bursts documented in `04 - Target Evidence.md` — a match in time between a source-host registry write and a target-side burst of ARP/port-scan traffic from that host's IP is the strongest possible tie between "this profile ran the scanner" and "this is the scan that hit these subnets."
