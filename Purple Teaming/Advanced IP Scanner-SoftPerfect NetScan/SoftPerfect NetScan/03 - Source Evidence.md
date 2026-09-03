# SoftPerfect Network Scanner — Source Evidence

**Scope note**, same convention as `Advanced IP Scanner/03 - Source Evidence.md`: "source" is the host the operator ran NetScan *from*. Because NetScan's own config/result files are far richer than Advanced IP Scanner's (genuine credential references, full deep-scan output, SQLite export), this file carries more forensic weight than its sibling tool's equivalent page.

## Contents
- [Configuration and License Files](#configuration-and-license-files)
- [Result Export Files](#result-export-files)
- [Credential Exposure](#credential-exposure)
- [Process and Command-Line Exposure](#process-and-command-line-exposure)
- [Network State on the Source Host](#network-state-on-the-source-host)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory-Forensics Angle](#memory-forensics-angle)
- [Timeline Correlation](#timeline-correlation)

---

## Configuration and License Files

Verified against independent forensic write-ups (Airbus's "Uncovering Cyber Intruders" deep dive) covering both portable and installed deployment:

| File | Location (installed) | Location (portable) | Contents |
|---|---|---|---|
| `netscan.xml` | `%APPDATA%\SoftPerfect Network Scanner\` | Same directory as the running executable | Scan configuration, enabled query types, column layout, and **IP-range scan history** (`<history><item><data>192.168.1.0-192.168.1.100</data></item>`-style entries) |
| `netscan.lic` | `%APPDATA%\SoftPerfect Network Scanner\` | Same directory as the running executable | License/configuration metadata in XML format |

Both files regenerate on use, making them **reliable, freshly-written indicators** rather than static install artifacts — a portable copy run from a USB stick still writes `netscan.xml` right next to the executable, so "no AppData entry" does not mean "no configuration trace" the way it might for a tool that only writes to the user profile.

## Result Export Files

Every `/auto`/`/live` invocation and every manual "Save results" action produces an operator-chosen output file — per `01 - Overview.md`'s command-line table, this can be `.txt`/`.htm`/`.xml`/`.csv`/`.json`, or a genuine **SQLite `.db`** file. A `.db` export is a categorically richer artifact than a flat file: it's a structured, queryable dataset an analyst can open directly with any SQLite client and immediately see every column NetScan collected (hostnames, MACs, open ports, WMI/registry-pulled fields) without reconstructing anything from text parsing.

## Credential Exposure

If the operator used Credential Manager-stored credentials for WMI/SSH/SNMP queries (`01 - Overview.md`), those credential **references** live inside `netscan.xml`/the loaded config file — the manual does not document the at-rest protection applied to Credential Manager entries independent of the separate master-password feature, so treat a recovered `netscan.xml` from a source host as a **potential credential-material find**, not just a scan-configuration file, until proven otherwise on the specific build in use. A master-password-protected config (`/mpass`) at least demonstrates the operator took a deliberate protective step — its absence is itself a data point about operational hygiene.

## Process and Command-Line Exposure

`netscan.exe` (or a renamed copy — `Intel.exe`, `Dell.exe`, `nv.exe`, `ns.exe` are all documented real-world names) running or recently run is visible via Prefetch/Shimcache/Amcache regardless of the name used, since those artifacts key off file hash/binary content in addition to path. Command-line arguments — `/hide /auto:... /range:... /mpass:...` — are captured in full by Sysmon 1/EDR command-line logging, **including the master password value itself** if `/mpass` was used: this is a real, actionable OPSEC gap for the operator and a real credential-recovery opportunity for an analyst, exactly parallel to `AnyDesk/`'s `--set-password`/`--with-password` command-line-exposure caveat.

## Network State on the Source Host

During an active scan, expect the same LAN-scoped ARP/ICMP burst as `Advanced IP Scanner/`, **plus** protocol-specific traffic the sibling tool never generates: outbound WMI/DCOM (RPC dynamic port range, endpoint mapper on TCP 135), remote registry (also via RPC/named pipe over SMB 445), SNMP (UDP 161) queries, and SSH (TCP 22) sessions to every target configured for deep query — a materially richer, more protocol-diverse network fingerprint than a pure ARP sweep, and a stronger source-side network signature for a defender with visibility into the source host's own outbound connections.

## OS-Level Audit Trail

Standard process-creation logging (Sysmon 1 / Security 4688) for the binary launch, plus Prefetch/Shimcache/Amcache confirming execution even post-deletion. Where WMI queries against remote targets were issued, the **source** host's own WMI activity is generally not separately logged by default (WMI-Activity Operational logging covers the querying host's WMI provider subsystem more than outbound query issuance) — the stronger trail for outbound WMI activity is the destination host's own event log (`04 - Target Evidence.md`), not the source.

## Memory-Forensics Angle

Higher value than `Advanced IP Scanner/`'s equivalent section: a live memory capture of a running `netscan.exe` process can recover in-memory Credential Manager entries (username/password pairs actively in use for the current scan) if the process is still resident, independent of whether those credentials were ever written to disk in a master-password-protected form. This is the single strongest reason to prioritize live memory acquisition over a straight shutdown-and-image when NetScan is found actively running on a host during response.

## Timeline Correlation

`netscan.xml`'s own scan-history entries plus the file's `LastWriteTime` anchor "most recent configuration/use." Result-export file timestamps anchor specific scan-completion events. Cross-correlate both against the network-layer WMI/SNMP/SSH protocol traffic documented in `04 - Target Evidence.md` — because NetScan's deep-query protocols each have their own distinct network signature (RPC/135 for WMI, UDP/161 for SNMP, TCP/22 for SSH), a defender can often determine **which specific query types** an operator ran during a given scan window from network evidence alone, even without recovering the config file itself.
