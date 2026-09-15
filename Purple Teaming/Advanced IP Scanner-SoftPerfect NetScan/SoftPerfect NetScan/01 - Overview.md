# SoftPerfect Network Scanner (NetScan) — Overview

> 🔴 **Red Flag Principle:** Where `Advanced IP Scanner/` is a credential-free ARP sweep, **SoftPerfect Network Scanner is a genuinely credentialed deep-enumeration engine** — its own manual documents authenticated WMI, remote registry, SNMP, SSH, and PowerShell querying, plus a real, extensively-documented scripting CLI (`/hide /auto /config /mpass /range /wol`) built for unattended, scheduled, fleet-wide use. That same CLI is exactly why CISA's Black Basta advisory documents affiliates **renaming `netscan.exe` to innocuous names like `Intel` or `Dell` and leaving it in the root of `C:\`** — a filename-based hunt is trivially defeated, but the PE's own embedded product metadata (`Network Scanner` / "Application for scanning networks") is not. Hunt the metadata, not the filename.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

- **SoftPerfect Pty Ltd**, an Australian software company, develops Network Scanner as part of a broader system/network-management product line — verified against the vendor's own [product page](https://www.softperfect.com/products/networkscanner/) and [company site](https://www.softperfect.com/).
- **Current version 26.7** (released 30 July 2026 per public download-mirror listings at time of writing) — the product has a long release history dating back to early Windows XP-era network-admin tooling, still actively maintained.
- **Licensing**: free for personal/non-commercial use with a functional cap (10 devices displayed in the free tier per vendor licensing summaries); commercial deployment requires a purchased license — a materially different model from `Advanced IP Scanner/`'s blanket-free (if ambiguously commercially-licensed) distribution.
- **No dedicated MITRE ATT&CK Software (S-number) entry** — verified directly against the live [ATT&CK Software list](https://attack.mitre.org/software/), same absence pattern confirmed for `Advanced IP Scanner/`. Cited only as a procedure example under [T1046](https://attack.mitre.org/techniques/T1046/) (Network Service Discovery) and [T1135](https://attack.mitre.org/techniques/T1135/) (Network Share Discovery).
- **CISA #StopRansomware citations** — named explicitly by filename in the **Black Basta** advisory ([AA24-131A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a)): *"Black Basta affiliates use tools such as SoftPerfect network scanner (netscan.exe) to conduct network scanning... [it] can ping computers, scan ports, and discover shared folders... via WMI, SNMP, and HTTP"* — and the same advisory documents affiliates **renaming the binary to innocuous names like `Intel` or `Dell` and leaving it in the root of `C:\`**, a defining finding for this page's entire evidence chain. Also named in the **Medusa** advisory ([AA25-071A](https://www.cisa.gov/sites/default/files/2025-03/aa25-071a-stopransomware-medusa-ransomware.pdf)) alongside `Advanced IP Scanner/` for "initial user, system, and network enumeration."
- **Real-world malware-campaign associations** — verified against [3CORESec's MAL-CL descriptor](https://github.com/3CORESec/MAL-CL/blob/master/Descriptors/Other/SoftPerfect%20Network%20Scanner/README.md): documented use in **Trickbot**, **Conti**, **BazarCall**, and **FiveHands** ransomware incidents (FiveHands separately covered in [CISA's AR21-126A](https://www.cisa.gov/news-events/analysis-reports/ar21-126a)), with alternate binary names `nv.exe`/`ns.exe` observed alongside the default `netscan.exe`.

## How It Works

### A genuinely multi-protocol discovery and query engine

Verified directly against SoftPerfect's own [product page](https://www.softperfect.com/products/networkscanner/) and manual — this is a substantially deeper tool than a ping sweeper:

| Discovery stage | Mechanism |
|---|---|
| Live-host sweep | Multi-threaded ICMP ping and ARP (IPv4 and IPv6) |
| Port scanning | TCP and (some) UDP port discovery |
| Device discovery | DHCP server, UPnP, mDNS, WSD, ONVIF |
| Banner grabbing | Identifies web/FTP/other services from response banners |
| **Windows deep query** | **WMI**, **remote registry**, file system, services, groups, performance counters, **PowerShell** remoting |
| **Cross-platform deep query** | **SNMP**, **SSH**, XML/JSON endpoints, Nmap integration, Python |

The manual's own section structure (`Windows Queries` vs. `Cross-Platform Queries`) makes explicit that this tool is designed to reach **non-Windows** infrastructure too (via SNMP/SSH), not just a Windows LAN — a real capability difference from `Advanced IP Scanner/`, whose documented feature set is Windows/NetBIOS-centric.

### Credential Manager and authenticated queries

Per the manual's own [Credentials and security](https://www.softperfect.com/products/networkscanner/manual/credentials.htm) page: NetScan ships a built-in **Credential Manager** (`Options → Credential Manager`) storing username/password/comment/tag per entry, reusable across WMI, SSH, SNMP, remote-registry, and file operations — an operator picks "current account" or a specific stored credential per scan-option tab. **Open question, flagged rather than asserted:** the manual documents credential *use* thoroughly but does not itself specify the on-disk encryption/at-rest protection for stored Credential Manager entries beyond the separate, opt-in **master password** feature (`File → Current Config → Set Master Password`), which encrypts the **configuration file** as a whole and gates both interactive load and the `/mpass` command-line switch. Whether Credential Manager entries are protected independently of that master password is not stated in the vendor's own documentation reviewed for this page.

### Command-line automation — the real differentiator from Advanced IP Scanner

The manual's dedicated [Command line](https://www.softperfect.com/products/networkscanner/manual/command-line.htm) page documents an extensive, **first-party** scripting surface (full table below) — scheduled/unattended scans, per-column exports, database output, Wake-on-LAN batch operations, and config-file-driven repeatable runs. This is a genuine vendor-supported automation product, not a community-reverse-engineered set of undocumented flags like `Advanced IP Scanner/`'s console binary.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Host discovery | Multi-threaded ICMP ping + ARP sweep (IPv4/IPv6) |
| Port scanning | TCP and partial UDP port discovery |
| Ancillary discovery | DHCP, UPnP, mDNS, WSD, ONVIF device detection |
| Windows deep query | WMI, remote registry, file system, services, groups, performance counters, PowerShell |
| Cross-platform deep query | SNMP, SSH, HTTP, XML/JSON, Nmap integration, Python/VBScript execution |
| Credential handling | Built-in Credential Manager; optional master-password config-file encryption |
| Export | TXT, HTML, XML, CSV, JSON, or a SQLite database (`.db`) |
| Wake-on-LAN | Native magic-packet transmission, single MAC, file-list, or WOL-manager-wide |

## Command-Line Switches — Quick Reference

Verified directly against the official [manual's command-line reference](https://www.softperfect.com/products/networkscanner/manual/command-line.htm) — every switch below is vendor-documented, unlike `Advanced IP Scanner/`'s community-sourced console flags.

| Switch | Plain-English meaning |
|---|---|
| `/auto:<file>.[txt\|htm\|xml\|csv\|json\|db]` | Runs a scan with the currently loaded settings and exports to the given file; format inferred from extension, `.db` writes a SQLite database |
| `/live:<file>.[txt\|htm\|xml\|csv\|db]` | Like `/auto`, but keeps running with background scanning enabled, re-writing the file after every scan round — the persistent/continuous-monitoring mode |
| `/hide` | Hides the main window entirely (silent/headless mode); progress still prints to a console if launched from one |
| `/config:<file>.xml` | Loads a specified XML configuration (scan options, columns, credentials references) before scanning |
| `/mpass:<password>` | Supplies the master password for an encrypted config file non-interactively — the automation-friendly counterpart to the GUI's password prompt |
| `/load:<file>.xml` | Loads a previously saved XML result set (can combine with `/auto` to trigger a rescan of those same targets) |
| `/range:<from-to>` | Sets the IP range(s) to scan; comma-separate multiple ranges, `#N` suffix for non-contiguous sets |
| `/range:<all\|v4\|v6>` | Auto-detects the local range(s) rather than specifying one manually |
| `/file:<file>.txt` | Loads target IP addresses/ranges from a text file |
| `/cols:<col1;col2;...>` | Exports only the named columns rather than every collected field |
| `/append` | Appends to an existing text/CSV output file instead of overwriting it |
| `/merge` | Merges new results into an existing file, sorting and de-duplicating |
| `/splitmv` | Splits multi-value cells (e.g. multiple shares) into separate output rows |
| `/sharetype:<C\|R\|W\|A\|P>` | Filters exported shares by type (Common/Restricted/Writable/Administrative/Printer) |
| `/wol:<mac>` | Sends a single Wake-on-LAN magic packet to the given MAC address and exits |
| `/wolfile:<file>.txt` | Sends WOL packets to every MAC address listed in a file (one per line) and exits |
| `/wakeall` | Sends WOL packets to every device already configured in the WOL manager and exits |

## Quick Use-Case List

- Baseline unauthenticated ping/ARP/port sweep of a subnet — the entry-level use, same as `Advanced IP Scanner/`
- Authenticated deep scan via WMI/remote registry using stored Credential Manager credentials, pulling installed software, services, and local users from every reachable Windows host
- SNMP-based enumeration of network infrastructure (switches, printers, UPS) that has no Windows agent at all
- SSH-based querying of Linux/Unix/network-appliance targets alongside Windows hosts in the same sweep
- Silent, scheduled, unattended sweep (`/hide /auto:...`) run from Task Scheduler for recurring recon
- Continuous background monitoring (`/live:...`) that re-exports on every scan round without operator interaction
- Config-file-driven repeatable scans (`/config:...` `/mpass:...`) for consistent, scripted multi-host operations
- Exporting results directly to a SQLite database for downstream querying/joining rather than a flat file
- Column-filtered CSV export (`/cols:...`) to hand off a minimal target list (e.g. just Host Name + MAC) to another tool
- Fleet-wide Wake-on-LAN via `/wolfile:` ahead of a mass overnight operation, the same operational need `Advanced IP Scanner/` serves via its GUI
- Renaming the binary (`Intel.exe`, `Dell.exe`) and dropping it at `C:\` root to blend into administrative activity, per CISA's documented Black Basta observation
- Chained workflow: authenticated WMI/registry findings (local admin group membership, running services) feeding directly into a credential-based lateral-movement tool already in this repo

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Network reachability | ICMP/ARP for basic discovery (LAN-scoped like `Advanced IP Scanner/`); routed reachability plus the relevant protocol port for deep queries (WMI/RPC, SSH 22, SNMP 161) against non-local subnets |
| Credentials for deep query | **Required** for WMI/remote registry/SSH/most SNMP-community-string setups — this is the tool's real differentiator from `Advanced IP Scanner/`'s credential-free model |
| Privilege on the scanning host | None beyond normal user rights to run the scan itself; the target-side account used for WMI/registry needs local admin rights on the target for full data return |
| Automation/scripting use | No GUI session required at all — every `/auto`/`/live`/`/hide` invocation runs headless from a script or scheduled task |
| Master-password-protected configs | Requires the password (interactively or via `/mpass`) to load — a config an operator forgets to pass `/mpass` for will simply fail to load rather than prompt, in a headless context |
