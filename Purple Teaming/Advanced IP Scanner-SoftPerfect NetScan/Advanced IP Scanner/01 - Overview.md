# Advanced IP Scanner — Overview

> 🔴 **Red Flag Principle:** Advanced IP Scanner is a **free, unauthenticated ARP/ICMP LAN sweeper** — it needs zero credentials to enumerate every live host, MAC address, vendor, and open Radmin/RDP/FTP/shared-folder on a subnet, which is exactly why it's the single most-cited discovery tool across CISA's #StopRansomware corpus (Akira, Medusa, and by name in Hunt & Hackett's APT-toolbox research covering Conti, REvil, Ryuk, Egregor, Darkside, and more). It leaves **no installed-program trace at all in portable mode**, but it cannot avoid writing its own MRU (most-recently-used) registry trail — `IpRangesMruList`, `LastRangeUsed`, `SearchMruList` under `HKEY_USERS\<SID>\SOFTWARE\Famatech\advanced_ip_scanner\State` — a Windows-user-profile artifact independent of install method that survives portable execution and typically survives uninstall. Hunt that key, not "is it installed."

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

- **Famatech Corporation**, founded **1999**, is best known for **Radmin**, its commercial remote-control product — verified against the vendor's own [About Us page](https://www.advanced-ip-scanner.com/about/). Advanced IP Scanner launched in **2002** as a free companion tool, and that sibling relationship is not incidental: the tool's built-in Radmin-connect shortcut (below) exists specifically to funnel discovered hosts into Famatech's paid remote-access product.
- **Current version: 2.5.4594.1** (verified against vendor and mirror-download listings at the time of writing). The tool is distributed as freeware; Famatech's own site states it's used by organizations including IBM, HP, and Siemens, though some third-party license summaries note commercial redistribution requires the vendor's written consent — worth confirming directly with Famatech before assuming blanket commercial-use rights, an ambiguity this note flags rather than resolves.
- **No dedicated MITRE ATT&CK Software (S-number) entry** — verified directly against the live [ATT&CK Software list](https://attack.mitre.org/software/): no "Advanced IP Scanner" entry exists. It is cited only as a **procedure example** under discovery techniques ([T1046](https://attack.mitre.org/techniques/T1046/) Network Service Discovery, [T1018](https://attack.mitre.org/techniques/T1018/) Remote System Discovery, [T1595](https://attack.mitre.org/techniques/T1595/) Active Scanning) inside Group/Campaign/Software pages for the ransomware crews below — same pattern as this repo's `AnyDesk/` page, which found no dedicated Software entry for a widely-abused legitimate tool either.
- **CISA #StopRansomware citations** — named explicitly in the **Akira** advisory ([AA24-109A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a), updated Nov. 2025) for "network device discovery and reconnaissance," and in the **Medusa** advisory ([AA25-071A](https://www.cisa.gov/sites/default/files/2025-03/aa25-071a-stopransomware-medusa-ransomware.pdf)), which names Advanced IP Scanner **alongside SoftPerfect Network Scanner** for "initial user, system, and network enumeration" — the exact pairing this Wave 2 folder bundles the two tools around.
- **Hunt & Hackett's "the preferred scanner in the A(P)T toolbox"** research (verified against the [published blog](https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox)) names **nine** distinct threat-actor groups observed using the tool: **Conti, Darkside/UNC2465, Egregor, Hades/Evilcorp, REvil, Ryuk/UNC1878, UNC2447, an unnamed Iran-nexus actor, and Dharma** — spanning ransomware crews and at least one state-linked actor, underscoring that this isn't a niche-crew tool.
- **Supply-chain risk in the other direction**: Trustwave/LevelBlue's SpiderLabs documented a **trojanized installer campaign** distributed via typosquatted domains (`advanCCed-ip-scaNer[.]com` and similar, ranked via malicious Google Ads against the real `advanced-ip-scanner.com`) that side-loads a malicious `pcre.dll` next to a digitally-signed (stolen-certificate) copy of the real installer, XOR-decrypts (key `0x2E`) and process-hollows a Cobalt Strike beacon into a fresh Advanced IP Scanner process. This means the tool's own name is now also an **initial-access lure against admins/pentesters searching for it**, not just a post-foothold recon tool — relevant to `02 - Hands-On Use Cases.md` and `05 - Detection and Hunting.md`.

## How It Works

### ARP-based LAN discovery — and what it does *not* document

Verified against Famatech's own [Help page](https://www.advanced-ip-scanner.com/help/) and [product page](https://www.advanced-ip-scanner.com/): the tool's primary discovery mechanism is an **ARP-based sweep** of the local subnet — it broadcasts ARP requests across the configured range and treats any ARP reply as a live host, which is faster and more complete on a local segment than an ICMP-only ping sweep (ARP replies aren't affected by host-based ICMP filtering the way `ping` responses often are). Because ARP doesn't route past a gateway, **this discovery mechanism is inherently LAN-segment-scoped** — scanning a remote subnet from across a router falls back to ICMP/TCP-based reachability rather than true ARP resolution.

For each live host, the vendor's own documented feature set is:
- **Hostname** — resolved via NetBIOS and/or reverse DNS.
- **MAC address and vendor** — read from the ARP-resolved MAC, vendor identified via OUI (organizationally unique identifier) lookup.
- **Resource/service checks** — the tool probes for HTTP/HTTPS, FTP, and shared folders, and separately checks for an open Radmin Server or RDP listener, surfacing each as a clickable icon per host.
- **Remote shutdown / Wake-on-LAN** — uses native Windows remote-shutdown APIs and standard WOL magic packets, not a proprietary protocol.

**Correcting a common misconception:** several third-party summaries (and general-purpose search results) describe Advanced IP Scanner as querying hosts via **WMI and remote registry** the way `SoftPerfect NetScan/` genuinely and documentedly does. Famatech's own official Help and product pages make **no such claim** — the documented feature set above (ARP + NetBIOS/reverse-DNS + resource/port checks + Radmin/RDP detection + shutdown/WOL) is narrower than that. Treat any WMI/registry-query claim for this specific tool as unverified rather than fact; it is the single clearest technical differentiator from its bundled sibling `SoftPerfect NetScan/`, which documents exactly that deeper, credentialed query surface.

### Radmin integration — the tool's actual differentiator

Per the Help page: "If Radmin Server is found on the computer, you can connect to it by selecting the corresponding type of Radmin connection in the shortcut menu." This means the scan itself includes a check for an **open Radmin Server listener (TCP 4899 by default)**, and a positive hit surfaces a one-click pivot into Famatech's own **Radmin Viewer** (a separate download) for full remote control — the scanner's real purpose, from Famatech's own business perspective, is as a **discovery front-end that funnels into a Radmin session**, exactly mirroring the RDP-icon pivot for hosts running Terminal Services.

### Portable vs. installed mode

Per the vendor's own Help page, a portable mode is available via `Settings → Options… → Misc`, and the tool is also distributed as a standalone download requiring no installer at all. As with `AnyDesk/`, portable execution avoids the installed-program/Program-Files/Start-Menu trace, but **cannot avoid the per-user registry MRU trail** described in the red-flag callout — this asymmetry (no install trace, but an unavoidable HKCU write) is the load-bearing fact for this entire page's evidence chain.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Host discovery | ARP request/reply broadcast sweep across the configured local-subnet range |
| Hostname resolution | NetBIOS name query and/or reverse DNS |
| MAC/vendor identification | ARP-resolved MAC address, OUI-based vendor lookup |
| Resource/service checks | TCP probes for HTTP/HTTPS, FTP, SMB shared folders, RDP (3389), and Radmin Server (4899 default) |
| Remote pivot | One-click launch into external Radmin Viewer (if Radmin Server found) or the OS's own RDP client |
| Remote shutdown/wake | Native Windows remote-shutdown RPC and standard Wake-on-LAN magic packets |
| Export | `.xml` / `.html` / `.csv` via `File → Save as…` or the shortcut menu's "Save selected" — only `.xml` reloads into Favorites |

## Command-Line Switches — Quick Reference

Famatech's **own site documents no command-line interface at all** for either `advanced_ip_scanner.exe` or the separate `advanced_ip_scanner_console.exe` — a real asymmetry against `SoftPerfect NetScan/`'s extensively vendor-documented CLI (`01 - Overview.md` in that folder). Everything below is corroborated instead by **independent community references** (radmin-club.com's user-run switch guide, a 2017 walkthrough blog) and cross-validated by **SigmaHQ's own published detection rule**, which independently requires `/portable` **and** `/lng` together as a real, observed command-line pattern — so these flags are confirmed to exist and be used in the wild even though the vendor never wrote a reference page for them.

| Switch | Binary | Plain-English meaning |
|---|---|---|
| `/portable [path]` | `advanced_ip_scanner.exe` | Runs/installs in portable mode to the given path — no Program Files entry, no uninstall entry |
| `/lng [language]` | `advanced_ip_scanner.exe` | Sets the UI language at launch |
| `/r:<range>` | `advanced_ip_scanner_console.exe` | IP address or range to scan (e.g. `/r:192.168.0.1-192.168.0.255`) |
| `/s:<file>` | `advanced_ip_scanner_console.exe` | Path to a text file listing IP ranges, one per line — batch scan input |
| `/f:<file>` | `advanced_ip_scanner_console.exe` | Output file path for scan results |
| `/v` (`/v2` grouped) | `advanced_ip_scanner_console.exe` | Verbose output — includes per-service scan results |

**Note on the console binary:** `advanced_ip_scanner_console.exe` ships alongside the GUI executable and is the tool's real scripting/automation surface — an operator never has to touch the GUI at all for a scripted sweep. This is a materially different fact from "Advanced IP Scanner is a GUI-only tool," a framing several write-ups (including this repo's own initial assumptions before verification) default to.

## Quick Use-Case List

- Baseline interactive LAN sweep via the GUI — the default, single-click use case
- Portable, no-install execution to avoid an installed-program trace on a compromised host
- Scripted, multi-range sweep via `advanced_ip_scanner_console.exe /r:` / `/s:` for unattended, repeatable recon
- Exporting live-host/Favorites lists to `.csv`/`.xml` as a target inventory to hand off to another tool or operator
- MAC-vendor (OUI) fingerprinting to distinguish servers/workstations from printers, IoT, and network gear at a glance
- One-click pivot from a discovered host into Radmin Viewer or native RDP for hands-on access
- Fleet-wide Wake-on-LAN to bring sleeping hosts online ahead of a mass overnight operation
- Shared-folder discovery as a staging-location/exfil-target reconnaissance step
- Repeating the sweep per VLAN/segment (via a jump host inside each) since ARP discovery doesn't route past a gateway
- Chained workflow: feeding the exported live-host list into `Impacket/`, `NetExec`, or another lateral-movement tool already in this repo
- Post-engagement cleanup — deleting a portable copy or uninstalling, without realizing the per-user registry MRU trail survives
- The inverted risk: an admin or pentester downloading a **trojanized installer** from a typosquatted domain and self-infecting with a Cobalt Strike beacon while trying to get the legitimate tool

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Local network vantage point | ARP discovery only sees the local broadcast domain — the operator's host must already be on (or bridged/relayed into) the target subnet |
| Privilege | No elevation required to run either the GUI or console binary; Radmin/RDP pivot requires valid credentials on the target separately |
| Credentials | **None** for the core scan itself — this is the tool's whole value proposition versus a credentialed tool like `SoftPerfect NetScan/` |
| Radmin pivot | Requires Radmin Viewer installed separately and valid Radmin Server credentials on the target |
| Console/scripted use | No GUI session needed at all — `advanced_ip_scanner_console.exe` runs headless from a terminal or scheduled task |
