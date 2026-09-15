# Advanced IP Scanner — Hands-On Use Cases

Every scenario below expands an entry from `01 - Overview.md`'s Quick Use-Case List, with a full command sequence where one applies and its MITRE ATT&CK ID(s).

## Contents
- [Baseline Interactive LAN Sweep](#baseline-interactive-lan-sweep)
- [Portable No-Install Execution](#portable-no-install-execution)
- [Scripted Multi-Range Sweep via the Console Binary](#scripted-multi-range-sweep-via-the-console-binary)
- [Exporting a Target Inventory](#exporting-a-target-inventory)
- [MAC-Vendor Fingerprinting of Device Types](#mac-vendor-fingerprinting-of-device-types)
- [Pivoting into Radmin or RDP](#pivoting-into-radmin-or-rdp)
- [Fleet-Wide Wake-on-LAN Before a Mass Operation](#fleet-wide-wake-on-lan-before-a-mass-operation)
- [Shared-Folder Discovery for Staging/Exfil Targets](#shared-folder-discovery-for-stagingexfil-targets)
- [Per-Segment Sweeps Across Multiple VLANs](#per-segment-sweeps-across-multiple-vlans)
- [Chained Workflow: Feeding Live Hosts into a Lateral-Movement Tool](#chained-workflow-feeding-live-hosts-into-a-lateral-movement-tool)
- [Post-Engagement Cleanup That Misses the Registry Trail](#post-engagement-cleanup-that-misses-the-registry-trail)
- [The Inverted Risk: Trojanized-Installer Self-Infection](#the-inverted-risk-trojanized-installer-self-infection)

---

## Baseline Interactive LAN Sweep

**MITRE ATT&CK:** T1046 (Network Service Discovery), T1018 (Remote System Discovery), T1595.001 (Active Scanning: Scanning IP Blocks)

Launch `advanced_ip_scanner.exe`, enter or accept the auto-detected local range, click **Scan**. No credentials, no configuration — this is the default action CISA's Akira and Medusa advisories describe simply as "network device discovery" or "initial ... network enumeration." Every live host on the segment appears within seconds with hostname, MAC/vendor, and any detected HTTP/FTP/SMB/RDP/Radmin resource icons.

## Portable No-Install Execution

**MITRE ATT&CK:** T1046, T1027 (Obfuscated Files or Information — mild, via absence of an install footprint rather than true obfuscation)

```
:: Copy the standalone build to a writable path and just run it
advanced_ip_scanner.exe /portable "C:\Windows\Temp\AIS"
```

No Program Files entry, no Start Menu shortcut, no uninstall registry key. Per `01 - Overview.md`, this **does not** avoid the per-user `HKEY_USERS\<SID>\SOFTWARE\Famatech\advanced_ip_scanner` MRU trail — that write happens on first scan regardless of install method.

## Scripted Multi-Range Sweep via the Console Binary

**MITRE ATT&CK:** T1046, T1018, T1595.001

```
:: Community-documented console syntax, cross-validated against the
:: SigmaHQ detection rule's independent /portable+/lng requirement
advanced_ip_scanner_console.exe /r:172.25.181.1-253 /f:result\1st_ranges.txt /v
advanced_ip_scanner_console.exe /r:172.25.178.1-253 /f:result\2nd_ranges.txt /v

:: Or batch multiple ranges from a target list file
advanced_ip_scanner_console.exe /s:ip_ranges.txt /f:scan_results.txt
```

No GUI window ever opens — this is the scripted, unattended equivalent of the interactive sweep, suited to a scheduled task or a chained script that feeds straight into the next tool. `/v` (or `/v2` for grouped output) adds per-service scan detail to the output file.

## Exporting a Target Inventory

**MITRE ATT&CK:** T1046, T1592.004 (Gather Victim Host Information: Client Configurations — the resulting inventory itself)

```
:: GUI: select discovered hosts → right-click → "Save selected…"
:: or File → Save as… — .xml / .html / .csv
```

Only the `.xml` export reloads back into the Favorites tab for later reference — `.csv`/`.html` are one-way reporting formats. This exported file, not the scan itself, is often the more consequential find for an analyst: it's a **named, operator-curated target list**, frequently handed off between crew members or fed directly into the next stage of an intrusion.

## MAC-Vendor Fingerprinting of Device Types

**MITRE ATT&CK:** T1018, T1592.004

The OUI-based vendor lookup on every discovered MAC address lets an operator distinguish server/workstation hardware from printers, VoIP phones, and IoT/OT devices at a glance without touching any of them — useful for prioritizing which hosts are worth deeper enumeration (domain controllers, file servers) versus which to ignore (a networked printer has no ransomware value).

## Pivoting into Radmin or RDP

**MITRE ATT&CK:** T1021 (Remote Services), T1219.002 (Remote Access Software — for the Radmin leg specifically)

```
:: GUI: right-click a host showing the Radmin or RDP icon →
:: "Radmin: Full control" / "Connect via RDP"
```

The scan's own port check for **TCP 4899** (Radmin Server default) or **3389** (RDP) is what populates these icons — a host lighting up with a Radmin icon means Radmin Server is already installed and listening there, either legitimately (an admin's own remote-support tool) or as a prior actor's persistence mechanism the current operator just inherited visibility into.

## Fleet-Wide Wake-on-LAN Before a Mass Operation

**MITRE ATT&CK:** T1018

```
:: GUI: select hosts → right-click → "Wake up"
```

Ransomware operators running an overnight mass-encryption push need sleeping/powered-down endpoints online first — WOL magic packets sent to every MAC address discovered in an earlier sweep solve exactly that logistics problem, using standard Wake-on-LAN rather than anything proprietary.

## Shared-Folder Discovery for Staging/Exfil Targets

**MITRE ATT&CK:** T1135 (Network Share Discovery)

The scan's shared-folder resource check surfaces every SMB share visible to the operator's current auth context across the whole subnet in one pass — a fast way to locate a writable share for payload staging or a data-rich share worth exfiltrating, without running `net view` host-by-host.

## Per-Segment Sweeps Across Multiple VLANs

**MITRE ATT&CK:** T1018, T1595.001

```
:: Repeat the same GUI or console sweep from a jump host already
:: inside each VLAN/segment — ARP discovery does not route past a
:: gateway, so a single scan from one segment cannot see hosts on another
```

A realistic large-environment operation runs this tool **repeatedly**, once per reachable segment, rather than once — each fresh registry MRU entry and each fresh burst of ARP traffic on a different segment is a separate, independently-discoverable event for a defender watching multiple segments.

## Chained Workflow: Feeding Live Hosts into a Lateral-Movement Tool

**MITRE ATT&CK:** T1046 → T1021/T1570 (Lateral Tool Transfer) downstream

```
:: Export live hosts to CSV, extract the IP column, feed it as a
:: target list to an already-built lateral-movement tool in this repo
Import-Csv .\ais_export.csv | Select-Object -ExpandProperty IP |
  Out-File .\targets.txt
:: → Impacket/psexec/, Impacket/wmiexec/, or a NetExec sweep against targets.txt
```

Advanced IP Scanner's own role in a real chain ends at "who's alive and what's open" — the actual code execution or credential validation against that list happens in a separate, already-covered tool.

## Post-Engagement Cleanup That Misses the Registry Trail

**MITRE ATT&CK:** T1070 (Indicator Removal — partial)

```
:: Delete the portable copy or run the installed version's uninstaller
del "C:\Windows\Temp\AIS\advanced_ip_scanner.exe"
```

Deleting the binary or uninstalling removes the executable and (for installed mode) the Program Files entry, but does **not** touch `HKEY_USERS\<SID>\SOFTWARE\Famatech\advanced_ip_scanner` — an operator who only deletes the binary leaves the MRU trail fully intact for `05 - Detection and Hunting.md` to find.

## The Inverted Risk: Trojanized-Installer Self-Infection

**No discrete operator-side MITRE ATT&CK ID** — this is a threat against whoever downloads the tool, not a technique run by an operator already using it, mirroring `AnyDesk/02 - Hands-On Use Cases.md`'s tech-support-scam entry.

Per LevelBlue/Trustwave's SpiderLabs research: an admin or pentester searching for "advanced ip scanner download" who clicks a malicious ad or typosquatted domain (`advanCCed-ip-scaNer[.]com` and similar) receives a **digitally-signed (stolen-certificate) installer** that behaves identically to the real thing but DLL-side-loads a malicious `pcre.dll`, which XOR-decrypts (key `0x2E`) and process-hollows a **Cobalt Strike** beacon into a newly-spawned Advanced IP Scanner process, beaconing to `nanopeb[.]com`/`coldfusioncnc[.]com`. The lesson for this repo's dual audience: verifying you're on `advanced-ip-scanner.com` itself (not a search-ad result) before downloading is a real, documented control, and a defender investigating "why is Advanced IP Scanner spawning a beaconing child process" should check for `pcre.dll` in the install directory before assuming the scan itself is the malicious action.
