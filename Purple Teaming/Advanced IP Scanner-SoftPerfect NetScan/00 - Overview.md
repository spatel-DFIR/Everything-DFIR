# Advanced IP Scanner / SoftPerfect NetScan — Overview

This folder bundles **two different vendors' GUI network-discovery tools** — Famatech's **Advanced IP Scanner** and SoftPerfect Pty Ltd's **Network Scanner (NetScan)** — because they're same-purpose alternatives in exactly the way CISA's own advisories treat them: the **Medusa** #StopRansomware advisory ([AA25-071A](https://www.cisa.gov/sites/default/files/2025-03/aa25-071a-stopransomware-medusa-ransomware.pdf)) names **both tools together**, in the same sentence, as the actors' choice for "initial user, system, and network enumeration." They are not the same codebase, the same company, or the same technical depth — this page exists to make the real differences legible rather than let two "network scanner" names blur together.

## Contents
- [Why These Two Are Bundled](#why-these-two-are-bundled)
- [The Core Distinction — Unauthenticated Sweep vs. Credentialed Deep Query](#the-core-distinction--unauthenticated-sweep-vs-credentialed-deep-query)
- [Side-by-Side Comparison](#side-by-side-comparison)
- [When an Analyst Sees One vs. the Other](#when-an-analyst-sees-one-vs-the-other)
- [Sub-Tool Table of Contents](#sub-tool-table-of-contents)

---

## Why These Two Are Bundled

Both tools solve the same first problem in any hands-on-keyboard intrusion — *"what else is on this network, and which of it is worth touching next?"* — with a free, GUI-first Windows application requiring no exploit and no framework. CISA's #StopRansomware corpus cites them **individually and jointly**:

| Advisory | Cites Advanced IP Scanner | Cites SoftPerfect NetScan |
|---|---|---|
| Akira ([AA24-109A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a)) | ✅ | — |
| Black Basta ([AA24-131A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a)) | — | ✅ (with the `netscan.exe`→`Intel.exe`/`Dell.exe` rename finding) |
| Medusa ([AA25-071A](https://www.cisa.gov/sites/default/files/2025-03/aa25-071a-stopransomware-medusa-ransomware.pdf)) | ✅ | ✅ (named together) |

Hunt & Hackett's dedicated Advanced IP Scanner research separately names nine threat-actor groups (Conti, Darkside/UNC2465, Egregor, Hades/Evilcorp, REvil, Ryuk/UNC1878, UNC2447, an Iran-nexus actor, Dharma); 3CORESec's MAL-CL project documents SoftPerfect NetScan across Trickbot, Conti, BazarCall, and FiveHands incidents. Between the two, essentially every major ransomware-affiliated crew in the CISA advisory record has used at least one of them — this is why Wave 2 (real-world threat-actor-sourced tooling) includes both rather than picking one.

## The Core Distinction — Unauthenticated Sweep vs. Credentialed Deep Query

Read each sub-tool's own `01 - Overview.md` for full mechanics — this is the fast disambiguation an analyst needs before reading either page in depth:

```
Advanced IP Scanner                          SoftPerfect NetScan
────────────────────                         ────────────────────
ARP broadcast sweep (LAN-scoped)             ICMP + ARP sweep, same LAN scope
NetBIOS/reverse-DNS hostname                 + WMI, remote registry, SNMP,
MAC/vendor (OUI) lookup                        SSH, PowerShell — CREDENTIALED
HTTP/FTP/SMB/RDP/Radmin port checks            deep query, needs a working
No credentials required at all                 credential against the target
                    │                                       │
                    ▼                                       ▼
     Radmin/RDP pivot for hands-on             Local admin/service/software
        remote control                          inventory WITHOUT a separate
                                                 execution tool — read-only
                                                 but genuinely authenticated
```

Advanced IP Scanner answers **"what's alive, and can I get hands-on-keyboard access to it via Radmin/RDP?"** — its differentiator is the Radmin-pivot business relationship with its own vendor, Famatech. SoftPerfect NetScan answers **"what's alive, AND — using a credential I already have — what does it look like from the inside?"** — its differentiator is a genuinely documented, vendor-supported scripting/automation surface built for exactly that credentialed depth. Neither tool executes arbitrary attacker code on a target the way `Impacket/psexec/` or `Impacket/wmiexec/` do; both are strictly discovery/enumeration, feeding whatever comes next rather than being the "next" step themselves.

## Side-by-Side Comparison

| | Advanced IP Scanner | SoftPerfect NetScan |
|---|---|---|
| Vendor | Famatech (also makes Radmin) | SoftPerfect Pty Ltd |
| Cost model | Free (commercial-use terms ambiguous per some third-party summaries) | Free for personal use (10-device cap); paid license for commercial use |
| Primary discovery mechanism | ARP broadcast sweep | ICMP + ARP sweep |
| Credentialed deep query | **Not documented by the vendor** — a common misconception this repo's page corrects | **Yes** — WMI, remote registry, SNMP, SSH, PowerShell, all vendor-documented |
| First-party CLI | Undocumented by the vendor; real but community-sourced (`advanced_ip_scanner_console.exe /r: /s: /f: /v`) | Extensively vendor-documented (`/auto /live /hide /config /mpass /range /wol` and more) |
| Portable mode | Yes, via `/portable` | Yes, run directly from removable media |
| Config/result artifacts | Registry MRU only by default; export files are operator-triggered and optional | `netscan.xml`/`netscan.lic` regenerate automatically on every use, in addition to operator-triggered exports |
| Notable evasion in the wild | Registry MRU trail generally outlives cleanup; no CISA-documented rename convention | CISA's own Black Basta advisory documents renaming to `Intel.exe`/`Dell.exe` |
| Distinguishing pivot | Radmin (own vendor's remote-control product) / RDP | None built-in — feeds a separate execution tool |
| MITRE ATT&CK Software entry | None (procedure example only) | None (procedure example only) |

## When an Analyst Sees One vs. the Other

- **Advanced IP Scanner, no follow-up connection** → the operator is doing pure situational-awareness recon, likely early in an intrusion, before any credential has been validated against anything.
- **Advanced IP Scanner + a Radmin/RDP pivot immediately after** → the operator already has (or is testing) working credentials/access and is moving to hands-on-keyboard control of a specific host.
- **SoftPerfect NetScan with WMI/registry/SSH query activity** (target-side 4624 + 5857 correlation, `04 - Target Evidence.md` in that sub-folder) → the operator already holds a working privileged credential and is using it to map local admin rights, services, and software across many hosts at once — this is functionally a **privilege-and-attack-surface enumeration** step, closer in intent to `BloodHound/`'s collection phase than to a simple ping sweep, just without BloodHound's graph output.
- **`netscan.exe` renamed to `Intel.exe`/`Dell.exe` at the root of `C:\`** → per CISA's Black Basta advisory, this specific pattern is close to a direct crew fingerprint; worth flagging distinctly in an incident write-up rather than folding into generic "recon tool found" language.
- **Either tool's exported result file recovered intact** → often more valuable than the scan itself: a named, curated target list is a direct window into what the operator considered worth pursuing next, out of everything the scan actually found.

## Sub-Tool Table of Contents

| Sub-Tool | Covers |
|---|---|
| [`Advanced IP Scanner/`](Advanced%20IP%20Scanner/01%20-%20Overview.md) | Famatech's free, credential-free ARP-based LAN sweeper. Radmin/RDP pivot is its real differentiator; registry MRU trail (`HKEY_USERS\<SID>\SOFTWARE\Famatech\advanced_ip_scanner`) is the strongest surviving artifact. Also covers a real trojanized-installer supply-chain campaign delivering Cobalt Strike to admins searching for the legitimate tool. |
| [`SoftPerfect NetScan/`](SoftPerfect%20NetScan/01%20-%20Overview.md) | SoftPerfect's credentialed deep-enumeration engine — genuine WMI/registry/SNMP/SSH/PowerShell querying plus an extensively vendor-documented automation CLI. CISA's Black Basta advisory directly documents its rename-to-`Intel.exe`/`Dell.exe` evasion; PE metadata (`ProductName`/`FileDescription`) is what survives that rename. |

Both sub-tool folders share this page's CISA-citation table and the ARP-sweep-vs-credentialed-query framing above — neither re-derives it.
