# AnyDesk — Target Evidence

What an AnyDesk session leaves on the **target/victim** host — the primary evidentiary surface for this tool, per `03 - Source Evidence.md`'s reframe. Artifacts split into two tiers: those requiring **installed mode** (registry, service, event-log install signals) and those present under **either** portable or installed mode (trace/log files, network connections) — every table below flags which tier it belongs to, since that split is the backbone of `05 - Detection and Hunting.md`'s priority ranking.

## Contents
- [Filesystem Artifacts](#filesystem-artifacts)
- [Registry Artifacts (Installed Mode Only)](#registry-artifacts-installed-mode-only)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon](#sysmon)
- [Trace and Log Files — the Core Evidentiary Set](#trace-and-log-files--the-core-evidentiary-set)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Behavior](#endpoint-security-product-behavior)
- [CVE-2024-12754 — Session-Initiation Junction Abuse](#cve-2024-12754--session-initiation-junction-abuse)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)
- [Distinguishing Legitimate IT Use from Abuse](#distinguishing-legitimate-it-use-from-abuse)

---

## Filesystem Artifacts

| Artifact | Path | Mode |
|---|---|---|
| Portable executable + its own data folder | Wherever the operator placed it, plus `%APPDATA%\AnyDesk\` for UI-side traces/config even in portable mode | Portable or installed |
| Installed binary | `C:\Program Files (x86)\AnyDesk\AnyDesk.exe` (documented default; operator-changeable at install time) | Installed only |
| Service-side data folder | `C:\ProgramData\AnyDesk\` | Installed only |
| Session-initiation temp copy | `C:\Windows\Temp\<targetimagefilename>` (installed) / `%LOCALAPPDATA%\Temp` (portable) — the desktop-background copy central to CVE-2024-12754, below | Either |
| `user.conf` | Same data folder as above — per Hats Off Security's analysis, reveals configured file-transfer directory paths and the username of any connected remote system | Either |
| Thumbnails | `<data folder>\thumbnails\` — cached preview images of remote systems' desktops/wallpapers from past sessions | Either |
| Chat logs | Stored in the AnyDesk data subdirectory, named by the remote client's ID, containing the in-session chat transcript | Either |

## Registry Artifacts (Installed Mode Only)

Installing AnyDesk registers it as a genuine Windows service, so it follows the standard OS service-registration pattern rather than anything AnyDesk-specific:

- `HKLM\SYSTEM\CurrentControlSet\Services\AnyDesk` — the service's own registration key (`ImagePath`, `Start` type, `DisplayName`), following the same structure every Windows service uses.
- `HKLM\SOFTWARE\AnyDesk` — install-location and configuration state, referenced across multiple independent forensic write-ups without a single fully-published canonical value list; treat exact subkey names as something to confirm against a live installed instance in your own environment rather than assumed a priori.
- Standard `Uninstall` registry entries under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\` for Add/Remove Programs visibility (installed mode only — this is exactly the entry `--remove`/portable mode never creates in the first place).

**None of this exists in portable mode at all** — no service key, no `HKLM\SOFTWARE\AnyDesk`, no Uninstall entry. This is the mechanical reason `01 - Overview.md`'s red-flag callout singles out portable mode as defeating any registry-based hunt structurally, not just by evasion effort.

## Windows Event Logs

| Log | Event ID | Signal | Mode |
|---|---|---|---|
| System | 7045 | Service creation — fires once, at install time, for the AnyDesk service | Installed only |
| Security | 4688 | Process creation for `AnyDesk.exe` (or its renamed copy — command-line auditing needed to see the full invocation) | Either |
| Security | 4624 | Logon events on the host, if the session results in additional local/domain authentication activity from within the remote session | Either |
| Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | 2004 / 2006 | Firewall rule creation/deletion — AnyDesk's install (or first run) commonly provisions its own inbound-allow rules; a rule referencing `AnyDesk.exe` appearing outside a change-managed deployment window is a hunting signal in its own right | Installed typically, portable can still trigger a rule prompt depending on Windows Firewall profile |

## Sysmon

| Event ID | Signal |
|---|---|
| 1 (Process Create) | `AnyDesk.exe` (or a renamed copy) launching — critically, **`OriginalFileName` in the Sysmon 1 event reads `AnyDesk.exe` regardless of the on-disk filename**, since this reads the compiled PE's own embedded metadata field, not the path it was invoked from (`01 - Overview.md`'s red-flag callout, `02 - Hands-On Use Cases.md`'s rename use case) |
| 3 (Network Connect) | Outbound connection to `*.net.anydesk.com`-resolving infrastructure on TCP 80/443/6568 |
| 11 (FileCreate) | The service-initiation temp-copy file under `C:\Windows\Temp\` (or `%LOCALAPPDATA%\Temp\` portable), trace-file creation/updates under the data folder |
| 22 (DNSEvent) | DNS resolution of `*.net.anydesk.com` — a durable signal independent of which of the three fallback TCP ports the session ultimately uses |

## Trace and Log Files — the Core Evidentiary Set

Verified against AnyDesk's own [trace-file doc](https://support.anydesk.com/docs/what-are-trace-files) and cross-checked against independent forensic analyses (Hats Off Security, inversecos, The DFIR Spot) since the vendor doc alone doesn't cover field-level format:

| File | Path | Records | Mode |
|---|---|---|---|
| `ad.trace` | `%APPDATA%\AnyDesk\ad.trace` | UI-side activity: connection setup/teardown, an **`External address`** field carrying the remote party's IP, file-transfer task activity, application/OS version — the single richest trace file for reconstructing session content | Either |
| `ad_svc.trace` | `%PROGRAMDATA%\AnyDesk\ad_svc.trace` | Service-side (network) activity — connections handled while no UI window was open, unattended-access session establishment, remote-restart requests | **Installed only** — the doc is explicit that this file "is only available if AnyDesk is installed" |
| `connection_trace.txt` | Same data folder as `ad.trace`/`ad_svc.trace` | **Inbound connection requests only** — entries formatted `Incoming <date>, <time> [<Username>]`, with an authentication-method field (`User` = locally accepted, `Passwd` = password entered, `Token` = "remember this session" token reused, or `REJECTED`) — verified independently by two forensic write-ups as inbound-only, a real and non-obvious asymmetry covered in `03 - Source Evidence.md` | Either |
| `file_transfer_trace.txt` | Same data folder | File-transfer session activity with byte counts, per The DFIR Spot's analysis | Either |

**A `Passwd` entry in `connection_trace.txt` only ever appears at all if the local system has an Unattended Access password configured** — its presence is itself confirmation that persistent unattended access was set up on this host, not just a one-off interactive session.

## Network-Layer Evidence

| Signal | Detail | Confidence |
|---|---|---|
| DNS/connection to `*.net.anydesk.com` | Verified against AnyDesk's own [firewall doc](https://support.anydesk.com/docs/firewall) as the domain pattern the client needs reachable | **High** — this is the vendor's own relay infrastructure; an operator cannot change it without abandoning AnyDesk's network entirely |
| TCP 80/443/6568 | Fallback order per the same doc — only one needs to be open | High, but overlaps with legitimate web/HTTPS traffic on 80/443 at the port level alone; pair with the DNS signal |
| UDP 50001–50003, multicast `239.255.102.18` | Discovery/LAN-scan traffic | Medium — only fires for local-network discovery, not present in every session |
| TLS session content | AEAD-encrypted per AnyDesk's own security documentation — no plaintext session content recoverable from a passive network capture | N/A for content inspection; destination/timing metadata is what's actually usable |

## Endpoint Security Product Behavior

This is the detection gap `01 - Overview.md`'s red-flag callout points at directly: **AnyDesk is a legitimately Authenticode-signed binary from a real, well-known vendor**, and many EDR/AV products allowlist known-good vendor signatures by default or score them at low suspicion — the entire premise behind why this tool is attractive for abuse in the first place (per CISA's Akira advisory framing of RMM tools generally). Two verified exceptions worth hunting specifically:

- **The February 2024 certificate-compromise window** (`01 - Overview.md`'s History section): AnyDesk clients in the **7.0.x through 8.0.7** version range carry the certificate that was compromised and subsequently revoked; a detection rule built around this specific combination (process name `AnyDesk.exe`, product `AnyDesk`/`AnyDesk Software GmbH`, version in that pre-8.0.8 range) is a genuine, narrowly-scoped signature distinct from anything AnyDesk's normal signing trust would otherwise flag — this pattern is published as a real detection rule (ManageEngine Log360's "AnyDesk Execution With Known Revoked Signing Certificate").
- **CVE-2024-12754** (below) — versions prior to **9.0.1** are exploitable for local information disclosure regardless of how trusted the signature is.

## CVE-2024-12754 — Session-Initiation Junction Abuse

Covered at the mechanism level in `01 - Overview.md`; the target-side artifact this leaves is specific and worth calling out on its own: at session initiation, the AnyDesk service copies the current desktop background to **`C:\Windows\Temp\<targetimagefilename>`**. Per ZDI-24-1711's own advisory, a local attacker who has planted an NTFS junction at that path can cause the service to instead read and disclose an arbitrary attacker-chosen file (with the service's own privileges) — a forensic examiner should treat an unexplained NTFS reparse point/junction under `C:\Windows\Temp\` coinciding with AnyDesk session-initiation timestamps as a strong indicator this specific technique was used, not an unrelated housekeeping artifact. **Fixed in v9.0.1** — any AnyDesk instance on a target predating that version should be treated as exploitable for this specific local information-disclosure path.

## Memory Forensics

A live AnyDesk process's memory holds the current session's authentication token (if Unattended Access is configured — `01 - Overview.md`'s "never stored, token-based" model means the plaintext password itself is not expected to be resident, but the active token is), the DeskRT-decoded screen buffer for whatever's currently displayed, and any file mid-transfer before it's flushed to disk. No public config-extraction tooling comparable to Cobalt Strike's `1768.py`/`CobaltStrikeParser` exists for this tool, since there's no equivalent embedded Malleable-style configuration block to extract — flagged as a genuine capability gap rather than an oversight in this note.

## Building a Timeline

1. Delivery/execution — portable EXE run or silent install (Sysmon 1/11, System 7045 if installed, Security 4688)
2. First connection — inbound session establishment (`connection_trace.txt`'s `Incoming` entry, `ad.trace`'s richer session-open record with the connecting `External address`)
3. Authentication method used — `User`/`Passwd`/`Token` in `connection_trace.txt`, directly telling you whether this was an interactively-approved one-off or a pre-configured Unattended Access reconnection
4. Session activity — file-transfer events (`file_transfer_trace.txt`), any CVE-2024-12754 junction artifact under `C:\Windows\Temp\`
5. Persistence check — was the install mode portable (no service, ephemeral) or installed (service-registered, survives reboot, `--start-with-win`)?
6. Cleanup — `--remove` execution (Sysmon 1) and/or trace-file deletion attempts, weighed against the fact that event logs and Sysmon telemetry already generated **survive** an uninstall

## Distinguishing Legitimate IT Use from Abuse

Because AnyDesk is frequently legitimately deployed, no single artifact above proves malicious use on its own — the same way `LOLBins/`'s living-off-the-land tools require context, not just presence. The differentiators that matter in practice: **does this specific ID/Alias, install path, and deployment method match the organization's own approved AnyDesk baseline** (an MSP-managed fleet install via GPO, per `support.anydesk.com`'s own [Windows Group Policy doc](https://support.anydesk.com/docs/windows-group-policy), looks structurally different from a silent portable-mode install dropped via a separate initial-access foothold)? CISA's own Akira-advisory guidance frames this exactly: if AnyDesk isn't part of an environment's approved tool baseline at all, block it outright (AppLocker/WDAC); if it is approved, **alert on any install occurring outside the expected deployment mechanism** — the deployment method, not the tool's mere presence, is the actual signal.
