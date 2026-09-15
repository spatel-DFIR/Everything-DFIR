# AnyDesk — Overview

> 🔴 **Red Flag Principle:** AnyDesk is a **legitimately signed, widely-deployed commercial RMM client** — its entire value to an operator is that it looks exactly like the same tool your own help desk uses. The single most durable fact for a defender: AnyDesk's **portable mode** requires no install, no admin rights, and no registry/service footprint at all, so the classic "check for installed programs" hunt structurally cannot see it. What *does* survive — even portable, even renamed — is the **network destination** (`*.net.anydesk.com`, TCP 80/443/6568) and the fact that a legitimately signed `AnyDesk.exe` PE, however renamed on disk, still carries `AnyDesk.exe` in its `OriginalFileName` field for Sysmon Event ID 1 to read. Hunt the destination and the PE metadata, not "is it installed."

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

AnyDesk is **closed-source commercial software** — same sourcing constraint as `Cobalt Strike/`: no public source tree to inspect, so history and mechanics here are verified against **AnyDesk Software GmbH's own site/support docs** and corroborated third-party security research, flagged inline wherever a detail is community-inferred rather than vendor-confirmed.

- **Founded in 2014** in Stuttgart, Germany, as **AnyDesk Software GmbH**, by Andreas Mahler, Olaf Liebe, and Philipp Weiser — verified against the company's own [leadership page](https://anydesk.com/en/leadership-team) and corroborating company-profile sources. The company states its founding goal was making remote access "fast, simple, and reliable."
- **DeskRT** is AnyDesk's own proprietary video codec, built specifically to keep the remote-screen feed usably responsive over low-bandwidth links — this performance focus (not a feature checklist) is the product's own stated differentiator from older remote-desktop tools, and directly explains why it became a common help-desk/support-tech default even before its attacker adoption.
- The company reports **1.2+ billion downloads** worldwide, with subsidiaries in the US, China, and Hong Kong. Scale like this is precisely why an unexpected AnyDesk install rarely triggers reflexive suspicion the way an unfamiliar C2 tool would — it is legitimately present in a huge share of enterprise environments already.
- **February 2, 2024 — AnyDesk publicly confirmed a compromise of its own production systems.** Per the company's statement and corroborating reporting (BleepingComputer, Akamai, Cybereason), the incident led AnyDesk to **revoke all security-related certificates, including its code-signing certificate, and reset all web-portal passwords** as a precaution. Reporting at the time (not fully confirmed by AnyDesk itself) suggested source code and the private code-signing key may have been accessed; threat actors were separately observed advertising ~18,000 AnyDesk credentials for sale and using a compromised-adjacent signing certificate to sign malware samples (Agent Tesla) so they'd pass as legitimate. AnyDesk shipped fixed clients (**7.0.15+ / 8.0.8+**) with a new certificate. This is directly relevant to `04 - Target Evidence.md` and `05 - Detection and Hunting.md`: a hunt for AnyDesk clients still running the old, now-revoked certificate serial is a real, verifiable detection opportunity distinct from anything the tool's normal operation would flag.
- **CVE-2024-12754 / ZDI-24-1711** (disclosed by researcher Naor Hodorov, CVSS 5.5) — a **local information-disclosure vulnerability**, fixed in **v9.0.1**, covered in depth in `04 - Target Evidence.md` since it directly affects what a session can expose on a target host.
- **MITRE ATT&CK** does not track AnyDesk as its own numbered Software entry (unlike Cobalt Strike's S0154) — it's cited as a **procedure example** under [T1219.002 "Remote Access Software: Remote Desktop Software"](https://attack.mitre.org/techniques/T1219/002/), alongside VNC, TeamViewer, ScreenConnect, and LogMeIn, and appears by name in multiple Group/Campaign entries, including **G1052 (Contagious Interview / DPRK)**, **G1015 (Scattered Spider)**, **G1046 (Storm-1811)**, and **G1053 (Storm-0501)** — the Contagious Interview link is directly relevant to this repo's `macOS/17 - Threat Landscape and Playbooks/DPRK Fake-Job and Contagious Interview Playbook.md`, which already documents AnyDesk as the hands-on-keyboard tool InvisibleFerret drops on macOS victims; cross-linked rather than re-derived.
- AnyDesk's own distribution and abuse profile diverge sharply by intent: legitimately, it is sold/downloaded directly for IT support, MSP fleet management, and personal remote access; illegitimately, it is the **specific RMM tool named in CISA's #StopRansomware Akira advisory** ([AA24-109A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a)) and in CISA's earlier joint advisory on [malicious RMM software abuse](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a) (AA23-025A) — both cited throughout `02 - Hands-On Use Cases.md`.

## How It Works

### Architecture — client, ID/Alias addressing, and relay infrastructure

Unlike Cobalt Strike's Team-Server model or a classic C2 framework, AnyDesk has **no operator-controlled server component at all** — every party is running the same off-the-shelf client, and the vendor's own relay infrastructure brokers the connection between them. Verified against AnyDesk's own [firewall/network requirements doc](https://support.anydesk.com/docs/firewall) and [ID/Alias doc](https://support.anydesk.com/docs/anydesk-id-and-alias):

```
[ Client A (operator) ]                                    [ Client B (target) ]
   AnyDesk ID: 123 456 789                                   AnyDesk ID: 987 654 321
        │                                                            │
        │  1. Both clients register with AnyDesk's own              │
        │     relay infrastructure (*.net.anydesk.com)              │
        ▼                                                            ▼
              [ AnyDesk relay/rendezvous infrastructure ]
                     (vendor-operated, not operator-controlled)
        │                                                            │
        │  2. Operator enters Client B's ID/Alias in                │
        │     "Remote Desk" — relay brokers the handshake            │
        ▼                                                            ▼
        └───── 3. "Allow direct connections" (default, on) ──────────┘
                 tries a direct peer-to-peer path first;
                 falls back to routing session data through
                 the relay itself if direct connectivity fails
                 (NAT/firewall) — an operator-toggleable setting,
                 not a fixed architecture
```

- **AnyDesk ID** — a unique 9- or 10-digit number automatically assigned to every AnyDesk installation/instance, the primary address used to initiate a session. Verified against the [official ID/Alias doc](https://support.anydesk.com/docs/anydesk-id-and-alias): the ID **persists with the device by default even after uninstall** unless explicitly reset, and an **Alias** (`username@namespace`, e.g. `john@ad`) can be set as a human-readable substitute — but Alias assignment is one of the features the [portable-mode doc](https://support.anydesk.com/docs/portable-vs-installed) explicitly states is **not supported** in portable mode.
- **Relay vs. direct connection** — AnyDesk's own documented **"Allow direct connections"** setting is enabled by default; disabling it forces every session through AnyDesk's relay servers instead of attempting a peer-to-peer path. The practical forensic implication: even a "direct" session still depends on the relay for the initial ID-to-ID rendezvous/handshake, so `*.net.anydesk.com` traffic is expected at connection setup regardless of whether bulk session data ends up relayed or direct.
- **Network ports** (verified against the [official firewall doc](https://support.anydesk.com/docs/firewall)): **TCP 80, 443, and 6568** — only one needs to be open for a connection to succeed, and the client tries them in that fallback order. A separate **UDP 50001–50003** range (multicast `239.255.102.18`) powers the **Discovery** feature, which finds other AnyDesk instances on the *same local network segment only* — this is LAN-scoped and unrelated to the internet-facing relay path.
- **Portable vs. installed mode** — this is the single most consequential mechanical fact in this note, verified against AnyDesk's own [portable-vs-installed doc](https://support.anydesk.com/docs/portable-vs-installed):

| | Portable mode | Installed mode |
|---|---|---|
| Admin privileges to run | Not required | Required only to manually stop/restart the service from the tray |
| Filesystem/registry footprint | Runs as a standalone single-file app; no installer, no service registration | Registers a Windows service, writes to `Program Files`/`ProgramData`, creates registry entries |
| Autostart with OS | No — manual launch only | Yes — starts automatically and **persists across reboots and user sessions** |
| Unattended Access | Available **only while the app window is manually open** | **Always available**, brokered by the always-running service |
| Alias / Remote Restart | **Not supported** | Supported |
| Session behavior on window close | **Closes automatically and ends all active sessions** | Sessions persist independent of any open window |

This table is the mechanical basis for the "portable mode leaves no installed-program trace" red flag above, and for CISA's own characterization (per its Akira advisory) that AnyDesk Portable is attractive specifically because it "requires no installation, runs from user-writable directories, and blends into administrative activity."

### Unattended Access — password model and its real weak point

Verified against AnyDesk's own [Unattended Access doc](https://support.anydesk.com/docs/unattended-access): setting a password (`Settings > Access > Unattended Access`, minimum 8 characters, 12+ recommended) enables hands-free reconnection without a human on the other end approving each session. AnyDesk's documentation states plainly that **"Passwords are never stored"** — instead, a device-specific **one-time token** is issued to the connecting client after a successful authentication and reused for subsequent silent logins; changing the password invalidates every issued token.

The real, **verified** weak point isn't the password-storage model itself — it's **CVE-2024-12754 / ZDI-24-1711** (fixed in v9.0.1): when a new session initiates, the AnyDesk service copies the current desktop's background image to `C:\Windows\Temp\<targetimagefilename>` as part of session setup. A local, already-low-privileged attacker can plant an **NTFS junction** at that expected path pointing at an arbitrary file, and the service follows the junction and reads the attacker-chosen file with its own elevated privileges — per ZDI's own advisory, this can disclose "stored credentials, configuration files, or other protected data," turning a local foothold into a privilege-escalation/lateral-movement stepping stone via a mechanism most write-ups of AnyDesk's password model don't mention at all. Attack requires local code execution already, so it's a post-compromise escalation primitive, not an initial-access one.

### File transfer

A first-class feature of an established session, not a bolted-on afterthought — drag-and-drop through a built-in File Manager pane, or synced clipboard copy/paste, with **no documented file-size limit**. Because it rides the same authenticated session channel as interactive control, a file pulled off (or pushed onto) a target this way generates the **same trace-file footprint** as any other session activity (`04 - Target Evidence.md`) rather than a separately-flagged "transfer" event — this is exactly the mechanic Mad Liberator ransomware operators are documented abusing for data exfiltration (`02 - Hands-On Use Cases.md`).

### Command-line interface

AnyDesk ships a genuine, documented CLI for Windows (also Linux/macOS variants exist but are out of scope here) — verified against the [official Windows CLI reference](https://support.anydesk.com/docs/command-line-interface-for-windows). This is what turns AnyDesk from "a GUI remote-desktop app" into something scriptable for silent, unattended, fleet-wide deployment — see the table below and every install/connect command in `02 - Hands-On Use Cases.md`.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Session/control channel | AnyDesk's own proprietary protocol carrying DeskRT-encoded screen data, input events, file-transfer, and chat over a TLS 1.2 (AEAD) session |
| Relay/rendezvous | Vendor-operated relay infrastructure at `*.net.anydesk.com`, TCP 80/443/6568 (fallback order), brokering ID-to-ID connection setup regardless of whether the resulting session goes direct or stays relayed |
| Local discovery | UDP 50001–50003, multicast `239.255.102.18` — LAN-segment-scoped only |
| Persistence (installed mode) | Windows service registration, autostart, survives reboot |
| Credential/session model | Password-gated Unattended Access using device-bound one-time tokens rather than stored passwords (documented); CVE-2024-12754 as a verified local information-disclosure bypass of that model |
| Code-signing trust | Authenticode-signed binary — the trust surface directly implicated by the Feb 2024 certificate-compromise incident |

## Command-Line Switches — Quick Reference

Verified against the [official Windows CLI documentation](https://support.anydesk.com/docs/command-line-interface-for-windows). Covers the switches that matter for reading or writing a real deployment/connection command line, not an exhaustive reproduction of AnyDesk's own help output.

| Switch | Plain-English meaning |
|---|---|
| `--install <path>` | Installs AnyDesk to the given directory (registers the service, writes registry/filesystem artifacts) |
| `--start-with-win` | Configures the installed client to launch automatically with Windows |
| `--create-shortcuts` / `--create-desktop-icon` | Adds a Start Menu / desktop shortcut during install |
| `--silent` | Runs installation with no UI and no prompts — the scripted-deployment flag |
| `--remove-first` | Uninstalls any existing AnyDesk version before installing a new one |
| `--update-auto` / `--update-manually` / `--update-disabled` | Sets the client's update policy at install time |
| `--uninstall` | Uninstalls AnyDesk with a graphical confirmation prompt |
| `--remove` | Uninstalls AnyDesk **silently**, no prompt — the scripted-cleanup counterpart to `--silent` install |
| `--start` / `--stop-service` / `--restart-service` | Starts, stops, or restarts the AnyDesk background service |
| `--set-password` | Sets the Unattended Access password (value piped via `echo`, not passed as a bare argument — keeps it off a naive process-list grep, though not off full command-line/Sysmon-1 capture of the whole invocation) |
| `--remove-password` | Clears the configured Unattended Access password |
| `--get-id` | Prints this instance's AnyDesk ID (capture via a wrapping script) |
| `--get-alias` | Prints this instance's configured Alias, if any |
| `--get-status` | Prints the client's current online/offline status |
| `--version` | Prints the installed AnyDesk version |
| `AnyDesk.exe <ID\|Alias>` | Initiates an outbound session to the given AnyDesk ID or Alias — the core scripted-connection syntax |
| `--with-password` | Supplies the Unattended Access password for an automated connection (also piped via `echo`, same command-line-visibility caveat as `--set-password`) |
| `--file-transfer` | Starts the session directly in File Transfer mode rather than interactive remote-control mode |
| `--full-screen` / `--plain` | Cosmetic session-window options (fullscreen, or a borderless/menu-less window) |

## Quick Use-Case List

- Portable/no-install execution to avoid leaving an installed-program trace on the target
- Silent, scripted install (`--install --silent --start-with-win`) for persistent, hands-free re-entry
- Configuring Unattended Access with a preset password for return access without a human approving each session
- Renaming the AnyDesk binary/shortcut to something innocuous to blend into a process list at a glance
- Abusing the built-in file-transfer feature for data exfiltration once a session is established
- Social-engineering delivery — impersonating tech support (Microsoft/Apple/bank/antivirus) to talk a victim into installing AnyDesk themselves, per FBI/CISA consumer-fraud alerts on refund/tech-support scams
- Password-reuse/credential-stuffing against an Unattended Access password on an *already-installed*, legitimate enterprise AnyDesk deployment, rather than deploying a new instance
- Disabling or uninstalling security tooling once interactive remote-hands access is established
- Fleet-wide deployment across multiple already-compromised hosts as a redundant/backup access channel alongside a primary C2 implant
- Silently uninstalling AnyDesk (`--remove`) after use to reduce the installed-program footprint post-engagement
- Chained workflow: using an established AnyDesk session's file-transfer feature to deliver a separate C2 payload onto the target
- The ironic defender's-side observation that AnyDesk's own verbose trace logs (`04 - Target Evidence.md`) can end up recording the operator's entire session history on the very host they compromised

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Target reachability | At least one of TCP 80/443/6568 outbound reachable from the target to `*.net.anydesk.com` — nothing else needed; no inbound port ever has to be opened on the target |
| Local execution | Portable mode needs no privilege at all to run; installed mode's initial install typically needs local admin (silent install can still be scripted through an already-privileged foothold) |
| Target-side acceptance (interactive session) | Without Unattended Access configured, a session requires a human on the target to click "Accept" — this is why the social-engineering/tech-support-scam vector exists as a distinct use case |
| Unattended Access | Requires the password to already be set on the target (either by the attacker post-compromise, or reused/guessed against a pre-existing legitimate deployment) |
| Attacker-side | Nothing beyond the same off-the-shelf AnyDesk client and the target's ID/Alias — no infrastructure to stand up, unlike a C2 framework's Team Server |
