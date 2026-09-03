# Metasploit — Auxiliary Modules — Target Evidence

Evidence left on the **target/destination** host or network. Unlike `exploit/*`, where one worked example (EternalBlue) can carry most of the page, `auxiliary/*` genuinely has **no single evidence shape** — a port scanner, a credential-validation scanner, an authenticated database-config auditor, a search-engine OSINT harvester, a SYN flood, a protocol fuzzer, and an ARP poisoner leave almost nothing in common on the target side. This page is organized **by sub-category** rather than by artifact type for exactly that reason (per this module's documented latitude to structure Target Evidence/Detection however best fits the tool — see `../PLANNING.md` §9 R12).

## Contents
- [Why Target Evidence Shape Varies by Category](#why-target-evidence-shape-varies-by-category)
- [Scanner-Class — Service and Port Discovery](#scanner-class--service-and-port-discovery)
- [Scanner-Class — Credential Validation](#scanner-class--credential-validation)
- [Admin-Class — Authenticated Enumeration](#admin-class--authenticated-enumeration)
- [Gather-Class — OSINT / External Collection](#gather-class--osint--external-collection)
- [DoS-Class — Connection/Resource Exhaustion](#dos-class--connectionresource-exhaustion)
- [Fuzzer-Class — Malformed-Input Crash Artifacts](#fuzzer-class--malformed-input-crash-artifacts)
- [Spoof-Class — ARP Cache Poisoning](#spoof-class--arp-cache-poisoning)
- [Network-Layer Evidence Across Every Category](#network-layer-evidence-across-every-category)
- [Endpoint Security Product Signatures](#endpoint-security-product-signatures)
- [Building a Timeline](#building-a-timeline)

---

## Why Target Evidence Shape Varies by Category

The one organizing question that actually predicts what a given auxiliary module leaves behind: **does it authenticate, does it crash something, or does it never touch the target at all?** Pure discovery/scanning leaves connection-level noise but rarely a host-level log entry; credential validation leaves an authentication-log trail proportional to `THREADS`/wordlist size; authenticated `admin/*` modules leave whatever the target application itself audits; `gather/*`'s external-OSINT modules leave **nothing** on the target's own infrastructure; and `dos/*`/`fuzzers/*` leave the same crash/instability signature class already documented for low-ranked exploits in `../Exploit Modules/04 - Target Evidence.md` — this page cross-links there rather than re-deriving it.

## Scanner-Class — Service and Port Discovery

Covers `scanner/portscan/tcp`, `scanner/smb/smb_version`, and similar unauthenticated fingerprinting modules.

| Artifact | Detail |
|---|---|
| Windows Event Log | **Essentially nothing, by default.** A full TCP connect scan (`scanner/portscan/tcp`) and an SMB dialect negotiation (`smb_version`) are not authentication events — neither generates a Security-log entry on a stock Windows host. `smb_version`'s SMBv1 native-OS-string read *can* ride on a null/anonymous SMB session, which — same as EternalBlue's pre-exploitation step in `../Exploit Modules/04 - Target Evidence.md` — may surface as Security 4624 (Logon Type 3, `ANONYMOUS LOGON`) if null sessions are permitted and audited |
| Host firewall logs | Windows Defender Firewall logging (`pfirewall.log`, not on by default) or a Linux host firewall's connection log is the most likely **host-level** trace of a port sweep — a rapid sequence of connection attempts across many ports from one source IP in a short window |
| Application/service logs | An SMB service that logs dialect-negotiation attempts (verbose SMB server auditing, not a default configuration) would show the negotiate/session-setup sequence `smb_version` performs |
| Network-layer | By far the strongest signal for this category — see [Network-Layer Evidence](#network-layer-evidence-across-every-category) below |

**The `scanner/portscan/tcp` full-connect signature** is itself distinctive: unlike a SYN-only scanner, a full TCP connect (`connect()`, not a raw crafted SYN) completes the three-way handshake, then closes — this is *more* visible at the OS/socket-accounting level on the target than a stealth SYN scan would be, because the target's TCP stack has to fully establish and then tear down each connection, which is exactly the tradeoff `portscan/tcp`'s own description accepts in exchange for not needing raw-socket privileges (`02 - Hands-On Use Cases.md`).

## Scanner-Class — Credential Validation

Covers `scanner/smb/smb_login`, `scanner/ssh/ssh_login`, and equivalent login-scanner modules — this is the category the 🔴 red-flag callout in `01 - Overview.md` is written about.

| Log | Event ID | Signal |
|---|---|---|
| Security (Windows, SMB target) | **4625** (An account failed to log on) | One per failed credential attempt — at `THREADS 20`+ against a wordlist, this is a **burst** of 4625 events from one source IP, not an isolated failure |
| Security (Windows, SMB target) | **4624** (Logon Type 3) | The one successful login, if any — Logon Type **3** (network) is the expected type for `smb_login`; a `CreateSession`-opened session (`02 - Hands-On Use Cases.md`) rides on this same successful logon |
| Security (Windows, domain-joined target/DC) | **4740** (A user account was locked out) | Fires if the wordlist/spray exceeds the domain's lockout threshold against a given account — the exact condition `smb_login`'s `ABORT_ON_LOCKOUT` option is designed to avoid triggering repeatedly once seen |
| Security (Windows, DC) | **4776** (The domain controller attempted to validate credentials for an account) | NTLM-specific credential-validation record at the DC, independent of which specific member server was targeted — valuable when the spray hit multiple hosts but authenticated against one DC |
| `auth.log` / `sshd` journal (Linux, SSH target) | N/A (text log, not numbered) | `Failed password for <user> from <ip> port <port> ssh2`, repeated at wordlist-and-host volume for `ssh_login`; a matching `Accepted password for <user>` line marks the one success |

**The single highest-value target-side signal for this entire sub-category is volume and timing, not any one event.** A handful of 4625 events against one account over a day is routine password-typo noise; dozens-to-hundreds of 4625 events against **many different accounts from one source IP within a short window** is what a `THREADS`-driven spray actually produces, and it is one of the most reliably detectable patterns in this entire module — see the Hunting Priority table in `05 - Detection and Hunting.md`.

## Admin-Class — Authenticated Enumeration

Covers `admin/mssql/mssql_enum` and equivalent authenticated configuration/data-auditing modules.

| Artifact | Detail |
|---|---|
| SQL Server error log / Application Event Log | If SQL Server login auditing is enabled (`Both failed and successful logins`, not the default `Failed logins only`), each connection `mssql_enum` opens generates a login-audit entry in the Windows Application log, commonly cited under Source `MSSQLSERVER` — a successful audited login and a failed one are logged as distinct, well-documented event patterns in Microsoft's own SQL Server documentation |
| SQL Server default trace / Extended Events | The specific queries `mssql_enum` runs are distinctive and verifiable directly against its source: `select loginname from master.sys.syslogins`, `select name from master.sys.syslogins where sysadmin = 1`, `EXEC master..xp_regread` against the service's registry `ObjectName` key, and a systematic walk of `sys.configurations`/`sp_configure` covering `xp_cmdshell`, `Ole Automation Procedures`, `Database Mail XPs`, and C2 Audit Mode. Any SQL auditing solution capturing query text (Extended Events, a third-party DAM product, or the legacy SQL Trace) will show this exact, recognizable query sequence run back-to-back in a single connection |
| Network-layer (TDS protocol) | The queries above travel over TDS (TCP 1433 by default) in cleartext unless TLS is enforced — a packet capture showing this query sequence is directly readable |

This is the `admin/*` parallel to the crash-vs-no-crash framing in `../Exploit Modules/04 - Target Evidence.md`: **`mssql_enum` doesn't exploit anything** — every action it takes is a normal, authenticated SQL query a legitimate DBA tool could also run. The evidentiary weight here is entirely in the *sequence and volume* of specific dangerous-configuration queries run together in one session, not in any single query looking inherently malicious.

## Gather-Class — OSINT / External Collection

> 🔴 **The important negative-evidence case for this entire module class.** `gather/search_email_collector` and similar external-OSINT modules query public search engines, not the target organization's own infrastructure — **there is no target-side artifact to find, by design.** A DFIR engagement scoped only to the target's own logs/network will never see this activity; the only place it's visible at all is the operator's own egress (`03 - Source Evidence.md`) or, in principle, the search engine provider's own request logs (not accessible to the target organization). Don't spend hunt effort here — document the gap instead.

Not every `gather/*` module fits this description — some (e.g. an authenticated `gather/*` module pulling data from a session or an internal service) behave like the Admin-Class section above instead. The distinguishing question is the same one from the framing section: does this specific module ever send a packet to the target's own network at all.

## DoS-Class — Connection/Resource Exhaustion

Covers `dos/tcp/synflood` and equivalent flooding modules.

| Artifact | Detail |
|---|---|
| `netstat`/connection-table state | A flood of half-open connections in **`SYN_RECV`** state against the flooded port — visible live via `netstat -n` or `ss -tn state syn-recv` on the target for as long as the flood continues |
| Windows System Event Log | Legacy Windows versions logged **Event ID 4226** (Tcpip: "TCP/IP has reached the security limit for half-open connections") when the SYN-flood protection threshold was hit — this event ID was **removed in later Windows releases**; don't assume its presence or absence proves anything about a modern target without first confirming the OS build still emits it |
| Service/application availability | The practical target-side signal for most modern hosts: the flooded service becomes slow or unreachable for legitimate traffic while the flood is active, then recovers immediately once it stops — a transient, timing-correlated outage rather than a persistent artifact |
| Packet capture — the strongest signal here | `synflood`'s own verified behavior (`02 - Hands-On Use Cases.md`) randomizes **source IP** (unless `SHOST` is pinned), **source port**, **IP TTL** (128–255), and **TCP window size** (1–4096) on every packet — a capture showing a high-volume burst of SYN packets to one port with wildly inconsistent TTL/window values and no completing three-way handshakes is close to a fingerprint match for this specific module's packet-crafting logic, not just "a SYN flood happened" |
| IDS/IPS | Any network sensor with flood/DoS signatures (Suricata's `ET DOS` rule category, a firewall's built-in SYN-flood protection) is very likely to alert on this — SYN floods are one of the oldest, best-signatured attack patterns in any commercial security product |

## Fuzzer-Class — Malformed-Input Crash Artifacts

Covers `fuzzers/ftp/ftp_pre_post` and equivalent protocol fuzzers.

| Artifact | Detail |
|---|---|
| Application/service log (e.g. FTP server log) | The malformed-input strings themselves are distinctive and source-verified — `ftp_pre_post` sends both cyclic long strings and a fixed evil-character set (`%s`, `%n`, `%x`, `../`, null-byte sequences, format-string tokens) against a fixed FTP command list (`USER`, `RETR`, `STOR`, `SITE`, `MKD`, etc.). A service log showing FTP commands with format-string tokens or path-traversal sequences as arguments is a strong, directly-matchable signature |
| Crash/restart evidence | If a fuzz input actually triggers the target bug, the resulting crash/restart artifacts are the same class covered in depth in `../Exploit Modules/04 - Target Evidence.md`'s Crash and Stability Artifacts section (WER reports, minidumps, System 1001/41) — this page doesn't re-derive that, only notes that a fuzzer's entire purpose is to reach that state deliberately, same as a low-ranked exploit reaches it accidentally |
| Connection pattern | A single source IP opening an unusually high number of sequential connections to one service, each short-lived, over an extended window — distinct in shape from both a broad scanner sweep (many hosts, few connections each) and a login spray (many attempts, but authenticating, not sending malformed protocol data) |

## Spoof-Class — ARP Cache Poisoning

Covers `spoof/arp/arp_poisoning`.

| Artifact | Detail |
|---|---|
| ARP cache / table anomalies | The core observable: a legitimate IP (commonly the default gateway) suddenly resolving to the operator's MAC address in the ARP tables of hosts on the segment — `arp -a` on any affected host, or `show mac address-table` / ARP table dumps on switches, will show the same IP mapped to an unexpected MAC, and that mapping **flip-flopping** if the poisoning is intermittent |
| Switch-side logging | Managed switches with Dynamic ARP Inspection (DAI) or port-security enabled will log and can block gratuitous/forged ARP replies outright — the presence of DAI-violation log entries is a direct, switch-side record of the attempt regardless of whether any host was actually successfully poisoned |
| Network-layer capture | A burst of gratuitous/unsolicited ARP replies claiming the gateway's IP, sourced from a MAC not previously associated with it — visible in any packet capture or a network sensor's ARP-specific log (e.g. Zeek's `arp.log`, if the sensor is positioned on that broadcast segment — ARP doesn't route, so this is strictly local-segment visibility only) |
| Downstream effect | Once poisoning succeeds, whatever traffic gets rerouted through the operator's host becomes visible to it — the actual MITM payoff. That downstream traffic (credentials, session tokens) leaves its own separate evidentiary trail wherever it's ultimately captured/relayed — cross-link `../../Responder/04 - Target Evidence.md` for the closest already-documented sibling technique (LLMNR/NBT-NS poisoning) and how its captured-traffic evidence is typically handled |

## Network-Layer Evidence Across Every Category

| Source | What It Shows |
|---|---|
| Zeek `conn.log` / NetFlow | Every category in this page leaves *some* connection-level trace here even when nothing else does — a scanner's broad-and-shallow fan-out, a spray's repeated-connect-to-many-hosts pattern, a flood's high-volume single-destination burst, and a fuzzer's long single-target session all have distinguishable shapes purely from flow metadata, no payload visibility required |
| Zeek `notice.log` | Zeek's built-in `Scan::Address_Scan`/`Scan::Port_Scan` detection framework is tuned to catch exactly the `portscan/tcp`/`smb_version` sweep pattern out of the box in most deployments |
| Full packet capture | Required to see payload-level detail — the `smb_login`/`ssh_login` credential material itself (if unencrypted at the protocol layer, which SMB/SSH generally are not post-negotiation, but pre-auth negotiation detail still is), the `mssql_enum` query text (cleartext TDS unless TLS-enforced), the fuzzer's evil-character payloads, and the synflood's randomized TTL/window fingerprint all require this level of visibility |

## Endpoint Security Product Signatures

Modern EDR/AV products commonly carry generic **brute-force/spray detection** (repeated failed auth from one source across many accounts/hosts in a short window) independent of the specific tool generating it — `smb_login`/`ssh_login` traffic looks, at the protocol level, identical to `../../Hydra/` or `../../NetExec/` doing the same thing, so a product tuned to catch one should catch all three. Port-scan detection is similarly tool-agnostic. **DoS and ARP-spoofing modules are the two categories most likely to trigger a purpose-built signature** rather than a behavioral one — SYN-flood protection and DAI/ARP-inspection are mature, widely-deployed mitigations specifically because these are old, well-understood attack classes, not novel Metasploit behavior.

## Building a Timeline

Because this page spans six structurally different sub-categories, there's no single anchor sequence the way `../Exploit Modules/04 - Target Evidence.md` has one for EternalBlue. The anchor **pattern**, adapted per category:

- **Scanner/credential-validation:** [network-layer connection burst] → [Security 4625 burst, one per failed attempt] → [Security 4624, the one success, if any] → [Security 4740 if lockout threshold crossed] — tightest correlation is matching the *count and timing* of 4625 events against the operator-side `THREADS`/wordlist-size claim in `03 - Source Evidence.md`.
- **Admin-class:** [TDS/protocol connection] → [SQL audit login event, if enabled] → [the distinctive dangerous-config query sequence, if query auditing is enabled] — correlate against the operator-side credential material recovered separately (often from an earlier `smb_login`/`ssh_login` run in the same engagement).
- **DoS:** [flood packet burst begins, in a capture] → [connection-table exhaustion / service unavailability, live-observed or reported by monitoring] → [flood ends] → [service recovers] — a short, sharp, self-resolving outage window is the anchor, cross-referenced against any pentest-window documentation the same way an unexpected exploit crash is handled in `../Exploit Modules/04 - Target Evidence.md`.
- **Fuzzer:** [long single-target connection session with malformed commands] → [crash/restart artifacts, if the fuzz input succeeded] — same crash-timeline logic as the exploit-module page, cross-linked above.
- **Spoof:** [gratuitous ARP burst / DAI violation log] → [ARP-table anomaly persists as long as poisoning continues] → [downstream MITM'd traffic, wherever it's captured] — the ARP anomaly itself is the tightest anchor; everything downstream is a separate evidentiary chain.
- **Gather (external OSINT):** no target-side timeline exists to build — see the negative-evidence callout above.
