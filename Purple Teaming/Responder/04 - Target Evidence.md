# Responder — Target Evidence

Evidence left on the **victim** host and the network it sits on. This is the deep end of the note — unlike a single-host lateral-movement tool, Responder's victim-side footprint is spread across every host that ever queried a name it poisoned, which is often dozens of machines from one attacker session. Critically, **Windows has no native, always-on event log specifically for LLMNR/NBT-NS/mDNS query-and-reply activity** — the strongest target-side signal is the victim's own resulting *authentication attempt*, not the poisoned name resolution itself.

## Contents
- [Windows Event Logs — Authentication](#windows-event-logs--authentication)
- [DNS Client Operational Log (Non-Default)](#dns-client-operational-log-non-default)
- [Sysmon](#sysmon-if-deployed)
- [WPAD-Specific Artifacts](#wpad-specific-artifacts)
- [Endpoint Security Product Detections](#endpoint-security-product-detections)
- [Network-Layer Evidence](#network-layer-evidence)
- [Building a Timeline](#building-a-timeline)

---

## Windows Event Logs — Authentication

The name-resolution poisoning itself is invisible to standard Windows auditing; what's logged is the **consequence** — the victim authenticating (or attempting to) against the attacker's rogue server.

| Log | Event ID | Signal |
|---|---|---|
| Security | **4624** (Logon Type 3) | Only logged **on the victim** if the rogue server happens to accept the auth and complete a session — Responder's servers typically don't, they capture and then fail/redirect, so 4624 is the **less common** case here |
| Security | **4625** (Logon failure) | **The more common outcome** — Responder captures the NTLM material and returns a failure, so victims frequently show a *failed* logon attempt with no legitimate corresponding service. Filter `AuthenticationPackageName = NTLM` — an unexpected NTLM (rather than Kerberos) authentication attempt against an unfamiliar destination is the core signal |
| Security | 4648 (Explicit credential logon) | If the victim's own request supplied explicit alternate credentials (e.g. `net use \\FILESERVER\share /user:...`) rather than the current session's token |
| Application/System | (varies by app) | Applications that themselves attempt SMB/HTTP/LDAP connections and fail against the rogue server often log their own connection-failure events — these are highly application-specific and not enumerated here |

Cross-reference `AuthenticationPackageName`, logon type, and source/target host mechanics in `Windows/05 - Users, Groups & Authentication.md` — this note deliberately doesn't re-derive that table, only the tool-specific pattern layered on top of it.

## DNS Client Operational Log (Non-Default)

The `Microsoft-Windows-DNS-Client/Operational` ETW channel can show DNS resolution activity including query attempts that preceded an LLMNR/NBT-NS fallback — but **this channel is not enabled by default** and must be turned on explicitly (`wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true`). Where it's enabled, it's a config-dependent supplementary source, not a reliable primary detection — don't assume it's present on a typical unhardened endpoint, and verify the specific event IDs present against the actual OS build in your environment rather than trusting a fixed ID list, since this channel's exact schema has shifted across Windows versions.

## Sysmon (if deployed)

| Event ID | Signal |
|---|---|
| 3 (Network Connect) | The victim process (often `svchost.exe` hosting the workstation service, or the specific application that triggered the lookup) making an outbound connection to the attacker's IP on 445/80/443/389/1433/etc. — this is generally the **strongest Sysmon-side signal**, since it doesn't depend on any LLMNR-specific parsing at all, just an unexpected destination |
| 1 (Process Create) | Whatever application triggered the original failed name lookup — a mistyped `net use`, a browser doing WPAD discovery, an application probing for infrastructure |
| 22 (DNS Query) | Captures the **preceding standard DNS query that failed** (if the app went through the normal resolver first) — useful context, but Sysmon's DNS query logging does not itself capture LLMNR/NBT-NS/mDNS broadcast traffic, which bypasses the standard DNS Client service resolver path Sysmon 22 instruments |

## WPAD-Specific Artifacts

| Artifact | Detail |
|---|---|
| Browser proxy settings | A victim that received a poisoned PAC file may show an unexpected/unfamiliar auto-config URL in `netsh winhttp show proxy` or the browser's own proxy settings, if the setting persisted past the session |
| Registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\AutoConfigURL` — populated transiently during a poisoned WPAD session; rarely persists after the session ends since it's typically re-negotiated per network, but worth checking on a live-response triage |
| Certificate warnings | If `HTTPS`/`LDAPS` rogue servers were used, the victim's browser/OS may have generated a certificate-warning event or user-facing prompt for Responder's self-signed cert — check browser history/security-warning logs for the relevant timeframe |

## Endpoint Security Product Detections

Most mainstream EDR/AV products with network-behavior detection carry **heuristic signatures for LLMNR/NBT-NS poisoning response patterns** specifically (a host answering broadcast name-resolution queries it has no authority over), independent of Responder's specific implementation — this is a protocol-level detection, not a Responder-binary signature, so it applies equally to any tool implementing the same poisoning pattern. Windows Defender for Endpoint and comparable products commonly flag this as a distinct "network poisoning" or "AiTM" alert category. The absence of such an alert on a segment with modern endpoint coverage is itself worth investigating (product not deployed on that segment, detection disabled, or the endpoint doing the poisoning itself lacks agent coverage — e.g. a rogue device rather than a compromised managed host).

## Network-Layer Evidence

| Source | What It Shows |
|---|---|
| Raw packet capture on UDP 5355 (LLMNR), UDP 137 (NBT-NS), UDP 5353 (mDNS) | The most direct evidence of the poisoning itself — a query for a name followed by **two replies from two different source IPs** (the real, nonexistent-name failure plus the attacker's forged answer) is the ground-truth fingerprint. **Note:** Zeek does not ship a native LLMNR/NBT-NS/mDNS protocol analyzer as of the current stable releases — there is no built-in `llmnr.log`; capturing this traffic requires either a raw `tcpdump`/`pcap` filter on those ports or a custom/community Zeek script, not an out-of-the-box log file |
| Zeek `dns.log` | Captures standard DNS queries only — useful for confirming the *preceding* failed lookup that triggered the LLMNR/NBT-NS fallback, but does not itself record the broadcast poisoning traffic (see caveat above) |
| Zeek `conn.log` / `notice.log` | Shows the resulting connection from victim to attacker IP on the rogue server's port even without protocol-specific LLMNR parsing — a `notice.log` entry for an unexpected internal-to-internal connection pattern, or a `conn.log` filter for many distinct source IPs connecting to one internal IP on 445/389/1433 in a short window, is a practical Zeek-native substitute |
| NetFlow / switch logs | A single internal host receiving inbound connections from many other internal hosts on ports it has no legitimate reason to serve (445, 389, 1433, etc.) in a short window is a strong fleet-wide indicator, especially valuable in segments without endpoint logging at all |
| DHCP server logs (for `-d`/`-D`/`--dhcpv6` variants) | The legitimate DHCP server's own logs may show a **race condition** — two DHCPACK-equivalent responses for the same client transaction in quick succession, or clients receiving option 252 (WPAD) / a DNS server value the real DHCP scope doesn't configure |

## Building a Timeline

Because there's no single victim-side "poisoning occurred" event, timeline-building here is inherently a **correlation exercise** rather than a single-log pull: match a Security 4625 (NTLM auth failure, unfamiliar destination) or Sysmon 3 (unexpected outbound connection) on the victim against the source-side `Poisoners-Session.log` entry for that same victim IP and timestamp (see `03 - Source Evidence.md`). The tightest anchor available: **[preceding failed standard DNS/application lookup] → [victim outbound connection to attacker IP, Sysmon 3] → [NTLM authentication attempt, Security 4625 or 4624] → [source-side Poisoners-Session.log entry for the same IP/time]**. A wide time gap between the victim's connection attempt and the source-side log entry suggests either clock skew between hosts (normalize both to a common reference before concluding causality) or two unrelated events that happen to share a victim IP.
