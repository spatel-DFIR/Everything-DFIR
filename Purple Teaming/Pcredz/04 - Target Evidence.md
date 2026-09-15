# Pcredz — Target Evidence

**This file is deliberately thin, and that's itself the finding.** Per `01 - Overview.md`'s red-flag principle, Pcredz never sends a packet — it only reads what already arrives at its capture point. There is consequently **no "victim host" in the traditional sense** the way there is for `Impacket/psexec/` or `Responder/`: Pcredz-the-tool leaves no event log entry, no registry key, no filesystem artifact, and no authentication attempt on any remote machine, because it never talks to one. What *does* exist on the "target" side splits into two genuinely different categories, and conflating them is the most common mistake in reading this section:

1. **The traffic-redirection mechanism** (if any) that got the victim's traffic to Pcredz's capture point in the first place — this evidence belongs to *that* tool/technique, not Pcredz, and is documented on its own page.
2. **The network infrastructure** the capture point itself depends on (a SPAN/mirror port, a tap, a compromised switch) — genuine evidence, but it lives in switch/network-device logs, not on any single endpoint.

## Contents
- [If Chained with Responder or Another Poisoner](#if-chained-with-responder-or-another-poisoner)
- [If Positioned via ARP Spoofing](#if-positioned-via-arp-spoofing)
- [If Positioned via SPAN/Mirror Port or Tap](#if-positioned-via-spanmirror-port-or-tap)
- [The Victim's Own Authentication Attempt](#the-victims-own-authentication-attempt)
- [Endpoint Security Product Detections](#endpoint-security-product-detections)
- [Building a Timeline](#building-a-timeline)

---

## If Chained with Responder or Another Poisoner

The common real-world case (see `02 - Hands-On Use Cases.md`'s "Chained Use Alongside Responder"). All victim-side evidence — poisoned LLMNR/NBT-NS/mDNS replies, the resulting NTLM authentication attempt, Security 4624/4625, Sysmon Event ID 3 — is produced by the **poisoner**, not by Pcredz, and is already fully documented in `Responder/04 - Target Evidence.md`. Do not re-derive that table here; the only Pcredz-specific addition is that **two** independent tools captured the same session, so a matching entry should exist in both `Responder/03 - Source Evidence.md`'s log files and this tool's `03 - Source Evidence.md` output — their absence from one but not the other is itself informative (e.g. a protocol Responder doesn't natively terminate, like raw DCE-RPC NTLM traffic, showing up only in Pcredz's broader magic-byte scan).

## If Positioned via ARP Spoofing

If Pcredz's operator used ARP spoofing (a separate technique, not part of Pcredz itself — commonly `arpspoof`, `ettercap`, or a custom tool) rather than name-resolution poisoning to redirect traffic through their host:

| Artifact | Where | Detail |
|---|---|---|
| Victim ARP cache | Victim host, live-response only | `arp -a` (Windows) / `ip neigh` (Linux) showing the gateway's legitimate MAC address unexpectedly replaced by the attacker's — this is **transient**, overwritten by the next legitimate ARP reply/cache timeout, so only useful if captured during or immediately after the attack window |
| Switch CAM table anomalies | Network switch, not the victim | A single MAC address claiming multiple IPs, or gratuitous ARP floods, logged by switch-level port-security/DAI (Dynamic ARP Inspection) features if enabled |
| MITRE mapping | — | [T1557](https://attack.mitre.org/techniques/T1557/) (Adversary-in-the-Middle) generally, ARP-spoofing specifically isn't broken out to its own T1557 sub-technique the way LLMNR/NBT-NS (`.001`) and DHCP (`.003`) are |

## If Positioned via SPAN/Mirror Port or Tap

The passive-collection scenario (`02 - Hands-On Use Cases.md`'s fleet-wide use case) produces **zero** victim-endpoint artifact by design — that's the entire point of a mirror port, and it's indistinguishable from legitimate network-security-monitoring traffic from any single victim's perspective. The only evidence trail is infrastructure-side:

| Artifact | Where | Detail |
|---|---|---|
| SPAN/mirror session configuration | Switch running-config / config-change audit log | `show monitor session` (Cisco) or equivalent — an unauthorized or newly-added mirror session pointed at an unexpected destination port is the actual evidence of this collection method, not anything on an endpoint |
| Physical tap | Physical inspection only | No logical/log evidence exists for an inline hardware tap at all — this is the one scenario in this entire repo with **no native digital evidence path**, physical security review is the only control |
| Switch admin authentication logs | Switch/AAA (TACACS+/RADIUS) logs | Who configured the mirror session and when — the closest thing to an "operator identity" artifact this scenario produces |

## The Victim's Own Authentication Attempt

Regardless of *how* Pcredz got visibility, if the captured traffic includes a **successful or attempted** authentication (SMB/HTTP/LDAP NTLM exchange, an SMTP/FTP/IMAP-style cleartext login, an MSSQL TDS login, a Kerberos AS-REQ), that authentication attempt's own victim-side and (where applicable) server-side evidence — Security 4624/4625, Kerberos 4768/4771 for AS-REQ failures, application-specific auth logs — is standard authentication evidence, fully covered in `Windows/05 - Users, Groups & Authentication.md` and this repo's other artifact-reference notes, not re-derived here. What Pcredz specifically adds to that picture is only that the credential material was **exposed on the wire in a recoverable form** — cleartext or NTLM-negotiable — which is a property of the protocol/configuration in use (unencrypted LDAP, SMB signing not enforced, plaintext SMTP AUTH) rather than anything the victim host logs about Pcredz.

## Endpoint Security Product Detections

Since Pcredz produces no process activity, network connection, or authentication behavior *on the victim*, mainstream endpoint security products have **nothing Pcredz-specific to detect on the victim side at all** — any detection here is entirely a function of the redirection technique in use (Responder's poisoning heuristics, ARP-spoofing detection) or, separately, of whatever's deployed on the **operator's own host** if it's a managed endpoint (see `03 - Source Evidence.md`'s promiscuous-mode and process signals — some EDR products do flag a host's own NIC entering promiscuous mode as a "possible packet sniffer" heuristic, independent of which specific sniffing tool caused it).

## Building a Timeline

Because there is no single "Pcredz ran against this victim" event, timeline construction here is **entirely a function of which redirection/positioning technique was in play**:

- **Chained with Responder:** build the timeline exactly as described in `Responder/04 - Target Evidence.md`'s walkthrough, then cross-reference Pcredz's own `CredentialDump-Session.log` (see `03 - Source Evidence.md`) as a second, corroborating source-side timestamp for the same event.
- **ARP spoofing:** the victim's transient ARP-cache poisoning window (if captured live) anchored against the resulting authentication attempt.
- **SPAN/tap:** no victim-endpoint timeline is possible at all — the switch mirror-session **configuration change** timestamp (infrastructure audit log) is the only available anchor, correlated against Pcredz's own source-side capture-start time.

In every case, the tightest and most reliable anchor remains the **source-side** `CredentialDump-Session.log`/`logs/*.txt` timestamps documented in `03 - Source Evidence.md` — treat this file's contents as context for interpreting *why* the source-side evidence looks the way it does, not as an independent evidentiary source in its own right.
