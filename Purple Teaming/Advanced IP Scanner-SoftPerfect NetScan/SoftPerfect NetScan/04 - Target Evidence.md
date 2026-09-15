# SoftPerfect Network Scanner — Target Evidence

**Scope note**, same convention as `Advanced IP Scanner/04 - Target Evidence.md`: a host that's only ARP/ICMP/port-swept and never queried more deeply shows nothing beyond network-layer noise. What's genuinely different here is that NetScan's **authenticated WMI/registry/SSH/SNMP queries do execute real, logged actions on the target** — this is the tool's real forensic contribution beyond its sibling's page, and it's covered in depth below.

## Contents
- [Network-Layer Evidence for the Unauthenticated Sweep](#network-layer-evidence-for-the-unauthenticated-sweep)
- [Target-Side Evidence of an Authenticated WMI Query](#target-side-evidence-of-an-authenticated-wmi-query)
- [Target-Side Evidence of a Remote Registry Query](#target-side-evidence-of-a-remote-registry-query)
- [Target-Side Evidence of SNMP/SSH Queries](#target-side-evidence-of-snmpssh-queries)
- [Endpoint Security Product Signature Behavior](#endpoint-security-product-signature-behavior)
- [Building a Timeline](#building-a-timeline)

---

## Network-Layer Evidence for the Unauthenticated Sweep

Identical in character to `Advanced IP Scanner/04 - Target Evidence.md`'s diagram: an ARP/ICMP burst plus sequential TCP SYNs across the configured port set, all from one source IP within a short window. Zeek `arp.log`/`conn.log` or per-host Sysmon 3 shows the same horizontal single-source, multi-port pattern. Nothing tool-specific distinguishes this stage from `Advanced IP Scanner/`'s baseline sweep at the network layer alone — the differentiation only appears once a deep-query protocol gets involved.

## Target-Side Evidence of an Authenticated WMI Query

This is real code execution against the target's WMI provider host process, and it leaves a genuine trail:

- **WMI-Activity/Operational Event ID 5857** fires broadly for WMI provider-host activity, including a legitimate remote query like NetScan's — noisy (fires for lots of normal WMI activity too) but present.
- The connecting account is visible in the standard **Security Event ID 4624/4634** (network logon/logoff, Logon Type 3) pair on the target, correlating the source IP and the specific credential used — this is the same credential the operator configured in Credential Manager (`03 - Source Evidence.md`), so a target-side 4624 hit and a source-side Credential Manager reference are two independent corroborating views of the same authentication event.
- Per this repo's existing `Impacket/wmiexec/04 - Target Evidence.md` finding (cross-linked rather than re-derived): a WMI query that goes through `Win32_Process.Create()`-style execution spawns `WmiPrvSE.exe` as an unexpected child — but NetScan's WMI *queries* (pulling installed software, services, users) are typically **read-only property retrieval**, not process creation, so this specific `WmiPrvSE.exe`-child signature does **not** apply to NetScan's normal deep-scan behavior the way it does to `wmiexec.py`'s command-execution model. Don't conflate the two just because both ride WMI.

## Target-Side Evidence of a Remote Registry Query

- Requires the **Remote Registry** service to be running on the target — per the same mechanic already documented in `Impacket/secretsdump/04 - Target Evidence.md`, this service is frequently found already-running rather than freshly started by the query (many environments leave it enabled), so **no Event 7045 equivalent** should be expected as a reliable tell.
- The connecting session again produces a standard **Security 4624** (Logon Type 3) on the target, same correlation value as the WMI case above.
- No file is dropped, no service is created specifically by the registry-read operation itself — this stage is evidentially thin beyond the logon event, consistent with remote registry being a read-only query mechanism here rather than an execution primitive.

## Target-Side Evidence of SNMP/SSH Queries

- **SNMP** (UDP 161) queries against network infrastructure (switches, printers) typically leave **no host-side log at all** on consumer/appliance-class SNMP agents — this is often the thinnest-evidence query type in NetScan's whole toolkit, since many SNMP-speaking devices simply don't log queries by design.
- **SSH** (TCP 22) queries against a Linux/Unix/appliance target generate whatever the target's own SSH daemon logs by default — typically `/var/log/auth.log` or `/var/log/secure` recording the connecting IP, username, and success/failure, independent of anything NetScan-specific; this repo's Windows-centric event-ID tables don't apply here, and any Linux-side artifact reference lives outside this module's current scope.

## Endpoint Security Product Signature Behavior

Same structural point as `Advanced IP Scanner/`: a purely network-swept host with no deep query has nothing for local EDR/AV to see. Once a WMI/registry query actually executes against the target, most EDR products treat WMI provider-host activity as routine unless paired with a suspicious downstream action (process creation, lateral file write) — a pure information-gathering WMI/registry read from NetScan is unlikely to trigger a behavioral alert on its own, making the **event-log correlation above** (4624 + 5857) the more productive target-side hunt than expecting an EDR alert.

## Building a Timeline

1. Anchor the scan window using the source host's `netscan.xml` scan-history entries and result-export timestamps (`03 - Source Evidence.md`).
2. Cross-reference the unauthenticated-sweep portion against Zeek/Sysmon 3 ARP-and-multi-port-SYN evidence, identical methodology to `Advanced IP Scanner/`.
3. For any host that received a deep query, pull that specific target's **Security 4624/4634** pair and (for WMI) **WMI-Activity 5857**, matching the source IP and timestamp against the sweep window — this tells you definitively **which** hosts got only swept versus which got genuinely, credentially queried, a distinction the network layer alone can blur (SNMP/SSH/WMI traffic all just look like "more connections from the same source IP" without inspecting protocol/port).
4. Where the renamed-binary evasion (`Intel.exe`/`Dell.exe`) is suspected on the source side, corroborate via the target-side event correlation above rather than relying on the source host's filename at all — the target's own logs don't care what the scanning binary was named.
