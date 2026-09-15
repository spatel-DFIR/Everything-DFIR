# Advanced IP Scanner — Target Evidence

**Scope note, read this first:** unlike a lateral-movement tool (`Impacket/psexec/`, etc.), Advanced IP Scanner never executes code on the hosts it scans — a scanned host's own disk/registry/event log is **structurally untouched** by the scan itself. What this file actually covers is (a) the **network-layer signature** every scanned host's own NIC/firewall/Sysmon sees regardless of any code execution, and (b) what a target shows **only if** the operator follows up the scan with an actual connection (Radmin, RDP, or a mounted share) — those two are evidentially very different and are kept separate below. Don't expect filesystem/registry artifacts on a merely-scanned host; that's not a gap in this note, it's a structural fact about what the tool does.

## Contents
- [Network-Layer Evidence on a Scanned Host](#network-layer-evidence-on-a-scanned-host)
- [If Radmin/RDP Follow-Up Occurs](#if-radminrdp-follow-up-occurs)
- [If a Share Is Actually Mounted](#if-a-share-is-actually-mounted)
- [Endpoint Security Product Signature Behavior](#endpoint-security-product-signature-behavior)
- [Building a Timeline](#building-a-timeline)

---

## Network-Layer Evidence on a Scanned Host

Every host on the segment being swept — whether or not it's ultimately of interest to the operator — sees the same signature at the network layer:

```
Source (operator's foothold)                    Every host on the subnet
        │                                                  │
        │──── ARP request (broadcast) ───────────────────▶│
        │◀─── ARP reply (if host is up) ───────────────────│
        │                                                  │
        │──── TCP SYN :4899 (Radmin check) ───────────────▶│
        │──── TCP SYN :3389 (RDP check) ──────────────────▶│
        │──── TCP SYN :445  (SMB share check) ────────────▶│
        │──── TCP SYN :80/443/21 (HTTP/FTP check) ────────▶│
        │        (all within a short window, sequential
        │         across the whole configured range)
```

If the scanned host runs **Sysmon** or has host-firewall connection logging enabled, this produces:
- **Sysmon Event ID 3** (or the equivalent firewall "connection allowed/blocked" log) showing **one source IP hitting several distinct destination ports on this host within seconds** — the classic horizontal single-source, multi-port probe pattern, easily distinguished from normal traffic by port diversity alone.
- If the host itself runs Zeek/an equivalent NSM sensor upstream, `arp.log` shows the broadcast/reply pair, and `conn.log` shows the short burst of SYNs, both attributable to the same source IP within the same short window — the strongest possible network-layer corroboration, and the one signal that survives even if the operator later deletes every trace on the source host (`03 - Source Evidence.md`).

This network-layer signature is the **only** evidence a purely-scanned, never-followed-up host will ever show.

## If Radmin/RDP Follow-Up Occurs

Only relevant once the operator actually pivots into a discovered host, not for the scan itself:

- **RDP** — standard Security Event ID **4624** (Logon Type 10, RemoteInteractive) on the target, correlating the source IP to the account used. This repo's broader `Windows/` module already covers RDP logon-event mechanics in depth; nothing here is scan-tool-specific beyond the fact that the scan is what *found* the open listener in the first place.
- **Radmin** — Radmin Server maintains its own connection log (configurable, off by default per Famatech's documentation) independent of the Windows Security log; if enabled, it records the connecting IP and timestamp. Radmin itself is out of this page's scope — it's a separate Famatech product with its own mechanics — but its presence as a follow-up action from this tool's scan is worth naming here since the two are commercially and operationally linked (`01 - Overview.md`).

## If a Share Is Actually Mounted

Browsing a share the scan surfaced generates the same SMB-session evidence any other SMB client would (Security Event ID 5140 Network Share Object Access if that auditing is enabled, which it usually isn't by default) — again, standard SMB evidence rather than anything specific to this tool; the scan's contribution was only identifying which shares existed.

## Endpoint Security Product Signature Behavior

A scanned host, having had no code execute on it, gives an EDR/AV product **nothing to alert on locally** — this is a structural blind spot, not a product failure. Detection responsibility for the scan itself sits entirely with network-layer tooling (above) or with whatever product is running on the **source** host (`03 - Source Evidence.md`), which may flag `advanced_ip_scanner.exe`/`advanced_ip_scanner_console.exe` as a PUA/HackTool (several vendors, including Trend Micro's `HackTool.Win32.IPScanner.A` signature, categorize it this way) — but a PUA/HackTool classification is frequently set to "detect only" rather than "block," since the tool has broad legitimate IT-admin use, mirroring `AnyDesk/`'s "presence alone means nothing without a baseline" framing.

## Building a Timeline

1. Establish the scan window from the source-host registry `LastWriteTime` on the `IpRangesMruList`/`LastRangeUsed` values and any exported result-file timestamps (`03 - Source Evidence.md`).
2. Cross-reference that window against Zeek `arp.log`/`conn.log` or per-host Sysmon 3 events for the matching ARP-broadcast-and-multi-port-SYN pattern from the same source IP.
3. Where a Radmin/RDP/share follow-up occurred, anchor the **next** event in the chain (4624 Type 10, Radmin's own log if enabled, or 5140) to a timestamp shortly after the scan window closes — the gap between "scan completes" and "first follow-up connection" is itself a useful operational-tempo data point (an automated, scripted operation typically pivots within seconds to minutes; a manual, hands-on-keyboard operator may take much longer).
4. Cross-check against `01 - Overview.md`'s trojanized-installer campaign: if the *source* host's own `advanced_ip_scanner.exe` spawns an unexpected child process or an outbound beacon to an unfamiliar domain shortly after launch, that host may itself be the actual victim of the fake-installer supply-chain attack rather than a genuine operator foothold — check for `pcre.dll` in the install directory before assuming the scan traffic itself is the primary incident.
