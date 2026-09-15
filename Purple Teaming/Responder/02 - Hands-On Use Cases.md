# Responder — Hands-On Use Cases

Every poisoning scenario below rides the same protocol sequence documented in `01 - Overview.md` — what changes is which protocols are poisoned, how aggressively, and what happens to captured material afterward. MITRE ATT&CK ID(s) are tagged per scenario.

## Contents
- [Passive Analyze Mode (Baseline Recon)](#passive-analyze-mode-baseline-recon)
- [Default Broadcast-Segment Poisoning](#default-broadcast-segment-poisoning)
- [Protocol-Scoped Poisoning via Responder.conf](#protocol-scoped-poisoning-via-responderconf)
- [WPAD/PAC Injection for Proxy Credential Capture](#wpadpac-injection-for-proxy-credential-capture)
- [Forced Proxy Authentication](#forced-proxy-authentication)
- [DHCP-Based WPAD Injection Across the Broadcast Domain](#dhcp-based-wpad-injection-across-the-broadcast-domain)
- [IPv6 Router Advertisement / DHCPv6 Poisoning](#ipv6-router-advertisement--dhcpv6-poisoning)
- [Forcing Cleartext Credentials with HTTP Basic Auth](#forcing-cleartext-credentials-with-http-basic-auth)
- [Downgrading to NTLMv1/LM for Faster Cracking](#downgrading-to-ntlmv1lm-for-faster-cracking)
- [Targeted Poisoning Against a Specific Host](#targeted-poisoning-against-a-specific-host)
- [Fingerprinting Hosts with RunFinger.py](#fingerprinting-hosts-with-runfingerpy)
- [Relaying Captured Auth Instead of Cracking It](#relaying-captured-auth-instead-of-cracking-it)
- [Cracking Captured Hashes Offline](#cracking-captured-hashes-offline)
- [Chained Use as an Intrusion's Opening Move](#chained-use-as-an-intrusions-opening-move)

---

## Passive Analyze Mode (Baseline Recon)

**MITRE ATT&CK:** [T1046](https://attack.mitre.org/techniques/T1046/) (Network Service Discovery) — reconnaissance, no poisoning yet

```bash
sudo python3 Responder.py -I eth0 -A -v
```

`-A` puts Responder into **analyze mode**: it logs every LLMNR/NBT-NS/mDNS query it observes without ever sending a poisoned reply. This is the operationally sane first step on an unfamiliar segment — it shows what names are actually being requested (and how often) before deciding whether poisoning is worth the noise, and it's the closest thing to a "safe" mode Responder has, since it never actively interferes with name resolution.

## Default Broadcast-Segment Poisoning

**MITRE ATT&CK:** [T1557.001](https://attack.mitre.org/techniques/T1557/001/) (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay)

```bash
sudo python3 Responder.py -I eth0 -v
```

The baseline case — every other poisoning scenario in this note is a variation on this. With the default `Responder.conf` (`LLMNR = On`, `NBTNS = On`, `MDNS = On`, `SMB = On`, `HTTP = On`, etc.), this single command starts every enabled poisoner and rogue server simultaneously and captures whatever authentication material any victim on the segment offers. `-v` is recommended for live operation — it prints captured hashes and poisoned-query notices to the console in real time rather than only to the log files.

## Protocol-Scoped Poisoning via Responder.conf

**MITRE ATT&CK:** T1557.001 — same technique, reduced footprint

```ini
# Responder.conf
[Responder Core]
LLMNR = On
NBTNS = Off
MDNS = Off
```
```bash
sudo python3 Responder.py -I eth0 -v
```

There is **no command-line flag** to disable an individual poisoner — this is a `Responder.conf` edit only (see the correction in `01 - Overview.md`'s History section: the legacy `-r` NBT-NS toggle flag was removed in v3.1.3.0). Operators scope poisoning down for two reasons: reduced noise (NBT-NS in particular is chatty and easy to fleet-wide-sweep for, see `05 - Detection and Hunting.md`), or because a specific detection is known to key off one protocol and not another.

## WPAD/PAC Injection for Proxy Credential Capture

**MITRE ATT&CK:** T1557.001 · [T1557.003](https://attack.mitre.org/techniques/T1557/003/) (Adversary-in-the-Middle: DHCP Spoofing) if paired with `-d`, below

```bash
sudo python3 Responder.py -I eth0 -w -v
```

`-w` starts the rogue WPAD proxy server. A victim whose browser has "Automatically detect settings" enabled (the Windows/IE default for years) tries to resolve the `wpad` hostname, which — absent a real WPAD server — falls through to the same LLMNR/NBT-NS broadcast poisoning covered above. Once resolved to Responder's IP, the victim fetches `wpad.dat`; Responder auto-generates a PAC script whose `FindProxyForURL()` points all traffic at itself as the proxy. From that point every outbound web request from the victim passes through Responder — often without any visible prompt, since browsers frequently negotiate proxy authentication silently.

## Forced Proxy Authentication

**MITRE ATT&CK:** T1557.001

```bash
sudo python3 Responder.py -I eth0 -P -v
```

`-P` forces proxy authentication directly rather than relying on the PAC-file handoff — the project's own README describes this as **"highly effective."** It cannot be combined with `-w` (the two are mutually exclusive request-handling paths for the same port). Operators reach for `-Pvd` together in practice — proxy-auth forcing, verbose output, and rogue DHCP (`-d`, below) injecting the WPAD pointer network-wide instead of relying on a per-victim LLMNR race.

## DHCP-Based WPAD Injection Across the Broadcast Domain

**MITRE ATT&CK:** [T1557.003](https://attack.mitre.org/techniques/T1557/003/) (Adversary-in-the-Middle: DHCP Spoofing)

```bash
sudo python3 Responder.py -I eth0 -d -w -v

# Inject a rogue DNS server instead of WPAD
sudo python3 Responder.py -I eth0 -D -v
```

`-d` races the legitimate DHCP server to answer client DHCP requests and injects a WPAD URL directly into the DHCP response (option 252), meaning **every new client that gets an IP lease** on the segment picks up the rogue proxy configuration — a fundamentally broader blast radius than winning individual LLMNR races. `-D` does the same DHCP-response race but injects a rogue DNS server instead. Both compete directly with real infrastructure and are explicitly noisier/riskier — this is the loudest, highest-blast-radius variant in this note, appropriate for a short, scoped assessment window rather than a stealthy long-running foothold.

## IPv6 Router Advertisement / DHCPv6 Poisoning

**MITRE ATT&CK:** T1557.001 · T1557.003

```bash
sudo python3 Responder.py -I eth0 --dhcpv6 -v

# Or: Router Advertisement with RDNSS, making Responder the IPv6 DNS server
sudo python3 Responder.py -I eth0 --rdnss -v
```

Modern Windows prefers IPv6 over IPv4 when both are available, and most enterprise networks run IPv4-only DHCP with no IPv6 infrastructure at all — meaning a rogue IPv6 DNS server (via `--dhcpv6` or `--rdnss`) frequently faces **zero legitimate competition**. The tool's own help text explicitly warns `--dhcpv6` "may disrupt the network," so this is a scoped, deliberate choice rather than a default-on option. Edit `[DHCPv6 Server]` in `Responder.conf` (`DHCPv6_Domain`) to restrict responses to a specific target domain rather than the entire broadcast domain.

## Forcing Cleartext Credentials with HTTP Basic Auth

**MITRE ATT&CK:** T1557.001

```bash
sudo python3 Responder.py -I eth0 -b -v
```

`-b` returns an HTTP Basic-auth challenge instead of NTLM. Basic auth is base64-encoded, not hashed — the operator gets the **plaintext password** directly rather than a NetNTLM hash to crack, at the tradeoff of a more conspicuous browser credential prompt (NTLM auth is frequently silent/transparent for domain-joined machines; Basic auth pops a visible dialog).

## Downgrading to NTLMv1/LM for Faster Cracking

**MITRE ATT&CK:** [T1562.010](https://attack.mitre.org/techniques/T1562/010/) (Impair Defenses: Downgrade Attack), plus T1557.001

```bash
sudo python3 Responder.py -I eth0 --disable-ess -v

# Legacy clients only (Windows XP/2003)
sudo python3 Responder.py -I eth0 --lm -v
```

`--disable-ess` disables Extended Session Security during the NTLM handshake, pushing the exchange toward NTLMv1 — which cracks dramatically faster offline than NTLMv2 (see [Cracking Captured Hashes Offline](#cracking-captured-hashes-offline)). `--lm` forces the legacy LM hashing scheme, relevant only against clients old enough to still negotiate it. Both are downgrade attacks against the *authentication protocol itself*, distinct from the name-resolution poisoning that got the victim connected in the first place.

## Targeted Poisoning Against a Specific Host

**MITRE ATT&CK:** T1557.001 — scoped variant

```ini
# Responder.conf
[Responder Core]
RespondTo = 10.10.10.50
RespondToName = FILESERVER01
```
```bash
sudo python3 Responder.py -I eth0 -v
```

By default Responder answers **every** query it sees on the segment. `RespondTo`/`RespondToName` (and their inverses, `DontRespondTo`/`DontRespondToName`) scope poisoning to a specific victim IP or a specific queried name — useful when a target user/host has already been identified and broad segment-wide poisoning would create unnecessary noise or collateral (e.g. breaking other analysts' or red-team members' own name resolution during a shared engagement).

## Fingerprinting Hosts with RunFinger.py

**MITRE ATT&CK:** T1046 (Network Service Discovery)

```bash
python3 tools/RunFinger.py -i 10.10.10.0/24
```

**Not a `Responder.py` flag** — `RunFinger.py` is a separate standalone script in the repo's `tools/` directory (the successor to the old, now-removed `fingerprint.py`/`-f` flag; see the correction in `01 - Overview.md`'s History). It probes SMB (445), RDP (3389), and MSSQL (1433) across a single host or a CIDR range and extracts OS version/build, domain membership, SMB signing status, null-session availability, and — notably — flags hosts still vulnerable to specific patchable issues (e.g. MS17-010) based on what it observes. Results land in a local SQLite database (`RunFinger.db`) as well as stdout. Operators run this **before** poisoning to prioritize which captured credentials are worth relaying where (a host with SMB signing disabled is directly relay-able; one that requires signing is not).

## Relaying Captured Auth Instead of Cracking It

**MITRE ATT&CK:** T1557.001, plus [T1210](https://attack.mitre.org/techniques/T1210/) (Exploitation of Remote Services) once the relay authenticates elsewhere

```ini
# Responder.conf — disable Responder's own SMB/HTTP servers so a relay
# tool can bind those ports instead
[Responder Core]
SMB = Off
HTTP = Off
```
```bash
# Option A: the bundled relay tool
sudo python3 tools/MultiRelay.py -t 10.10.10.20 -u ALL

# Option B: hand poisoning off to Impacket's ntlmrelayx.py
# (planned sibling page: Purple Teaming/Impacket/ntlmrelayx/)
sudo python3 Responder.py -I eth0 -v          # poisoning only, SMB/HTTP disabled above
ntlmrelayx.py -tf targets.txt -smb2support
```

Captured NTLM material is worth far more relayed live than cracked offline, since relaying doesn't require the victim's password at all — it just forwards the in-progress authentication to a **different** target where that hash is valid, landing a session directly. This requires Responder's own `SMB`/`HTTP` servers to be turned off in `Responder.conf` first so the relay tool can bind those ports instead of competing with Responder for them. `MultiRelay.py`'s own usage text says explicitly: *"Use this script in combination with Responder.py for best results. Make sure to set SMB and HTTP to OFF in Responder.conf."*

## Cracking Captured Hashes Offline

**MITRE ATT&CK:** T1557.001 (capture) — cracking itself isn't a distinct ATT&CK technique, it's the offline follow-on

```bash
# NetNTLMv1
hashcat -m 5500 logs/SMB-NTLMv1-Client-10.10.10.5.txt wordlist.txt

# NetNTLMv2 (the common case with default Responder.conf settings)
hashcat -m 5600 logs/SMB-NTLMv2-Client-10.10.10.5.txt wordlist.txt

# Kerberos AS-REP (captured via the Kerberos server, if enabled)
hashcat -m 7500 logs/MSKerberos-Client-10.10.10.5.txt wordlist.txt
```

Hash format and hashcat mode must match — see `03 - Source Evidence.md` for the exact filename patterns each captured type produces. `Challenge = Random` (the current `Responder.conf` default) means each session's captured hash uses a different NTLM challenge value, which is more secure for the *victim's* credential (no single crackable challenge value shared across every victim) but doesn't change per-hash crackability itself — NetNTLMv2 remains slow to crack regardless of challenge value; NetNTLMv1/LM (see the downgrade scenario above) remain fast.

## Chained Use as an Intrusion's Opening Move

This is the canonical real-world Responder pattern — it is rarely the payoff step itself; it's the credential-material source that everything else in an intrusion depends on.

```bash
# 1. Poison the segment and capture a NetNTLMv2 hash from a workstation user
sudo python3 Responder.py -I eth0 -v
# -> logs/SMB-NTLMv2-Client-10.10.10.44.txt captured

# 2. Crack it offline (or relay it live per the scenario above)
hashcat -m 5600 logs/SMB-NTLMv2-Client-10.10.10.44.txt rockyou.txt

# 3. Reuse the recovered password/hash to move laterally with a separate tool
# (Impacket's psexec.py — see Purple Teaming/Impacket/psexec/)
psexec.py 'CORP/jsmith:<recovered-password>@10.10.10.20'
```

Recognizing this **chain** — not just a Responder capture in isolation — is what separates a fast, high-confidence detection from a slow one: a burst of LLMNR/NBT-NS poisoning activity from one host, followed within hours by a successful authenticated logon from that same source IP against a host it had no prior legitimate reason to reach, is a textbook credential-harvest-to-lateral-movement chain.
