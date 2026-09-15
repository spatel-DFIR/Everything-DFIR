# Pcredz — Hands-On Use Cases

Every scenario below rides the same acquisition → normalization → extraction pipeline documented in `01 - Overview.md` — what changes is the input source, which protocols are in scope, and what happens to the extracted material afterward. MITRE ATT&CK ID(s) are tagged per scenario.

## Contents
- [Offline Parsing of a Single Pcap File](#offline-parsing-of-a-single-pcap-file)
- [Bulk Recursive Parsing of a Capture Directory](#bulk-recursive-parsing-of-a-capture-directory)
- [Live Interface Capture](#live-interface-capture)
- [Verbose Live Capture](#verbose-live-capture)
- [Timestamped Extraction for Timeline Work](#timestamped-extraction-for-timeline-work)
- [Per-Engagement Output Directory](#per-engagement-output-directory)
- [Protocol-Scoped Extraction](#protocol-scoped-extraction)
- [Host Exclusion](#host-exclusion)
- [Chained Use Alongside Responder](#chained-use-alongside-responder)
- [Extracting from a Wireshark/tcpdump Triage Export](#extracting-from-a-wiresharktcpdump-triage-export)
- [Passive, Fully Offline DFIR Use Against a Seized Pcap](#passive-fully-offline-dfir-use-against-a-seized-pcap)
- [Fleet/Segment-Wide Passive Collection from a SPAN or Tap](#fleetsegment-wide-passive-collection-from-a-span-or-tap)
- [Cracking Captured Hashes with Hashcat](#cracking-captured-hashes-with-hashcat)
- [Docker-Based Deployment](#docker-based-deployment)
- [Running a Legacy python-libpcap Install](#running-a-legacy-python-libpcap-install)

---

## Offline Parsing of a Single Pcap File

**MITRE ATT&CK:** [T1040](https://attack.mitre.org/techniques/T1040/) (Network Sniffing) — applied post-hoc to a static capture rather than live traffic

```bash
./Pcredz -f capture.pcap
```

The baseline case. Pcredz opens the file with `pcapy.open_offline()`, walks every packet once, and writes any matches to `./logs/`. No privileges are required beyond read access to the file itself — this is the mode most relevant to a pure analyst who was handed a `.pcap` and has no live network position at all.

## Bulk Recursive Parsing of a Capture Directory

**MITRE ATT&CK:** T1040

```bash
./Pcredz -d /forensics/network-captures/
```

Walks the directory tree with `os.walk()`, processing every file ending in `.pcap` or `.pcapng`. Each file gets its own **fresh** in-memory state (NTLM challenge cache, dedup set) — a hash captured in `day1/morning.pcap` and again in `day1/afternoon.pcap` will be written to `logs/NTLMv2.txt` twice, once per file, since the dedup set doesn't persist across files in the same directory walk. Useful for processing a day's worth of rotated captures, or an entire evidence share, in a single invocation.

## Live Interface Capture

**MITRE ATT&CK:** T1040

```bash
sudo ./Pcredz -i eth0
```

Opens `eth0` in promiscuous mode via `pcapy.open_live()` and processes packets as they arrive, indefinitely, until interrupted (`Ctrl+C`). On an unswitched segment (hub, wireless in monitor mode, or a host already positioned to see broadcast/multicast poisoning traffic) this alone can see other hosts' traffic; on a modern switched network it will only see traffic addressed to or from the capture host itself unless paired with a redirection technique — see [Chained Use Alongside Responder](#chained-use-alongside-responder) below.

## Verbose Live Capture

**MITRE ATT&CK:** T1040

```bash
sudo ./Pcredz -i eth0 -v
```

`-v` prints every match to the console as it's seen, including repeats of a credential already captured — useful for confirming a target is authenticating repeatedly (e.g. a service account retrying on an interval) during a live-monitoring window. Does not change what lands in `logs/*.txt` — those files stay deduplicated regardless.

## Timestamped Extraction for Timeline Work

**MITRE ATT&CK:** T1040

```bash
./Pcredz -f capture.pcap -t
```

Prepends a timestamp to every printed/logged line. Since Pcredz's own file outputs don't otherwise carry a per-credential timestamp (only the session log does, via the logging handler's own timestamp), `-t` is the difference between being able to correlate a specific `logs/NTLMv2.txt` entry against a specific moment in a broader timeline versus not.

## Per-Engagement Output Directory

**MITRE ATT&CK:** T1040

```bash
./Pcredz -f capture.pcap -o /data/engagements/acme-corp-2026/
```

`-o` controls where `logs/` and `CredentialDump-Session.log` land (default: current directory). Operators running multiple engagements or processing multiple clients' captures use this to keep evidence cleanly separated rather than relying on discipline about which directory `Pcredz` was launched from.

## Protocol-Scoped Extraction

**MITRE ATT&CK:** T1040

```bash
# NTLM-only capture — cut noise from a busy mixed-protocol segment
./Pcredz -f capture.pcap --disable HTTP --disable FTP --disable IRC \
  --disable LDAP --disable SMTP --disable Kerberos --disable SNMP --disable MSSQL

# Suppress the noisiest/least valuable protocols only
./Pcredz -f capture.pcap --disable HTTP --disable SNMP
```

Each `--disable` is independently checked at the top of its extractor function — a disabled protocol produces **zero** output at every level (console, `logs/*.txt`, and the session log), not just a suppressed file write. Operators reach for this either to cut down noisy/low-value output (HTTP password-field scanning is a common source of false positives) or to focus purely on one credential type for a targeted analysis pass.

## Host Exclusion

**MITRE ATT&CK:** T1040

```bash
# Exclude the operator's own host during live capture
sudo ./Pcredz -i eth0 --exclude-host 192.168.1.50 -v

# Exclude multiple hosts (e.g. known infrastructure/scanner IPs)
./Pcredz -f capture.pcap --exclude-host 192.168.1.100 --exclude-host 10.0.0.5

# Common pentest pattern — pass the operator's own current IP dynamically
sudo ./Pcredz -i eth0 --exclude-host $(hostname -I | awk '{print $1}') -v
```

`--exclude-host` is checked immediately after IP-header extraction, before any protocol parsing — an excluded IP's packets are dropped before Pcredz spends any cycles on them. The stated purpose in the tool's own examples is filtering the operator's own traffic out of target-focused results, but it's equally useful for excluding a known-noisy host (a backup server, a vulnerability scanner) from an analytic pass.

## Chained Use Alongside Responder

**MITRE ATT&CK:** [T1557.001](https://attack.mitre.org/techniques/T1557/001/) (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay) for the redirection step, plus T1040 for the capture itself

```bash
# Terminal 1 — Responder poisons the segment and gets victims talking to this host
sudo python3 Responder.py -I eth0 -v

# Terminal 2 — Pcredz independently parses the same interface's traffic
sudo ./Pcredz -i eth0 -v
```

This is the scenario that resolves Pcredz's own architectural limitation described in `01 - Overview.md`'s red-flag callout: Pcredz alone is a passive listener with nothing to listen to on a switched segment, so it's commonly run **alongside** `Responder/`, which does the actual traffic redirection (see `Responder/01 - Overview.md`'s poisoning mechanics). Pcredz then serves as an independent, protocol-broader second extraction pass over the same traffic — useful because Responder's own capture logic is scoped to the protocols its rogue servers implement, while Pcredz's raw-payload NTLMSSP magic-byte scan (see `01 - Overview.md`'s Stage 3) will also catch NTLM material carried inside protocols Responder itself never terminates, like DCE-RPC or MSSQL traffic that happens to cross the same wire for an unrelated reason.

## Extracting from a Wireshark/tcpdump Triage Export

**MITRE ATT&CK:** T1040

```bash
tcpdump -i eth0 -w live-triage.pcap 'port 445 or port 389 or port 88'
./Pcredz -f live-triage.pcap -t
```

A common analyst pattern during live incident triage: capture a short, filtered window with `tcpdump`/`dumpcap` (kernel-level BPF filtering that Pcredz itself never applies — see `01 - Overview.md`), then hand the resulting file to Pcredz for fast bulk extraction rather than manually paging through the capture in Wireshark looking for authentication exchanges.

## Passive, Fully Offline DFIR Use Against a Seized Pcap

**MITRE ATT&CK:** Not an ATT&CK technique in this direction — this is defensive/investigative use, not an attack

```bash
./Pcredz -f /evidence/case-4471/switch-mirror-capture.pcap -t -o /evidence/case-4471/pcredz-output/
```

The pure blue-team use case: an analyst with a previously collected/seized capture (from a compromised segment, a SPAN port that was already logging, or an IR vendor's own collection) runs Pcredz purely to inventory what credential material was exposed in cleartext or NTLM-negotiable form during the capture window — no live access, no attacker intent, and often the fastest way to answer "was anything usable to an attacker actually on this wire" across a large capture.

## Fleet/Segment-Wide Passive Collection from a SPAN or Tap

**MITRE ATT&CK:** T1040

```bash
sudo ./Pcredz -i eth0 -o /data/span-collection/ -t
```

Positioned on a switch SPAN/mirror port or an inline tap, a single Pcredz instance sees every host's traffic crossing that port without needing to poison or compromise any individual endpoint — the broadest-blast-radius live-capture scenario, and the one closest to a legitimate network-security-monitoring deployment (the same position a Zeek sensor or IDS would occupy). This is also the scenario where the switch/tap **infrastructure configuration itself**, not any endpoint, is the meaningful evidence trail — see `04 - Target Evidence.md`.

## Cracking Captured Hashes with Hashcat

**MITRE ATT&CK:** T1040 (capture) — cracking itself isn't a distinct ATT&CK technique, it's the offline follow-on; see `Hashcat/` for the full workflow

```bash
# NetNTLMv1
hashcat -m 5500 logs/NTLMv1.txt wordlist.txt

# NetNTLMv2
hashcat -m 5600 logs/NTLMv2.txt wordlist.txt

# Kerberos AS-REQ pre-auth (etype 23) — a distinct hash type from Kerberoasting/
# AS-REP Roasting's -m 13100/-m 18200, since this material was passively sniffed
# from a normal client logon rather than actively solicited via LDAP/KRB5
hashcat -m 7500 logs/MSKerb.txt wordlist.txt
```

Hash format and hashcat mode must match exactly (see `01 - Overview.md`'s Techniques table for the format each file uses); full mode reference and cracking-strategy detail lives in `Hashcat/`, not re-derived here.

## Docker-Based Deployment

**MITRE ATT&CK:** T1040

```bash
docker build -t pcredz .

# Offline file mode — mount the working directory
docker run --rm -v $(pwd):/data pcredz -f /data/capture.pcap

# Live capture mode — requires host networking to see the real interfaces
docker run --rm --net=host -v $(pwd):/data pcredz -i eth0 -v
```

The official `Dockerfile` builds a `python:3.11-slim-bookworm`-based image with `libpcap-dev`, `gcc`, `g++`, and `pcapy-ng` pre-installed — useful on an operator host where building `pcapy-ng`'s C extension is impractical (locked-down build environment, unsupported distro) or where engagement hygiene calls for a disposable, reproducible container rather than a persistent host install.

## Running a Legacy python-libpcap Install

**MITRE ATT&CK:** T1040

```bash
git clone --branch v2.0.3 https://github.com/lgandx/PCredz.git
cd PCredz
sudo apt-get install python3-pip libpcap-dev
pip3 install Cython python-libpcap
python3 ./Pcredz -f capture.pcap
```

Included because most existing third-party write-ups, cheat sheets, and course material describe **this** era of Pcredz (`pylibpcap`/`python-libpcap`, pre-2025-12-30) — worth knowing deliberately, since an analyst who finds `python-libpcap` (rather than `pcapy-ng`) installed on a seized operator host is looking at a checkout from **before** the 2.1.0 rewrite, which is itself a rough dating signal (see `03 - Source Evidence.md`'s Installation Artifacts). This checkout also still has real, functioning credit-card Luhn-check extraction and IMAP/POP3/Citrix-ICA parsing that the current `master` branch dropped (see `01 - Overview.md`'s History corrections).
