# Masscan — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide / Network-Wide Sweep](#fleet-wide--network-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

Masscan exposes very few evasion knobs compared to a tool like Impacket's `psexec.py` — `--rate` (timing), `--ttl` (one packet field), and `--seed`/target-set choices (order/scope) are essentially the whole surface. Rank hunts by what an operator can realistically change without recompiling the tool, strongest first:

| Rank | Signal | Survives `--rate` tuning down to stealth levels? | Survives a `--ttl` override? |
|---|---|---|---|
| 1 (strongest) | TCP window (1025) + options (MSS-only, no SACK/timestamps/window-scale) + DF-clear combination | ✅ Yes — none of these are exposed via any CLI flag | ✅ Yes — unrelated to TTL |
| 2 | IP TTL = 255 | ✅ Yes | ❌ **No** — `--ttl` directly overrides this field |
| 3 | Uniform, non-RTT-adaptive inter-packet timing at a detectable rate | ⚠️ **Partial** — a low `--rate` blends into background traffic and largely defeats rate-based heuristics; the *uniformity* (no timing-template adaptation the way nmap has) can still be a secondary signal even at low rates if enough samples are captured | ✅ Yes |
| 4 (weakest) | Volume/breadth heuristics (many destinations, many ports, in a short window) | ❌ **No** — this is exactly what tuning `--rate` down defeats; a slow, patient scan of a wide range looks like ordinary background noise to a pure volume-based detector | ✅ Yes |

**Build hunts on rank 1 as the primary, evasion-resistant detection; treat ranks 2-4 as high-confidence enrichment or an early-warning tripwire for the common case (default or moderately fast scans), not the sole detection logic against a patient operator.**

## Hunting on Source

```bash
# Shell history for any masscan invocation
grep -iE "masscan" ~/.bash_history ~/.zsh_history 2>/dev/null

# Live process check, with privilege context (masscan needs raw-socket rights)
ps -o pid,user,euid,cmd -C masscan 2>/dev/null

# Binary presence, and whether it's been granted raw-socket capabilities directly
which masscan 2>/dev/null
getcap "$(which masscan 2>/dev/null)" 2>/dev/null

# Evidence of an interrupted/resumed scan
find / -maxdepth 4 -iname "paused.conf" -newer /etc/hostname 2>/dev/null

# Non-default config that pre-loads a standing excludefile / rate — indicates
# a host set up for repeated, routine scanning rather than a one-off
cat /etc/masscan/masscan.conf 2>/dev/null

# If auditd is enabled, catch the raw-socket creation even after process exit
ausearch -x masscan 2>/dev/null
```

## Hunting on Target

Because a bare masscan sweep leaves **no host-based log at all**, target-side hunting is fundamentally **network-layer** hunting. These examples assume Zeek; adapt field names for Suricata/other sensors as needed.

```bash
# 1. HIGHEST-CONFIDENCE: pull TTL/window/options directly from captured SYNs
#    and match masscan's fixed template. Requires a PCAP or a sensor that
#    exposes these fields (Zeek's conn.log alone won't have them - use
#    Suricata's eve.json with packet-capture enabled, or raw tcpdump/PCAP).
tshark -r capture.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" \
  -T fields -e ip.src -e ip.ttl -e ip.flags.df -e tcp.window_size_value -e tcp.options \
  | awk -F'\t' '$2==255 && $3==0 && $4==1025 {print}'

# 2. NetFlow / Zeek conn.log: one source, many destinations/ports, near-zero
#    duration, tiny/uniform byte counts, in a tight time window
zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes conn_state < conn.log | \
  awk '{print $1}' | sort | uniq -c | sort -rn | head -20
# then, for a suspect source IP, count distinct destinations it touched
zeek-cut id.orig_h id.resp_h < conn.log | grep '^<SUSPECT_IP>' | awk '{print $2}' | sort -u | wc -l

# 3. Rate estimation from timestamps — a very tight, near-uniform
#    inter-packet interval across the burst is consistent with a fixed
#    --rate rather than natural, jittery user/application traffic
zeek-cut ts id.orig_h < conn.log | grep '^' | awk '{print $1}' > /tmp/ts.txt
awk 'NR>1{print $1-prev} {prev=$1}' /tmp/ts.txt | sort -n | uniq -c | head

# 4. --banners runs: check web/app logs for the minimal, unmodified request
#    signature (no custom headers/User-Agent, HTTP/1.0, immediate teardown)
grep -E 'HTTP/1\.0' /var/log/nginx/access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head

# 5. Firewall/perimeter "port scan detected" heuristic alerts — often the
#    first and cheapest signal to check, well before deep packet inspection
grep -i "scan" /var/log/firewall.log 2>/dev/null
```

## Fleet-Wide / Network-Wide Sweep

```bash
# Aggregate across all available NetFlow/Zeek sensors to find any single
# source touching a disproportionate number of distinct destinations/ports
# fleet-wide — the real signal for a masscan-class sweep is breadth, not
# any single flow
zeek-cut id.orig_h id.resp_h id.resp_p < conn.log | \
  awk '{print $1}' | sort | uniq -c | sort -rn | \
  awk '$1 > 500 {print}'   # tune threshold to your baseline traffic volume

# For each flagged source, confirm the packet-template fingerprint against
# a sample of its captured SYNs before escalating (rules out a legitimate
# high-volume service like a load balancer health-checker)
```

Distinguish a masscan-class sweep from ordinary high-fan-out legitimate traffic (CDN health checks, vulnerability-management scanners like Nessus/Qualys, internal asset-discovery tools) by layering the packet-fingerprint check (rank 1 above) on top of the volume heuristic — volume alone produces too many false positives to act on directly.

## Remediation

**Capture evidence first** — export the relevant PCAP/NetFlow window and firewall log entries before making any network changes, since blocking the source doesn't preserve what's already been logged elsewhere but does end the ability to capture more of the same traffic for analysis.

```
# Perimeter/firewall: block or rate-limit the confirmed source IP(s)
# (exact syntax is platform-specific — iptables/pf/vendor firewall)

# If the scan originated from a compromised internal host rather than an
# external actor, that host itself needs the standard internal-compromise
# response (isolate, image, check for how masscan got there and what else
# came with it) — see 03 - Source Evidence.md for what to collect from it
# before/while remediating.
```

If the scan is confirmed to be an authorized internal vulnerability-management or asset-discovery process (Nessus, Qualys, an internal CMDB sweep, etc.), document the source range/schedule as a known-benign exception in the relevant IDS/firewall tooling rather than repeatedly re-triaging the same recurring alert.
