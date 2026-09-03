# Nmap — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

Nmap exposes more evasion surface than most tools in this module — timing templates, decoys, fragmentation, custom source ports, idle scanning. Rank hunts by **invariant strength**, strongest first:

| Rank | Signal | Survives `-T0`/`-T1` slow timing? | Survives `-D` decoys? | Survives `-f` fragmentation? | Survives `-sT` instead of `-sS`? |
|---|---|---|---|---|---|
| 1 (strongest) | Fan-out: one source touching many distinct destination ports/hosts, aggregated over a **long correlation window** (hours, not minutes) | ✅ Yes — defeats *short*-window thresholds, not long-window aggregation | ⚠️ Partial — the real source IP is still present among the decoys; detection still fires, attribution gets harder | ✅ Yes — fragmentation is invisible above the IP layer once reassembled | ✅ Yes — the touch-many-ports shape is the same either way |
| 2 | OS-detection 16-probe burst signature (SEQ/ECN/T2-T7 flag combinations, ~500ms) | ✅ Yes — same probe set regardless of inter-host timing | ⚠️ Partial — real source still sends the real probes | ✅ Yes | N/A — `-O` is independent of TCP scan type |
| 3 | Incomplete-handshake ratio (Zeek `conn.log` `S0`/`REJ` states, SYN with no data transferred) | ✅ Yes | ✅ Yes | ✅ Yes | ❌ **No** — `-sT` completes real handshakes, this signal specifically weakens |
| 4 | NSE default-script/service-probe traffic signatures | ✅ Yes, if `-sC`/`-sV` is used | ✅ Yes | ✅ Yes | N/A — disappears entirely if the operator skips `-sC`/`-sV` |
| 5 (weakest) | File-hash or exact-payload signature matching against a specific known probe | ❌ No — trivially defeated by `--data-length`/`--data`/custom NSE args changing the payload | ❌ No | ❌ No | ❌ No |

**Build hunts on ranks 1-3 as primary detections; treat ranks 4-5 as enrichment, not sole detection logic.** The single most important caveat: decoys (`-D`) never hide *that* a scan happened — only *which* of the touching IPs is the real one. Don't confuse "harder to attribute" with "undetectable."

## Hunting on Source

```bash
# Shell history for any nmap invocation, including flags used
grep -iE "nmap " ~/.bash_history ~/.zsh_history 2>/dev/null

# Live process check — argv visible to any local user via /proc, not just root
ps aux | grep -i nmap

# sudo's own log survives a shell-history wipe (history -c doesn't touch it)
grep -i nmap /var/log/auth.log /var/log/secure 2>/dev/null

# Leftover scan-result output files anywhere on disk
find / \( -iname "*.nmap" -o -iname "*.xml" -o -iname "*.gnmap" \) 2>/dev/null

# Confirm install + version (matters: NSE default-script set changes across releases)
dpkg -l nmap 2>/dev/null; rpm -qi nmap 2>/dev/null; brew info nmap 2>/dev/null
```

## Hunting on Target

```powershell
# 1. Windows Filtering Platform connection events — only useful if the "Filtering
#    Platform Connection" audit subcategory is enabled (off by default, high volume)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156,5157} -MaxEvents 5000 |
  Group-Object { $_.Properties[7].Value } |   # group by source address field
  Where-Object { $_.Count -gt 50 } |          # one source touching many distinct ports/times
  Sort-Object Count -Descending

# 2. pfirewall.log, if per-profile logging was enabled — independent of the
#    Security event log entirely
Get-Content "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" -Tail 5000 |
  Where-Object { $_ -match '^\d{4}-\d{2}-\d{2}' } |
  ForEach-Object { ($_ -split '\s+')[0..7] -join ',' }
```

```bash
# 3. HIGHEST-CONFIDENCE — Zeek conn.log fan-out: one source, many distinct
#    destination ports, mostly S0 (SYN, no reply) or SYN-then-immediate-RST
cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p conn_state |
  awk '$5=="S0" || $5=="REJ"' |
  sort | awk '{print $2}' | uniq -c | sort -rn | head -20

# 4. Zeek weird.log — out-of-spec TCP flag combinations catch Null/FIN/Xmas/
#    custom --scanflags probes directly, independent of any scan-specific logic
cat weird.log | zeek-cut ts id.orig_h name | grep -iE "bad_TCP_flags|non_ip_pkt"

# 5. Suricata/Snort — ET SCAN / ET POLICY rule family alerts specifically tuned
#    to Nmap's default OS-detection probes and stock NSE traffic
grep -i "ET SCAN" /var/log/suricata/fast.log 2>/dev/null | tail -100
```

## Fleet-Wide Sweep

```powershell
# Aggregate WFP/firewall-log fan-out across the estate — the classic
# threshold-based port-scan detection algorithm: count distinct destination
# ports touched per source IP within a rolling window, flag statistical outliers
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5157; StartTime=(Get-Date).AddHours(-1)} `
    -MaxEvents 10000 -ErrorAction SilentlyContinue |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated,
      @{n='SourceIP';e={$_.Properties[7].Value}}, @{n='DestPort';e={$_.Properties[9].Value}}
} -ErrorAction SilentlyContinue

$results | Group-Object SourceIP |
  Select-Object Name, Count, @{n='DistinctPorts';e={($_.Group.DestPort | Sort-Object -Unique).Count}} |
  Where-Object { $_.DistinctPorts -gt 20 } |
  Sort-Object DistinctPorts -Descending
```
Network-layer aggregation (Zeek/NetFlow across a central collector, grouped the same way) reaches every segment without depending on per-host WFP auditing being enabled at all — usually the more practical fleet-wide starting point given how rarely that audit subcategory is turned on.

## Remediation

**Capture evidence first** — export the relevant Zeek/NetFlow window, WFP/`pfirewall.log` records, and IDS alerts before taking action, since blocking a source IP does nothing to preserve what it already touched.

```powershell
# Block the confirmed source at the perimeter/host firewall
New-NetFirewallRule -DisplayName "Block-Suspected-Scanner" -Direction Inbound `
  -RemoteAddress <SourceIP> -Action Block
```
Blocking a single source IP is a weak long-term control on its own — trivial to route around with a new address — so treat it as buying time, not resolution. If the scan originated from an **internal** host (the `T1018`/`T1046` scenario in `02 - Hands-On Use Cases.md`), the real incident is that host's compromise, not the scan itself: pivot the investigation to how that host was accessed rather than stopping at "scanning detected." If a fan-out event correlates with a subsequent NSE `auth`/`brute` signature (repeated authentication failures) or an `exploit`-category footprint, treat the engagement as active exploitation and escalate accordingly rather than as reconnaissance alone.
