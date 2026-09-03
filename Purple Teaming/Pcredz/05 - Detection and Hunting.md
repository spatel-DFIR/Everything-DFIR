# Pcredz — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal Survives Which Scenario](#hunting-priority--which-signal-survives-which-scenario)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal Survives Which Scenario

Pcredz itself exposes no evasion flags in the usual sense (no encoder, no traffic-shaping option) — its "evasion" is architectural: it's a pure listener, so most of what a defender can actually detect belongs to whichever redirection technique is paired with it, not to Pcredz. Rank hunts by which **scenario** they depend on, strongest (most scenario-independent) first:

| Rank | Signal | Live `-i` capture | Offline `-f`/`-d` (no live network use) | Chained with Responder | SPAN/tap-only (no redirection) |
|---|---|---|---|---|---|
| 1 (strongest) | Victim's own resulting authentication attempt (Security 4624/4625, Kerberos 4768/4771, app auth logs) exposed in cleartext/NTLM-negotiable form | N/A — belongs to whatever exposed it | N/A — pcap was already collected | ✅ Yes — `Responder/05 - Detection and Hunting.md`'s signal, applies unchanged | ✅ Yes, if the underlying protocol/config was already insecure |
| 2 | Operator-host promiscuous-mode NIC flag | ✅ Yes — required by `pcapy.open_live()`, no way to disable | N/A — no live capture occurs | ✅ Yes | ✅ Yes, but expected/benign on a legitimate monitoring host at the SPAN destination |
| 3 | Operator-host process/`pcapy-ng` presence | ✅ Yes | ✅ Yes (short-lived, may already have exited) | ✅ Yes | ✅ Yes |
| 4 (weakest, and often not applicable at all) | Any network-level Pcredz-specific traffic signature | ❌ **Never** — Pcredz sends no packets of its own, there is nothing to fingerprint on the wire | ❌ Never | ❌ Never (the redirection tool's traffic is what's fingerprinted, not Pcredz's) | ❌ Never |

**The practical conclusion:** hunting for "Pcredz" as a distinct network entity is a category error — rank 4 doesn't exist. Build detection around rank 1 (the exposed-credential consequence, which is what actually matters regardless of which sniffing tool was used) and rank 2/3 (the operator-host artifacts in `03 - Source Evidence.md`) if there's reason to suspect a specific host is doing the capturing. For the chained-with-Responder case, this note's contribution is purely corroborating — the real detection logic is `Responder/05 - Detection and Hunting.md`'s, not duplicated here per §7's cross-linking convention.

## Hunting on Source

```bash
# Promiscuous-mode NIC — the strongest single artifact for live-capture mode,
# since legitimate hosts rarely need it
ip link show | grep -B2 -i promisc

# Process check (covers both a running -i session and a still-executing -f/-d pass)
ps aux | grep -i pcredz

# Locate an installed/cloned copy and date it via which pcap library is present
find / -iname "Pcredz" -type f 2>/dev/null
pip3 show pcapy-ng 2>/dev/null && echo "-> v2.1.0+ (current feature/output set)"
pip3 show python-libpcap 2>/dev/null && echo "-> pre-v2.1.0 (has CC/IMAP/POP3/CTX parsing the current version lacks)"

# Pin the exact commit/tag in use
git -C <path-to-checkout> log -1 --format='%H %cd' 2>/dev/null
git -C <path-to-checkout> describe --tags 2>/dev/null

# Shell history for the invocation and chosen scope
grep -iE "pcredz" ~/.bash_history ~/.zsh_history 2>/dev/null

# auditd execve record — survives a shell-history wipe
ausearch -x Pcredz 2>/dev/null
ausearch -x python3 2>/dev/null | grep -i pcredz
```

## Hunting on Target

There is deliberately little here — see `04 - Target Evidence.md`'s reframe. What hunting logic exists on the "target" side is entirely the redirection technique's own, cross-linked rather than duplicated:

```powershell
# If chained with Responder — use Responder's own hunt logic in full
# (see Responder/05 - Detection and Hunting.md for the complete set)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
  Where-Object { $_.Message -match 'Package Name.*NTLM' }
```

```bash
# If SPAN/tap-positioned — the only meaningful "target-side" hunt is
# infrastructure configuration review, not an endpoint command at all
show monitor session all          # Cisco IOS — enumerate active mirror sessions
show run | include monitor        # cross-check against a known-good baseline
```

For the ARP-spoofing-positioned case, hunt using standard ARP-spoofing detection (gratuitous ARP monitoring, static ARP entries for critical infrastructure, Dynamic ARP Inspection where available) — this is generic AiTM-positioning detection, not specific to this tool, and isn't re-derived here.

## Fleet-Wide Sweep

```powershell
# Sweep for hosts with a NIC in promiscuous mode — the closest thing to a
# fleet-wide Pcredz-specific indicator, though it also flags legitimate
# monitoring tools (Wireshark, tcpdump, other sniffers) equally
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-NetAdapter | Where-Object { $_.PromiscuousMode -eq $true } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, Name, InterfaceDescription
} -ErrorAction SilentlyContinue

$results | Export-Csv -Path .\promiscuous_nic_sweep.csv -NoTypeInformation
```

```bash
# Linux fleet sweep via a config-management/orchestration tool (illustrative —
# adapt to your actual fleet-management platform)
for host in $(cat hosts.txt); do
  ssh "$host" "ip link show | grep -i promisc && echo FOUND on $host"
done
```

Combine with a switch-side sweep of all active SPAN/mirror sessions across the estate (`show monitor session all` per switch, or your NAC/network-management platform's equivalent) — an unaccounted-for mirror session pointed at a host that also shows up in the promiscuous-mode sweep above is a high-confidence pairing.

## Remediation

**Capture evidence first** — export the relevant promiscuous-mode/process findings and, if a live session is still running, consider a memory capture (see `03 - Source Evidence.md`) before killing the process, since in-progress capture state that hasn't yet flushed to disk will be lost otherwise.

The actual fix is **not** a Pcredz-specific control — since Pcredz only recovers what's already exposed on the wire, remediation is about removing the exposure, not the listener:

```text
1. Encrypt what's currently cleartext or NTLM-negotiable on the wire:
   - Enforce SMB signing (closes the NTLM-relay path that makes captured
     hashes dangerous even when cracking fails — see Responder/05's
     Remediation section, same underlying fix)
   - Enforce LDAPS / LDAP channel binding instead of plaintext Simple Bind
   - Enforce SMTP/IMAP/POP3 STARTTLS or implicit TLS, disable plaintext AUTH
   - Migrate SNMP to v3 (authenticated + encrypted) and retire v1/v2c
     community-string auth entirely
   - Enforce Kerberos-only authentication where NTLM fallback isn't required,
     since NTLM is what Pcredz's magic-byte scan (see 01 - Overview.md) is
     built around

2. Remove the redirection vector that gives Pcredz visibility in the first
   place (this is the actual root cause on a switched network):
   - LLMNR/NBT-NS/WPAD hardening — see Responder/05's Remediation block,
     unchanged here
   - Dynamic ARP Inspection (DAI) + DHCP snooping on switch infrastructure
     to prevent ARP spoofing
   - Restrict SPAN/mirror-port configuration changes to change-controlled,
     logged, alertable switch administration

3. Treat any unauthorized promiscuous-mode NIC or unaccounted-for mirror
   session as an active-incident indicator, not a routine finding — neither
   has a common legitimate cause on a typical managed endpoint.
```

Detection rules in this note are compensating controls for environments that can't immediately close every plaintext/NTLM-fallback protocol — the durable fix is removing what's recoverable from the wire at all, since a listener with nothing worth listening to is neutralized regardless of which specific tool an operator reaches for.
