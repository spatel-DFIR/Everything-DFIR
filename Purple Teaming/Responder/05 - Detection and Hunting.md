# Responder — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal Survives Which Toggle](#hunting-priority--which-signal-survives-which-toggle)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal Survives Which Toggle

Responder's `Responder.conf` toggles let an operator scope poisoning down to reduce noise (see `02 - Hands-On Use Cases.md`'s "Protocol-Scoped Poisoning"). Rank hunts by what survives that scoping, strongest first:

| Rank | Signal | Survives disabling individual protocols (`NBTNS = Off`, etc.)? | Survives `-e`/`-N` (custom answer IP/name)? | Survives protocol-scoped, single-target poisoning (`RespondTo`)? |
|---|---|---|---|---|
| 1 (strongest) | Victim's own resulting NTLM auth attempt against an unfamiliar internal destination (Security 4625/4624 + Sysmon 3) | ✅ Yes — this is a consequence of *any* successful poison, regardless of which protocol won the race | ✅ Yes — the auth still targets whichever IP was injected | ✅ Yes — still fires per-victim |
| 2 | A single internal host receiving connections from many distinct source IPs on 445/389/1433/etc. in a short window | ✅ Yes, if broad/segment-wide poisoning is in use | ✅ Yes | ❌ **No** — targeted single-victim poisoning doesn't produce this fan-in pattern |
| 3 | Raw LLMNR/NBT-NS/mDNS poisoned-reply pattern (two replies, two source IPs, for the same query) on the wire | Only for the **specific protocol(s)** still enabled — disabling `NBTNS` in `Responder.conf` fully suppresses this signal for NBT-NS | ✅ Yes — the anomaly is a second reply existing at all, regardless of its content | ✅ Yes, for the targeted victim |
| 4 (weakest) | NBT-NS-specific broadcast volume / "chatty protocol" heuristics | ❌ **No** — trivially defeated by `NBTNS = Off` alone, and mDNS/LLMNR-only poisoning produces none of this pattern | N/A | N/A |

**Build hunts on rank 1 as the primary, protocol-agnostic detection — it survives every toggle Responder exposes, because it depends on the victim's own authentication behavior, not on which poisoning protocol won. Treat ranks 2-4 as fleet-scale corroboration and raw-traffic enrichment, not sole detection logic.**

## Hunting on Source

```bash
# Live listener footprint — no single legitimate process binds all of these
# privileged ports simultaneously
sudo ss -lunp | grep -E ':137|:5355|:5353|:445|:80|:443|:21|:389|:1433|:143|:110|:25'

# Process check
ps aux | grep -i responder

# Locate an installed/cloned copy and pin down its exact version/commit
find / -iname "Responder.py" 2>/dev/null
git -C <path-to-checkout> log -1 --format='%H %cd' 2>/dev/null

# Shell history for the invocation and chosen flags (reveals operator intent —
# -w/-P/-d indicate WPAD/proxy focus, --disable-ess/--lm indicate a cracking-speed
# priority over stealth)
grep -iE "responder\.py" ~/.bash_history ~/.zsh_history 2>/dev/null

# auditd execve record — survives a shell-history wipe
ausearch -x Responder.py 2>/dev/null
```

## Hunting on Target

```powershell
# 1. HIGHEST-PRIORITY: NTLM authentication failures against unfamiliar internal
#    destinations — the protocol-agnostic signal from the priority table above
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
  Where-Object { $_.Message -match 'Package Name.*NTLM' } |
  Select-Object TimeCreated,
    @{n='Account';e={$_.Properties[5].Value}},
    @{n='SourceIP';e={$_.Properties[19].Value}}

# 2. Successful NTLM logons (Type 3) where a rogue server accepted the session
#    rather than failing it — less common but higher-confidence when present
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
  Where-Object { $_.Properties[8].Value -eq 3 -and $_.Message -match 'Package Name.*NTLM' }

# 3. Sysmon: outbound connections to an internal host on ports it has no
#    business serving (445/389/1433/21/143/110/25) from many DIFFERENT
#    source processes/hosts in a short window
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} |
  Where-Object { $_.Message -match 'DestinationPort: (445|389|1433|21|143|110|25):' }

# 4. Rogue DHCP race indicators — two DHCP responses for the same lease
#    transaction in quick succession (requires DHCP server-side audit logging)
Get-WinEvent -LogName 'Microsoft-Windows-Dhcp-Server/Operational' -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'NACK|DHCPOFFER' } |
  Group-Object { $_.Properties[2].Value } | Where-Object Count -gt 1

# 5. WPAD-specific: unexpected AutoConfigURL registry value, if a live-response
#    triage catches the setting before it's renegotiated
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue |
  Select-Object AutoConfigURL
```

Raw-traffic hunting for the poisoning itself (rank 3 in the priority table) requires packet capture rather than a native Windows/Zeek log — see the caveat in `04 - Target Evidence.md`'s Network-Layer Evidence section: Zeek has no built-in LLMNR/NBT-NS/mDNS analyzer, so this specific signal needs a raw filter:

```bash
tcpdump -i eth0 -n 'udp port 5355 or udp port 137 or udp port 5353'
```

## Fleet-Wide Sweep

```powershell
# Run from a hunting workstation with rights across the estate — the strongest
# fleet-level signal is many DIFFERENT hosts all failing NTLM auth against the
# SAME unfamiliar internal IP in a tight window (rank 2 in the priority table)
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Package Name.*NTLM' } |
    Select-Object @{n='Victim';e={$env:COMPUTERNAME}}, TimeCreated,
      @{n='SourceIP';e={$_.Properties[19].Value}}
} -ErrorAction SilentlyContinue

# Group by the internal IP being authenticated TO — one IP receiving failed
# NTLM auth attempts from many different victims is the fleet-scale fingerprint
$results | Group-Object SourceIP | Sort-Object Count -Descending | Select-Object -First 10 Count, Name

$results | Export-Csv -Path .\responder_sweep_results.csv -NoTypeInformation
```

## Remediation

**Capture evidence first** — export the relevant 4625/Sysmon 3 records and, if possible, a short packet capture of the poisoned segment before making network-wide changes, since remediation here (disabling LLMNR/NBT-NS) removes the ongoing signal this note is built around.

The actual fix is **not** a detection rule — it's disabling the vulnerable name-resolution fallback network-wide:

```powershell
# Disable LLMNR via Group Policy (preferred, fleet-wide):
# Computer Configuration > Administrative Templates > Network > DNS Client >
#   "Turn OFF Multicast Name Resolution" = Enabled
#
# Or per-host via registry (verify GPO isn't overriding this before relying on it):
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
  -Name 'EnableMulticast' -Value 0 -PropertyType DWord -Force

# Disable NBT-NS per-interface (no single fleet-wide GPO toggle exists for
# NBT-NS the way there is for LLMNR — must be set per network adapter, ideally
# via a scripted sweep or DHCP option 001/044/046 configuration):
# Network adapter > WINS tab > "Disable NetBIOS over TCP/IP"

# Disable WPAD auto-discovery fleet-wide via GPO:
# Computer Configuration > Administrative Templates > Windows Components >
#   Internet Explorer > "Disable changing Automatic Configuration settings"
# and disable "Automatically detect settings" in the browser/WinHTTP proxy config
netsh winhttp reset proxy
```

Network-wide LLMNR/NBT-NS/WPAD disablement is the actual remediation for this technique class — SMB signing enforcement (`RequireSecuritySignature`) is the necessary companion control, since it closes the relay path (`02 - Hands-On Use Cases.md`'s "Relaying Captured Auth" scenario) that makes captured NTLM material dangerous even when cracking the password itself fails. Detection rules in this note are a compensating control for environments that can't fully disable these protocols (e.g. legacy application dependencies), not a substitute for turning them off.
