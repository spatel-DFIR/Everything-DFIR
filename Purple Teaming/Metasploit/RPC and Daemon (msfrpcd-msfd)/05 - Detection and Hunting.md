# Metasploit — RPC and Daemon (msfrpcd / msfd) — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target (the Daemon as a Discoverable Service)](#hunting-on-target-the-daemon-as-a-discoverable-service)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Network-Layer Hunting](#network-layer-hunting)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

`msfrpcd` exposes real evasion/configuration flags (`-S` disables TLS, `-n` disables the database, custom ports/URIs move it off the well-known defaults); `msfd` exposes almost none, since it has no auth layer to weaken further. Rank hunts by what survives those choices, strongest first:

| Rank | Signal | Survives `-S` (no TLS)? | Survives `-n` (no database)? | Survives a non-default port? | Survives `msfd` instead of `msfrpcd`? |
|---|---|---|---|---|---|
| 1 (strongest) | The listening service's own network fingerprint (`Server: Rex` header, `health.check` response, or `msfd`'s immediate banner-on-connect) — found via a full port sweep, not a well-known-port assumption | ✅ Yes | ✅ Yes | ✅ Yes — if the hunt sweeps all ports, not just 55552–55554 | ✅ Yes |
| 2 | OS-level `auditd` execve records for `msfrpcd`/`msfd`/`ruby` on the daemon host | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| 3 | Listening/established socket state (`ss -tlnp`/`-tnp`) on the daemon host | ✅ Yes | ✅ Yes | ✅ Yes — port is whatever it is, still a listening process | ✅ Yes |
| 4 | Persistence artifact (`systemd` unit, cron entry) if the daemon was deployed to survive reboot | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes (a persisted `msfd` unit is just as findable) |
| 5 | MessagePack payload content (credentials in `auth.login`, commands in `console.write`) | ❌ **No** — only recoverable in cleartext when `-S` was used or TLS was intercepted | N/A | N/A | N/A — `msfd` traffic is *always* plaintext-console-readable unless `-s` (SSL) was used, which is off by default |
| 6 (weakest) | Framework database records (`Mdm::ApiKey` tokens, `sessions`, `hosts`) | ✅ Yes | ❌ **No** — `-n` disables the database for that instance entirely | N/A | N/A |
| 7 (weakest) | Process command-line argv showing `-U`/`-P` | N/A | N/A | N/A | N/A — defeated outright by `MSF_RPC_USER`/`MSF_RPC_PASS` env-var credential supply, which leaves no trace in `ps`/`cmdline` |

**Build hunts on ranks 1-3 as primary detections.** A full-port network sweep for the `Server: Rex` fingerprint or an `msfd` banner-on-connect is the one signal that survives every configuration choice an operator can make short of relocating the service behind a reverse proxy that strips/rewrites the `Server` header — and even then, the `health.check` MessagePack response and the distinctive error-message set (`"Invalid Content Type"`, etc.) remain. Treat ranks 4-7 as high-confidence enrichment once a candidate host is already identified, not sole detection logic.

## Hunting on Source

Applies to both the **daemon host** and, separately, the **RPC client host** — run the relevant half depending on which box is under investigation (see `03 - Source Evidence.md` for the distinction).

```bash
# --- Daemon host ---

# Process and command line — note MSF_RPC_USER/PASS env-var supply defeats the argv check
ps aux | grep -iE "msfrpcd|msfd|msgrpc"
sudo cat /proc/<pid>/environ 2>/dev/null | tr '\0' '\n' | grep -i MSF_RPC

# Listening/established sockets — sweep beyond the well-known ports too
ss -tlnp | grep -E ':55552|:55553|:55554'
ss -tnp

# Persistence
systemctl list-units --type=service | grep -i msf
crontab -l 2>/dev/null | grep -iE "msfrpcd|msfd"

# OS-level audit — survives everything above being cleaned up or obfuscated
ausearch -x msfrpcd 2>/dev/null
ausearch -x msfd 2>/dev/null
ausearch -x ruby 2>/dev/null

# Framework database, if reachable/imaged (same DB msfconsole uses)
#   SELECT token FROM api_keys;          -- permanent RPC tokens
#   SELECT * FROM sessions WHERE opened_at > ...;

# --- RPC client host ---

# Recovered automation scripts — the RPC equivalent of a resource script
find / -iname "*.py" -o -iname "*.rb" 2>/dev/null | \
  xargs grep -l "MsfRpcClient\|Msf::RPC::Client\|auth\.login\|module\.execute" 2>/dev/null

grep -iE "msfrpc|pymetasploit" ~/.bash_history ~/.zsh_history ~/.python_history 2>/dev/null
pip3 show pymetasploit3 2>/dev/null
```
If `-U`/`-P` are absent from `ps` output but a `systemd` unit or environment block shows `MSF_RPC_USER`/`MSF_RPC_PASS`, don't conclude the daemon is credential-less — check the environment path before ranking this a lower-confidence finding.

## Hunting on Target (the Daemon as a Discoverable Service)

PowerShell-first where the estate is Windows-heavy, but this hunt is fundamentally protocol-level and cross-platform — "target" here means sweeping the estate for a reachable `msfrpcd`/`msfd` instance, not a single exploited host (see `04 - Target Evidence.md`'s framing).

```powershell
# 1. Port reachability across a host list — don't assume only the three
#    documented defaults; a relocated port is a one-flag change (-p)
$targets = Get-Content .\hosts.txt
$ports   = 55552,55553,55554

foreach ($t in $targets) {
  foreach ($p in $ports) {
    if (Test-NetConnection -ComputerName $t -Port $p -InformationLevel Quiet -WarningAction SilentlyContinue) {
      "$t`:$p OPEN" | Out-File -Append .\msf_daemon_sweep.txt
    }
  }
}
```
```bash
# 2. Confirm it's genuinely msgrpc, not an unrelated service on the same port —
#    the Server: Rex header and health.check response are the fingerprint
curl -sk -o /dev/null -D - https://<host>:55553/ | grep -i '^Server:'

python3 -c "
import msgpack, sys
sys.stdout.buffer.write(msgpack.packb(['health.check']))
" | curl -sk https://<host>:55553/api -H 'Content-Type: binary/message-pack' --data-binary @-

# 3. msfd confirmation — immediate banner/prompt on connect means live,
#    unauthenticated console access
nc -w 3 <host> 55554
```
There is deliberately no Event ID/Sysmon table on this page — unlike a host-based tool, `msfrpcd`/`msfd` are network services whose primary target-side signature *is* the network fingerprint above, not a filesystem/registry/event-log artifact on a third host. Once a live instance is confirmed, pivot to `04 - Target Evidence.md`'s "Evidence of Probing or Intrusion Against the Daemon" for what a hostile connection against it looks like.

## Fleet-Wide Sweep

```powershell
# Run from a hunting workstation with network reachability across the estate —
# combine the port sweep and the health.check confirmation into one pass,
# then export for review
$targets = Get-Content .\hosts.txt
$results = foreach ($t in $targets) {
  foreach ($p in 55552,55553,55554) {
    $open = Test-NetConnection -ComputerName $t -Port $p -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($open) {
      [PSCustomObject]@{ Host = $t; Port = $p; Status = 'OPEN - verify with health.check / Server:Rex header' }
    }
  }
}
$results | Export-Csv -Path .\msf_daemon_fleet_sweep.csv -NoTypeInformation
```
Every `OPEN` result needs the manual `health.check`/`Server: Rex`/`msfd`-banner confirmation step above before being treated as a confirmed finding — a port being open only means *something* is listening, and 55552-55554 aren't reserved, so false positives from unrelated services are possible, if uncommon.

## Network-Layer Hunting

```
# Zeek: msgrpc's Content-Type is a distinctive, non-standard MIME type —
# essentially a free signature if http.log is being collected
zeek-cut ts id.orig_h id.resp_h uri mime_type < http.log | grep -i "message-pack"

# Zeek: Server: Rex response header, if not stripped by an intervening proxy
zeek-cut ts id.orig_h id.resp_h server < http.log | grep -i "^.*\tRex$"

# Zeek: repeated failed-then-successful auth pattern on the RPC port —
# each failed auth.login carries a deliberate 0.5-3.5s server-side stall,
# visible as elevated response latency on failed attempts specifically
zeek-cut ts id.orig_h id.resp_h duration < conn.log | awk '$4 > 55552 && $4 < 55555'

# Zeek: msfd has no HTTP framing at all — look for a raw TCP session on
# :55554 with an unusually large first-response payload from the server
# side (the banner + prompt), sent before the client has sent anything
zeek-cut ts id.orig_h id.resp_h orig_bytes resp_bytes < conn.log | awk '$3=="55554" && $5 > 200 && $4 < 10'
```
For environments with TLS interception/decryption in place, the plaintext MessagePack payload itself (`auth.login` credentials, `console.write` command bodies) becomes directly inspectable — without it, `-S`-disabled or `msfd`'s always-plaintext traffic is the only case where payload content is available to a passive network sensor.

## Remediation

**Capture evidence first** — export NetFlow/Zeek records for the daemon's connection history, and if the instance is still live, snapshot `service.tokens`/`Mdm::ApiKey` records and the process memory before touching anything, per `03 - Source Evidence.md`'s Memory Forensics guidance. If a hostile party has an active session against the daemon, treat every host in that daemon's `sessions`/`hosts` database tables as needing its own downstream remediation pass — same principle `../msfconsole/05 - Detection and Hunting.md`'s Remediation section uses.

```bash
# Stop the daemon
systemctl stop msfrpcd 2>/dev/null
pkill -f "msfrpcd|msfd"

# Remove persistence
systemctl disable msfrpcd 2>/dev/null
rm -f /etc/systemd/system/msfrpcd.service
crontab -l | grep -v "msfrpcd\|msfd" | crontab -

# Revoke every persistent token before re-standing the service up — a
# rotated -U/-P password does NOT invalidate previously-issued permanent tokens
msf6 > irb
>> Mdm::ApiKey.destroy_all
```
When re-deploying legitimately: bind to `127.0.0.1` and require an SSH tunnel or VPN for remote access rather than exposing `55553` directly, never run with `-S` outside a strictly loopback/isolated automation path, always supply `-U`/`-P` via environment variables rather than CLI arguments, rotate both the password and every `Mdm::ApiKey` token on any suspected exposure, and retire `msfd` in favor of `msfrpcd` entirely — there is no configuration of `msfd` that adds authentication, only network-layer allow-listing, which is not a substitute.
