# Nmap — Source Evidence

Evidence left on the **scanning/operator** host. Unlike a remote-execution tool, Nmap writes nothing to the target unless the operator explicitly saves output (`-oN`/`-oX`/`-oG`/`-oA`) — there is no "Nmap history file" separate from the shell/OS-level trail a scan leaves behind on the box it ran from. Raw-socket scan types also require elevated privilege, which itself creates a distinct audit trail most unprivileged tool use doesn't.

## Contents
- [Shell History](#shell-history)
- [Saved Output Files](#saved-output-files)
- [Live Process and Network State](#live-process-and-network-state)
- [Privilege-Escalation Audit Trail](#privilege-escalation-audit-trail)
- [Installation Artifacts](#installation-artifacts)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Shell History

| Shell | File | Notes |
|---|---|---|
| bash | `~/.bash_history` | Full command line — target ranges, every flag chosen (scan type, timing template, evasion options), and any inline `--script-args` credential material used for brute/auth NSE scripts |
| zsh | `~/.zsh_history` | Same content; `EXTENDED_HISTORY` (common default on macOS/Kali zsh setups) adds a timestamp prefix per command, directly useful for timeline building |
| fish | `~/.local/share/fish/fish_history` | YAML-structured with a native `when:` Unix timestamp per command — the easiest history to timeline-correlate if the operator used fish |

A recovered command line by itself often tells an analyst nearly everything documented in `02 - Hands-On Use Cases.md`: the scan type, the timing/evasion posture chosen, and — for `--script-args`-based brute-force runs — the exact credential list used.

## Saved Output Files

| Artifact | Notes |
|---|---|
| `.nmap` / `.xml` / `.gnmap` | If `-oN`/`-oX`/`-oG`/`-oA` was used, these files persist the **entire scan result** — full target inventory, open ports, service versions, OS guesses, and NSE script output — often left behind in an operator's working directory (`~/engagement/`, `/tmp/`, a home-lab `Desktop`) well after the scan itself is forgotten |
| `find / -iname "*.nmap" -o -iname "*.gnmap" 2>/dev/null` | Locates leftover output files anywhere on the filesystem, independent of shell history |
| Timestamps on output files | `mtime` bounds when the scan *completed* (long scans, e.g. full `-p-` UDP sweeps, can run for hours — file mtime is the finish time, not the start) |

For an intrusion or an engagement retrospective, a recovered `-oX` file is frequently more valuable than the shell history that produced it — it's the actual scan *result*, not just the command that requested it.

## Live Process and Network State

```bash
ps aux | grep -i nmap
```
While Nmap is running, `/proc/<pid>/cmdline` exposes the full invocation — including target list and any inline credentials — to any local user on a shared operator box, not just root, the same secondary-exposure risk documented for other command-line tools in this module.

```bash
ss -tnp | grep nmap
```
Raw-packet scan types (`-sS` and friends) don't create OS-tracked TCP connection-state entries the way a normal socket does, since Nmap crafts and reads packets directly rather than using `connect()` — so `ss`/`netstat` output during a `-sS` run looks sparse compared to the actual traffic volume on the wire. `-sT` (connect scan) is the exception: it drives real OS sockets, so a live `-sT` run shows a rapid succession of `SYN-SENT`/`ESTABLISHED`/`TIME-WAIT` entries in `ss` output exactly like the target-side network evidence would suggest.

## Privilege-Escalation Audit Trail

Nearly every scan type in `01 - Overview.md`'s technique table needs root/raw-socket privilege, which on most Linux distributions means the invocation ran through `sudo`:

```bash
grep -i nmap /var/log/auth.log 2>/dev/null   # Debian/Ubuntu
grep -i nmap /var/log/secure 2>/dev/null     # RHEL/CentOS
```
`sudo`'s own logging captures the **full command line**, including flags, independent of and in addition to the operator's own shell history — a second, harder-to-suppress copy of the same evidence, since clearing `.bash_history` doesn't touch the system's `sudo` log.

## Installation Artifacts

| Artifact | Command | Notes |
|---|---|---|
| Package metadata | `dpkg -l nmap` / `rpm -qi nmap` / `brew info nmap` | Confirms version — matters because NSE's default script set and `nmap-service-probes`/`nmap-os-db` content have grown across releases; an older Nmap version may lack scripts a newer one runs by default |
| Binary location | `which nmap`; `find / -iname "nmap" -type f 2>/dev/null` | Distinguishes a package-managed install from a source build or a portable/statically-linked copy staged for an engagement |
| NSE script directory | `/usr/share/nmap/scripts/` (Linux default) | Custom or modified scripts here — outside the stock set — indicate the operator built or altered NSE content specifically for this engagement |
| Npcap/WinPcap (Windows operator box) | Installer/registry evidence under `HKLM\SYSTEM\CurrentControlSet\Services\npcap` | Required for raw-socket scanning on Windows; its presence alone is a strong indicator the box is used for network scanning generally, not just this one tool |

## Memory Forensics

If the operator box is seized or imaged:
- A still-running Nmap process's memory holds the full target list and any `--script-args` credential material passed to `auth`/`brute` scripts — recoverable via a process dump (`gcore`) or full memory capture even if the on-disk shell history was cleared.
- For long scans (a full `-p-` UDP sweep against a large range can run for hours), the process may be captured mid-scan — memory analysis can recover partial results not yet written to any output file at all.

## Timeline Correlation Value

None of the artifacts above carry the same standalone weight as the target-side network-flow burst documented in `04 - Target Evidence.md` — their value is in **correlation**: matching an operator-side shell-history or `sudo`-log timestamp for `nmap -sS -T4 10.10.10.0/24` against a target-side (or perimeter-sensor) burst of single-packet, incomplete-handshake flows from that same source IP in the same window is what turns "someone ran Nmap somewhere" and "a scan hit this network" into one provable event tied to a specific operator and box.
