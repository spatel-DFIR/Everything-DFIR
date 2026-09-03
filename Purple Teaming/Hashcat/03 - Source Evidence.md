# Hashcat — Source Evidence

Evidence left on the **cracking machine** — the operator's own workstation or dedicated GPU rig hashcat was run from. This is where nearly all of this tool's forensic value lives (see `01 - Overview.md`'s red-flag callout and `04 - Target Evidence.md`'s explicit thinness). One nuance worth stating up front: "the operator's own machine" is not always a machine outside the victim environment entirely — an attacker who has already compromised a host with a capable GPU (a workstation, a build server, a cloud compute instance stood up with stolen credentials) may run hashcat **on infrastructure the blue team does have visibility into**. Everything in this section applies whether that host is truly external or is itself a compromised asset inside the target environment; only the *investigative access* to it differs.

## Contents
- [The Potfile](#the-potfile)
- [Session / Restore Files](#session--restore-files)
- [Input Hash Files](#input-hash-files)
- [Wordlists and Rule Files — Provenance Signal](#wordlists-and-rule-files--provenance-signal)
- [.hcmask Files](#hcmask-files)
- [Outfiles](#outfiles)
- [Logfile](#logfile)
- [GPU Driver / Compute Backend Logs](#gpu-driver--compute-backend-logs)
- [Live Process and Device State](#live-process-and-device-state)
- [Shell History](#shell-history)
- [Installation Artifacts](#installation-artifacts)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## The Potfile

Hashcat's single most valuable artifact. Every successfully cracked hash is written here as `hash:plaintext` (or the mode-specific equivalent), by default at:

| OS | Default potfile path |
|---|---|
| Linux | `~/.local/share/hashcat/hashcat.potfile` (XDG data-home profile directory) |
| Windows | `%APPDATA%\hashcat\hashcat.potfile` — **not independently re-verified against the current release for this note; confirm against the actual installed version before relying on this path in a live examination** |
| macOS | `~/Library/Application Support/hashcat/hashcat.potfile` — **same caveat as Windows: verify against the actual build in use** |

Overridable per-run with `--potfile-path`, or disabled entirely with `--potfile-disable` (an operator OPSEC choice — a disabled potfile means no persistent record of successful cracks survives the session unless `-o`/`--outfile` was also used). A populated potfile on a seized machine is direct, unambiguous proof of **which specific plaintext passwords the operator recovered**, independent of what hash-mode or wordlist produced them — the strongest single artifact this tool leaves anywhere.

```bash
cat ~/.local/share/hashcat/hashcat.potfile
```

## Session / Restore Files

Named after `--session` (default session name `hashcat` if none was specified), `.restore` files live in the same profile directory as the potfile unless `--restore-file-path` overrides it, and unless `--restore-disable` suppressed them entirely. A `.restore` file's mere existence proves a job was started under that session name; its last-modified timestamp is a strong proxy for **when the job was last actively running** (checkpoints are written periodically during execution). Multiple `.restore` files with descriptive session names (`corp_ntlm_20260802`, `kerberoast_batch2`) directly enumerate distinct cracking campaigns run from this machine, similar in evidentiary role to Responder's `Poisoners-Session.log` filenames.

```bash
find ~/.local/share/hashcat -name "*.restore" -exec ls -la {} \;
```

## Input Hash Files

The files passed as hashcat's positional hash-list argument. Filenames are frequently operator-descriptive (`ntlm_dump.txt`, `SMB-NTLMv2-Client-10.10.10.44.txt`, `kerberoast_tgs.txt`) and, even when renamed to something innocuous, the **content itself is a reliable fingerprint** — each hash format has a distinctive structure:

| Format prefix/shape | Hash mode | Source tool |
|---|---|---|
| 32 hex characters, no separator | `-m 1000` NTLM | secretsdump/DCSync/SAM dump |
| `username::domain:challenge:HMAC:blob` | `-m 5600` NetNTLMv2 | Responder |
| `$krb5tgs$23$...` | `-m 13100` Kerberos TGS-REP | Kerberoasting (GetUserSPNs.py) |
| `$krb5asrep$23$...` | `-m 18200` Kerberos AS-REP | AS-REP roasting (GetNPUsers.py) |

A disk-wide grep for these literal prefixes is one of the highest-signal, lowest-effort searches available on a seized cracking host — see `05 - Detection and Hunting.md`.

## Wordlists and Rule Files — Provenance Signal

```bash
find / -iname "rockyou.txt" -o -iname "*.rule" -o -iname "*.hcmask" 2>/dev/null
ls -la /usr/share/wordlists/ 2>/dev/null   # common Kali default location
```

The **specific** wordlists and rule files present (and which ones show recent access/modification times correlating with a `.restore` file's timestamp) tell an examiner what the operator actually tried, not just that cracking happened. A custom, org-specific wordlist (`corp_terms.txt`, containing company product names, building names, or breach-derived employee-specific terms) is a stronger investigative lead than a stock `rockyou.txt` — it demonstrates targeted reconnaissance of the victim organization, not generic opportunistic cracking. Modification/access timestamps on `rules/best66.rule` or a custom rule file, cross-referenced against `.restore` file timestamps, help sequence which attack (dictionary+rules vs. mask) ran when.

## .hcmask Files

Custom `.hcmask` files (as opposed to the ones shipped with hashcat itself, e.g. `masks/8char-1l-1u-1d-1s-compliant.hcmask`) are themselves evidence of **policy-specific targeting** — an operator who built a bespoke mask file encoding a victim's exact password-complexity requirements has done reconnaissance (often via a captured password policy, a `net accounts` query, or a prior password-reset error message) that predates and informs the cracking attempt. Treat a custom `.hcmask` file the same evidentiary way as a custom wordlist: as proof of target-specific preparation, not opportunistic guessing.

## Outfiles

If `-o`/`--outfile` was used, a plaintext `hash:plaintext` (or `--outfile-format`-controlled variant) file exists independent of the potfile — often named descriptively (`cracked_ntlm.txt`, `results.txt`) and, unlike the potfile, easy to `cat`/`grep` directly without knowing hashcat's own file format conventions.

## Logfile

Hashcat writes its own run log (disabled per-run via `--logfile-disable`) recording session start/stop times, the exact command-line arguments used, and any errors — when present and not disabled, this is close to a direct transcript of operator activity, more structured than reconstructing intent from shell history alone.

## GPU Driver / Compute Backend Logs

```bash
# NVIDIA
nvidia-smi -q | grep -A5 "Utilization"
journalctl -u nvidia-persistenced 2>/dev/null
cat /var/log/Xorg.0.log 2>/dev/null | grep -i nvidia

# AMD (ROCm/HIP)
rocm-smi --showuse

# General OpenCL ICD registration (which vendor runtimes are installed)
ls /etc/OpenCL/vendors/
```

GPU utilization history (where retained by driver-level monitoring/logging) and OpenCL/CUDA/HIP ICD registration are corroborating evidence that heavy, sustained GPU compute occurred on this host during the window a `.restore` file's timestamps suggest — useful when the primary artifacts (potfile, hash files) have been deleted but driver-level telemetry survives. This is also the artifact class that matters most for the "compromised host repurposed as a cracking rig" scenario noted in this file's introduction — a workstation with no legitimate reason to sustain high GPU utilization for hours is itself a strong anomaly independent of finding hashcat's own files.

## Live Process and Device State

```bash
ps aux | grep -i hashcat
nvidia-smi   # process list includes hashcat's PID and per-GPU memory/utilization if still running
```

Because a mask/brute-force job can run for days, catching hashcat mid-execution (live-response triage of a suspected compromised host) is far more plausible here than for a one-shot tool — `nvidia-smi`'s process table directly ties a running hashcat PID to specific GPU device utilization, which `ps` alone does not show.

## Shell History

| Shell | File | Notes |
|---|---|---|
| bash | `~/.bash_history` | The invocation line reveals `-m` (target hash type — tells you what the operator had), `-a` (attack strategy), the wordlist/rule/mask files referenced, and `--session` naming — high-value for reconstructing operator intent and sequencing |
| zsh | `~/.zsh_history` | Same content; timestamped by default under `EXTENDED_HISTORY` |
| PowerShell (Windows operator) | `(Get-PSReadlineOption).HistorySavePath` | Same evidentiary value if hashcat was run from a Windows cracking rig |

## Installation Artifacts

| Artifact | Command | Notes |
|---|---|---|
| Binary/build location | `find / -iname "hashcat*" -type f 2>/dev/null` | Operators commonly run a self-built binary from a git clone, or a Kali/package-manager install (`/usr/bin/hashcat` or `/usr/share/hashcat/`) — the presence of a full source checkout vs. a bare binary hints at customization (e.g. a modified hash-mode plugin) |
| Git checkout | `git -C <path> log -1 --format='%H %cd'` | Pins the exact version/commit in use, relevant given how much has changed across releases (see `01 - Overview.md`'s History — `best66.rule` didn't always exist under that name, mode numbers have been added over time) |
| `rules/`, `masks/` directories | `ls rules/ masks/` | Which bundled rule/mask files are present (and which custom ones have been added alongside them) |

## OS-Level Audit Trail

```bash
ausearch -x hashcat 2>/dev/null
```

As with any locally-invoked tool, `auditd` execve records (where syscall auditing is enabled — uncommon by default, more likely on hardened/monitored red-team infrastructure) are the artifact class most likely to survive a `history -c` shell-history wipe, since they're generated at the kernel level rather than the shell layer.

## Memory Forensics

Process memory of a still-running hashcat instance can contain in-progress candidate state and, depending on GPU memory-mapping behavior, portions of the hash list being worked. More practically valuable: memory of the **operator's terminal/session** may retain cracked plaintexts displayed on-screen that were never written to a potfile (`--potfile-disable`) or outfile — the same "skimmed but not saved" risk noted for Responder's live captures, applicable here to cracked passwords rather than captured hashes.

## Timeline Correlation Value

The real payoff of this section is correlating `.restore`/potfile/logfile timestamps on the cracking host against:

- **Upstream** — when the hash material was actually captured/dumped (`Responder/03 - Source Evidence.md`'s `Poisoners-Session.log`, `Mimikatz/lsadump (DCSync)/03 - Source Evidence.md`'s DCSync timing, or Impacket `secretsdump.py`/`GetUserSPNs.py` output timestamps once those pages exist).
- **Downstream** — when a recovered plaintext was subsequently used against a real target, which surfaces in standard target-side authentication logs (`Windows/05 - Users, Groups & Authentication.md`) as a **new, previously-unseen credential succeeding** where prior attempts (if any) had failed.

A potfile entry timestamped between a capture event and a successful reuse event is what turns three otherwise-disconnected log entries — one on the capture-source host, one on the cracking host, one on the eventually-compromised target — into a single provable chain of custody for a stolen credential.
