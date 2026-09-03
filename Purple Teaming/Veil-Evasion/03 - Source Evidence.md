# Veil-Evasion — Source Evidence

What an operation leaves on the **operator's own Linux host** — verified against `Veil-Framework/Veil`'s `config/update-config.py` (default path config) and `tools/evasion/tool.py`/`outfile.py` (output-write behavior).

## Contents
- [Output Directory Structure](#output-directory-structure)
- [Installation Footprint](#installation-footprint)
- [Shell/Command History](#shellcommand-history)
- [Process Artifacts](#process-artifacts)
- [Network Connection State](#network-connection-state)
- [Memory Forensics](#memory-forensics)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Output Directory Structure

Verified directly against `config/update-config.py`'s default option values — these are the framework's own defaults, applied unless the operator explicitly reconfigures via `--setup`/`--config`:

| Path | Contents |
|---|---|
| `/var/lib/veil/output/source/` | Every generated payload's source code (Python/PowerShell/Ruby/etc., pre-compilation) |
| `/var/lib/veil/output/compiled/` | Every compiled artifact (PE binaries, etc.) |
| `/var/lib/veil/output/handlers/` | Auto-written Metasploit `.rc` resource files, one per `generate` run where `LHOST`/`RHOST` were set |
| `/var/lib/veil/output/hashes.txt` | **A running, append-only log of the hash and filename of every payload the tool has ever generated on this host** — the single strongest source-side artifact in this module: it directly ties an operator's host to every payload it has ever produced, with no `--clean` run needed to remove it (only `--clean`/`clean` inside the menu purges it) |
| `/etc/veil/settings.py` | The framework's configuration file — install paths, compiler paths, output-directory overrides |
| `/tmp/` (`TEMP_PATH` default) | Intermediate build artifacts during compilation |
| `/var/lib/veil/wine/` | A Wine prefix, present only if Ruby payloads were ever generated (Ruby's OCRA compiler runs under Wine even on a Linux operator host) |
| `/var/lib/veil/PyInstaller-3.2.1/`, `/var/lib/veil/go/` | Bundled per-language toolchains installed by `config/setup.sh` |

Recovering `hashes.txt` alone reconstructs a complete history of every payload variant an operator built from that host — including ones never actually deployed.

## Installation Footprint

- **Kali package install:** `apt install veil` places the framework under `/usr/share/veil/`; `dpkg -l | grep veil` or `apt list --installed | grep veil` confirms package presence directly.
- **Manual git clone:** a working directory anywhere on disk containing `Veil.py`, `lib/`, `tools/evasion/`, `tools/ordnance/` — recognizable by directory structure alone even without the package-manager record.
- **Setup-script side effects:** `config/setup.sh` pulls and installs PyInstaller, a Go toolchain, and a Wine prefix with a bundled Ruby install — each is a standalone forensic artifact on the operator's host independent of whether any payload was ever generated, and each is unusual enough (a Wine-hosted Ruby install specifically for payload compilation) to warrant investigation on its own.

## Shell/Command History

- Every `Veil.py -t Evasion -p ... --ip ... --port ...` CLI invocation lands in `.bash_history`/`.zsh_history` (or shell-specific equivalents) in full, including the callback `LHOST`/`LPORT` values and the exact payload-module path chosen — directly readable operator intent if history wasn't cleared.
- Interactive menu sessions (`use`/`set`/`generate`) are **not** captured in shell history the same way — only the single `Veil.py` launch line is. Recovering the menu-session detail instead requires either a captured terminal transcript/`script(1)` recording, or reconstructing from the `source`/`compiled`/`hashes.txt` output artifacts themselves (which do carry the `LHOST`/`LPORT` values baked into the generated payload).
- `readline` history specific to Veil's own interactive prompt (`Veil>:`, `Veil/Evasion>:`, `[path>>]:`) is not persisted by the tool itself — it relies on the terminal's own scrollback/session logging, not a Veil-specific history file.

## Process Artifacts

- **Parent process:** `python3 Veil.py` (or `python3 /usr/share/veil/Veil.py` on a Kali package install) as the long-running interactive session, or a short-lived instance per CLI invocation.
- **Compiler child processes**, spawned per `generate`/`run`: `pyinstaller` (Python payloads), a native compiler (`gcc`/`mingw`-class toolchain for C/C#/native/AutoIt), the Go toolchain (`go build`), or `wine ... ruby.exe ocra ...` for Ruby payloads (Wine hosting a Windows Ruby interpreter and the OCRA compiler specifically to produce a Windows PE from a Linux host).
- **`checkvt`'s child process:** `tools/evasion/scripts/vt-notify/vt-notify.rb -f /var/lib/veil/output/hashes.txt -i 0` — a Ruby subprocess invoked directly from `tool.py`'s `check_vt()` method, confirmed in source.
- Any of these process names appearing as children of an interactive Python session on a Linux host — especially the Wine/Ruby-cross-compile chain, which has no ordinary reason to exist outside this kind of tooling — is a strong environmental tell independent of any specific Veil artifact.

## Network Connection State

- **`checkvt` egress:** a real, source-confirmed outbound HTTPS connection from the operator's own host to VirusTotal's API, triggered any time the operator runs `checkvt` from the Evasion menu. This is incidental OPSEC self-check traffic, not payload delivery — but it is a genuine network artifact tying the host to Veil usage, and it also means the operator's own payload hashes were submitted to a third party (VirusTotal) as a side effect of using the tool as documented.
- **No other Veil-originated network traffic exists on the operator side by default** — payload generation and compilation are entirely local; the eventual C2 callback traffic is generated by the *target*, not the operator's Veil process, and belongs in `04 - Target Evidence.md` instead.

## Memory Forensics

- While `Veil.py` is running, the process's own memory holds the full, unencrypted payload source/shellcode for every module currently in use — including any embedded AES/RC4/DES key before it's written to the obfuscated output file. A memory capture of a live Veil session recovers cleartext payload material that the compiled output deliberately obscures.
- PyInstaller/native-compiler child processes hold the equivalent build-time artifacts in their own memory for the (typically brief) duration of compilation.

## OS-Level Audit Trail

- **`auditd`** (if configured with an execve-watching rule) records every `python3`, `pyinstaller`, `wine`, and compiler-toolchain invocation with full command-line arguments — the most complete non-Veil-specific record of a generation session, since it captures the exact `-p`/`--ip`/`--port` arguments from CLI-mode runs and every compiler child-process spawn from either mode.
- **Package-manager logs** (`/var/log/apt/history.log` on Debian/Kali) record the original `apt install veil` timestamp, independently corroborating when the tool was first available on the host.
- **Filesystem `mtime`/`ctime`** on everything under `/var/lib/veil/output/` and `/etc/veil/settings.py` provide a coarse but reliable generation timeline even without process-level logging.

## Timeline Correlation Value

`hashes.txt`'s append-only, timestamped-by-filesystem-metadata structure is the anchor artifact for correlating operator-side activity against target-side detonation: each entry's on-disk write time (cross-referenced against the corresponding file's `mtime` in `compiled/`) establishes exactly when a given payload variant was built, which can then be matched against the earliest AV/EDR detection timestamp or process-creation event for that same file hash on the target side (`04 - Target Evidence.md`). Because the hash itself is stable and the tool writes it automatically with no operator effort required to preserve it, this is a higher-confidence timeline anchor than shell history alone, which depends on the operator not having cleared it.
