# Responder — Source Evidence

Evidence left on the **attacking/operator** host — the Linux (occasionally macOS) box Responder was launched *from*. Unlike a one-shot tool like `psexec.py`, Responder is a **long-running listening service** — it stays resident on the wire for the duration of the engagement, which changes the shape of its footprint: less "did this run once" and more "what did it accumulate while it ran."

## Contents
- [Log Files](#log-files)
- [Captured-Hash File Format](#captured-hash-file-format)
- [The Responder.db Database](#the-responderdb-database)
- [Live Process and Socket State](#live-process-and-socket-state)
- [Shell History](#shell-history)
- [Installation Artifacts](#installation-artifacts)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Log Files

Verified against `settings.py`'s `Settings` class, which builds `self.LogDir = os.path.join(self.ResponderPATH, 'logs')` — i.e. a `logs/` directory **relative to wherever `Responder.py` was run from**, not a fixed system path. Three session-level logs are written there, named via `Responder.conf`:

| File | `Responder.conf` key | Content |
|---|---|---|
| `logs/Responder-Session.log` | `SessionLog` | Overall session activity — startup banner, enabled modules, general run log |
| `logs/Poisoners-Session.log` | `PoisonersLog` | Every poisoned LLMNR/NBT-NS/mDNS reply sent — queried name, victim IP, timestamp |
| `logs/Analyzer-Session.log` | `AnalyzeLog` | Populated specifically by `-A` analyze-mode runs — every query *observed* without a poisoned reply being sent |

These three logs are the most direct **operator-intent evidence** on the source host: `Analyzer-Session.log` existing at all shows a recon/analyze-mode session happened; `Poisoners-Session.log` entries show exactly which names were poisoned and when, which is the most efficient way to reconstruct operator activity without parsing every individual hash-capture file.

## Captured-Hash File Format

Verified against `settings.py` (filename templates) and `utils.py`'s `SaveToDb()` function (the code that fills them in). Every captured credential is written to its own file under `logs/`, named:

```
<Module>-<Type>-Client-<VictimIP>.txt
```

For example: `SMB-NTLMv2-Client-10.10.10.5.txt`, `HTTP-NTLMv2-Client-10.10.10.12.txt`, `MSSQL-Clear-Text-Password-10.10.10.44.txt`. The `<VictimIP>` component is **not** a timestamp — it's literally the client's source IP, meaning a single victim host that authenticates multiple times produces repeated writes to the *same* file (or is skipped, depending on `CaptureMultipleHashFromSameHost` — see below), not a new file per attempt.

| `Responder.conf` setting | Default | Effect on this evidence |
|---|---|---|
| `CaptureMultipleHashFromSameHost` | `On` | Every repeat authentication attempt from an already-captured host is logged again (append), not deduplicated |
| If set `Off` | — | Repeat hashes from the same host IP are **skipped** with a `[*] Skipping previously captured hash for <ip>` console message — the *database* record's timestamp still updates even though the flat-file log doesn't grow, meaning `Responder.db` (below) can show a more complete timeline than the flat log files alone |

This filename convention is itself useful triage evidence: the **set of filenames present** in a seized `logs/` directory directly enumerates which protocols captured material during that session, without needing to open and parse each one.

## The Responder.db Database

`Responder.conf`'s `Database` key (default `Responder.db`) names a SQLite database, also created under `ResponderPATH` (the directory `Responder.py` was launched from). This is Responder's structured, queryable record of every capture — it holds the same material as the flat-file logs but is the more forensically complete source when `CaptureMultipleHashFromSameHost = Off` caused flat-file writes to be skipped (the database still records the repeat-attempt timestamp even when the text file doesn't grow). `RunFinger.py`'s own results (see `02 - Hands-On Use Cases.md`) land in a **separate** `RunFinger.db`, not this one.

```bash
sqlite3 logs/Responder.db ".tables"
sqlite3 logs/Responder.db "SELECT * FROM Responder ORDER BY id;"
```

## Live Process and Socket State

```bash
ps aux | grep -i responder
sudo ss -lunp | grep -E ':137|:5355|:5353|:445|:80|:443|:21|:389|:1433|:143|:110|:25'
```

Because Responder is long-running, `ps`/`ss` output is meaningful for far longer than with a one-shot tool — an operator box caught mid-engagement will show Responder bound to every privileged port its enabled `Responder.conf` modules use, simultaneously, which is itself a strong indicator distinct from any one protocol's normal use (no legitimate single process binds 137, 445, 389, and 1433 all at once).

## Shell History

| Shell | File | Notes |
|---|---|---|
| bash | `~/.bash_history` | The invocation line itself rarely contains credentials (Responder doesn't take a target credential argument the way `psexec.py` does) — but does reveal the interface (`-I`), flags chosen (`-w`, `-P`, `-b`, `--disable-ess`, etc.), and directly shows operator intent/aggressiveness |
| zsh | `~/.zsh_history` | Same content; timestamped by default under `EXTENDED_HISTORY` |

## Installation Artifacts

| Artifact | Command | Notes |
|---|---|---|
| Git checkout | `find / -iname "Responder.py" 2>/dev/null`, then `git -C <path> log` inside the containing repo | Most operators run Responder from a `git clone` of `lgandx/Responder` rather than a packaged install — commit hash pins down the exact feature set/flag availability in use (relevant given how much has changed across versions — see `01 - Overview.md`'s History section) |
| `Responder.conf` on disk | Diff against the repo's default `Responder.conf` | The single most information-dense artifact on the operator box — every protocol toggle, every `RespondTo`/`DontRespondTo` filter, and the exact `KerberosMode`/`Challenge` settings in use are all here, directly telling you what the operator chose to poison and what they deliberately left off |
| `certs/` directory | `ls certs/` | Populated if `HTTPS`/`LDAPS`/`IMAPS` were enabled — a self-signed cert generated locally, whose subject/issuer fields and generation timestamp can be pulled with `openssl x509 -in certs/responder.crt -noout -text` |

## OS-Level Audit Trail

If `auditd` is running with syscall auditing (uncommon by default, more likely on hardened/monitored red-team infrastructure):

```bash
ausearch -x Responder.py 2>/dev/null
```

As with any Python-invoked tool, this is the artifact class most likely to survive a `history -c` shell-history wipe, since it's generated at the kernel `execve` level rather than the shell layer.

## Memory Forensics

Because Responder is long-running and handles live credential material continuously, a memory capture of a still-running process is disproportionately valuable compared to a one-shot tool: process memory can contain **every** credential captured during the session, including ones an operator only skimmed on-screen and didn't specifically save or export, and including cleartext passwords from Basic-auth/FTP/SMTP captures that may not have been written to a persistent log file if the session was killed before a clean shutdown.

## Timeline Correlation Value

The real value of this section isn't any single artifact — it's correlating `Poisoners-Session.log` timestamps (which name was poisoned, for which victim IP, at what time) against the target-side evidence in `04 - Target Evidence.md` (the victim's own NTLM authentication attempt). A source-side poisoning entry for victim IP `10.10.10.44` at `14:02:11` matched against that same host's outbound authentication attempt in the same window is what turns "Responder ran somewhere on this segment" into a provable, specific victim-attacker pairing — the same evidentiary logic used in `Impacket/psexec/03 - Source Evidence.md`, applied here to a listening service rather than a one-shot invocation.
