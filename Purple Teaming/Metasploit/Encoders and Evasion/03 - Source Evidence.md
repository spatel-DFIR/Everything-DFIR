# Metasploit — Encoders and Evasion — Source Evidence

Everything in this file happens on the **operator/attacking host** — like `../msfvenom/03 - Source Evidence.md`, encoders and evasion modules both generate entirely locally; nothing here touches a target until a separately-delivered file is executed there (covered in `04 - Target Evidence.md`).

## Contents
- [Shell / Command History](#shell--command-history)
- [msfconsole History and Datastore](#msfconsole-history-and-datastore)
- [Local Generated-File Artifacts](#local-generated-file-artifacts)
- [Local Network-Connection State](#local-network-connection-state)
- [Process Artifacts](#process-artifacts)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics Angle](#memory-forensics-angle)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Shell / Command History

A `msfvenom -e <encoder>` invocation leaves the same shell-history footprint as any other msfvenom command — `~/.bash_history`, `~/.zsh_history`, or equivalent, containing the full command line including the encoder name, iteration count, and every other flag. This is the single richest source-side artifact: the `-e`/`-i`/`-b` flags directly answer *why* an operator reached for encoding (static-evasion attempt vs. bad-character avoidance for exploit dev), which shapes how the resulting file should be triaged on the target side. Same caveats apply as `../msfvenom/03 - Source Evidence.md`: history is trivially clearable (`unset HISTFILE`, `history -c`), off by default in some non-interactive automation contexts, and absent entirely if the operator used a resource script or a different shell configuration.

## msfconsole History and Datastore

Where an encoder or evasion module was invoked from inside `msfconsole` (`use encoder/...` / `use evasion/...`) rather than via the `msfvenom` CLI, the console's own command history file — `~/.msf4/history` — captures every line typed at the `msf6 >` prompt, including `use`, `set PAYLOAD`/`set LHOST`/`set FILENAME`, and `generate`/`exploit`. This is the msfconsole-native equivalent of shell history and should be checked alongside it; an operator working entirely inside an interactive console session leaves nothing in `~/.bash_history` at all. If `setg` was used to persist `LHOST`/`LPORT` globally before loading the encoder/evasion module, `~/.msf4/config` (written on `save`) can retain that operator infrastructure even after the specific module invocation has scrolled out of scrollback — same mechanic documented in `../msfconsole/03 - Source Evidence.md`, not re-derived here.

## Local Generated-File Artifacts

- **Encoder output via msfvenom (`-o <path>`)** — the finished file (`.exe`, raw shellcode, source-code transform, etc.) written wherever the operator specified, or to stdout if `-o` was omitted (in which case the file only exists downstream of a shell redirect or pipe, and the local artifact is whatever received that stdout).
- **Evasion module output** — per this pass's research (`01 - Overview.md`'s How It Works), evasion modules write their generated file to the operator's **local Metasploit directory, `~/.msf4/local/`, by default**, using a random filename unless `FILENAME` was explicitly set. This directory is worth a direct filesystem check independent of shell/console history — a `FILENAME` value or a randomly-named file's timestamp can corroborate or fill gaps in the history-based timeline.
- **Intermediate raw-shellcode files** — in a chained-encoding workflow (`../02 - Hands-On Use Cases.md`'s "Chained Multi-Encoder Pipeline"), if the operator wrote intermediate `-f raw` output to disk between pipeline stages rather than piping directly, those intermediate files are additional artifacts, each independently timestamped.

## Local Network-Connection State

Encoders and evasion-module generation are **zero-network-activity** operations — same as msfvenom's own generation step (`../msfvenom/03 - Source Evidence.md`). There is nothing to find in local connection state (`netstat`/`ss`) attributable to the encoding/evasion-generation step itself. Network-connection evidence only appears once the *delivered* payload calls back — at that point, `04 - Target Evidence.md`'s network-layer section and the wrapped payload's own protocol coverage (`../Meterpreter/03 - Source Evidence.md` for the handler side) become relevant, not this file.

## Process Artifacts

- **`msfvenom` process** — a short-lived Ruby process invocation, visible only while generation is actually running (typically sub-second for a single encoder pass; longer for `--smallest` which tries every available encoder, or high iteration counts).
- **`msfconsole` process** — long-running for the duration of the interactive session; an encoder/evasion module loaded inside it doesn't spawn a distinguishable child process of its own — the encoding/generation work happens inside the existing `ruby`/`msfconsole` process.
- **Evasion-module-specific tooling** — some evasion modules invoke an external compiler as part of generation (e.g. `windows_defender_exe`'s "custom compiler" per its own documentation). Where that's the case, expect a short-lived child process (compiler binary) under the `msfconsole`/`ruby` parent during the `exploit`/`run` step — this is module-specific and not verified in detail for every `evasion/windows/*` module in this pass, consistent with the deferred deep-dive noted in `01 - Overview.md`.

## OS-Level Audit Trail

On a Linux/macOS operator box with `auditd` (or equivalent) execve logging enabled, both `msfvenom` and `msfconsole`/`ruby` process launches are captured independent of shell history — the same durable, harder-to-suppress signal class documented for other Metasploit sub-tools in this module (e.g. `../RPC and Daemon (msfrpcd-msfd)/03 - Source Evidence.md`'s OS-level audit coverage). This is the standard route to recovering encoder/evasion-module usage evidence when history has been cleared.

## Memory Forensics Angle

Encoding and evasion-module generation are transient, in-memory-then-written-to-disk operations — by the time an investigator has access to the operator host, the generation process has almost always already exited and the interesting artifact is the **output file**, not process memory. The narrow exception: if the operator host itself is imaged while `msfvenom` or `msfconsole` is actively mid-generation (a race unlikely to be caught in practice), process memory would briefly contain the raw, pre-encoded payload bytes alongside the encoder's working buffers — of academic rather than practical investigative value given the operation's speed.

## Timeline Correlation Value

The generation timestamp (file mtime on the output artifact, or the shell/`msf4/history` line timestamp) is the anchor point that ties an operator's local encoding/evasion-generation activity to the **delivery and execution timeline on the target** built in `04 - Target Evidence.md`. Because msfvenom and evasion modules perform zero network activity of their own, there is no natural network-layer link between "generated at T0 on the operator box" and "executed at T1 on the target" — that link has to be established through the delivery mechanism (file transfer logs, a phishing timeline, a LOLBin download) or through content-based correlation (matching hash/structural fingerprint between the source-side output file and the target-side dropped file), not through any evidence intrinsic to the encoding step itself.
