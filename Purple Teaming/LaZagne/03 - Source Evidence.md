# LaZagne — Source Evidence

LaZagne has an unusual "source" story for the same structural reason `Seatbelt/` does: it's a **purely local** tool with no network client of its own (per `01`'s Prerequisites). In the overwhelmingly common real-world case, the host LaZagne runs on **is** the host being harvested — there is no separate "attacker's laptop" in the operation itself, only whatever got the binary there in the first place (a C2 implant, a prior lateral-movement tool, an interactive RDP session). This file covers that upstream delivery evidence and the operator-side loot trail; `04 - Target Evidence.md` covers the much richer set of artifacts left on the host LaZagne actually executed against — which, again, is usually the same machine.

## Contents
- [Delivery / Staging Evidence](#delivery--staging-evidence)
- [In-Memory Execution — a Real Constraint, Not Just an Option](#in-memory-execution--a-real-constraint-not-just-an-option)
- [C2-Side Output Capture](#c2-side-output-capture)
- [Operator Loot Handling](#operator-loot-handling)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Delivery / Staging Evidence

Because LaZagne must execute directly on the host whose secrets are being harvested, the meaningful "source" artifact is almost always **how the binary got there**, not a distinct source-host footprint of LaZagne itself:

- If staged from an attacker-controlled web server or file share, the download leaves the same evidence any file transfer does on the delivering host — HTTP/SMB access logs naming the exact filename requested (commonly `laZagne.exe` or a renamed variant — check outbound-facing web server logs on the operator's own infrastructure if seized).
- If pushed via a prior lateral-movement tool already covered in this repo (PsExec, `Impacket/psexec` or `smbexec`, an existing C2 implant's file-upload command), that tool's own `03 - Source Evidence.md` documents the transfer artifact — this note doesn't re-derive it. Cross-reference the transfer timestamp against `04`'s filesystem-drop timestamp for LaZagne itself to confirm which specific upload delivered it.

## In-Memory Execution — a Real Constraint, Not Just an Option

Unlike `Seatbelt/` (a .NET assembly, trivially reflectively loaded by Cobalt Strike's `execute-assembly`, Sliver's `execute-assembly`, or Meterpreter's .NET-execution module), a PyInstaller-built LaZagne standalone is a **native Win32 PE with an embedded Python interpreter and bytecode archive** — not a .NET assembly. A CLR-hosting in-memory loader **does not apply** to it. Genuine fileless execution requires a **generic reflective PE loader** instead (e.g. Cobalt Strike's `execute-pe` Beacon Object File-based loader, or an equivalent capability in another C2 framework) — a materially less common capability than .NET-assembly loading across the C2 landscape, which is a structural reason LaZagne shows up in incident reporting as a **dropped, disk-resident binary** far more often than as an in-memory-only execution. Where a generic PE loader genuinely is used, no dropped-binary artifact exists on the executing host at all, and `04`'s filesystem/Prefetch/Amcache findings for the binary itself won't apply — everything from `01`'s hive-save, token-impersonation, and reg.exe/netsh.exe child-process behavior still fires exactly the same, since those are runtime behaviors, not disk artifacts.

## C2-Side Output Capture

Where LaZagne is tasked and its output captured through a C2 framework rather than run interactively from a dropped `.exe`, the richer evidence trail is often on the **operator's own C2 infrastructure**, not the victim host — the same asymmetry `Seatbelt/03 - Source Evidence.md` documents for its own loader-log case:

| Framework | What's captured, and where |
|---|---|
| Cobalt Strike (`execute-pe` / a custom aggressor-script wrapper) | Beacon output logging captures whatever the loaded PE writes to stdout, stored per-beacon on the Team Server / operator client — see `../Cobalt Strike/` for that logging path in general |
| Any framework's generic "run a command, capture output" tasking | The C2's own task-history/log store retains LaZagne's full console output (equivalent to what `-oN` would have written to disk) even if the operator never touched `-oA`/`-output` at all — this is frequently the **only** surviving copy of LaZagne's results if the operator deliberately avoided writing an output file to the victim host |

An analyst with legitimate access to seized or recovered C2 operator infrastructure should treat this task-output log as a direct equivalent of a recovered `credentials_*.txt`/`.json` file — same evidentiary value, different host.

## Operator Loot Handling

If `-oA`/`-oN`/`-oJ` output **was** written to disk and later exfiltrated back to the operator (rather than only viewed via C2 task output), the resulting `credentials_<DDMMYYYY_HHMMSS>.txt`/`.json` file — recovered from the operator's own infrastructure via legal process, a seized C2 server, or threat-intel sharing — is itself a self-dating artifact: the timestamp embedded in its own filename records, to the second, when the harvesting run that produced it completed on the victim host, independent of any timestamp metadata on the file's own copy on the operator side (which reflects only when it was *received*, not generated).

## Timeline Correlation Value

For a fully local, no-network tool, the timeline-correlation value runs almost entirely in one direction: use `04`'s much richer target-side artifact set (the dropped binary's execution timestamps, the `reg.exe`/`netsh.exe` child-process timestamps, the `credentials_*` filename's embedded timestamp) as the anchor, and work backward to whichever delivery/staging or C2-tasking event in this section put the binary there in the first place. The reverse direction — using this file's thin delivery evidence to predict what LaZagne did once it ran — adds little; go to `04` directly for that.
