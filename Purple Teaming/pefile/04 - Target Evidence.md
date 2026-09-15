# pefile — Target Evidence

## No target-side evidence

**pefile leaves zero evidence on target hosts.** The tool is a local-machine analysis library that parses PE binaries already present on the operator's system. It generates no network traffic, makes no RPC calls, triggers no event logs on victim machines, and creates no artifacts beyond the attacking/analyzing machine.

The only target-side artifact is the **binary itself** — the malware sample, staged payload, or legitimate binary the operator analyzed. The binary may have reached the target via a separate mechanism (phishing, exploit, lateral movement), but pefile does not obtain it, stage it, or exfiltrate results. pefile operates entirely offline.

---

## Why target evidence is inapplicable

| Aspect | Why it doesn't apply |
|---|---|
| **No network connections** | pefile has zero networking code; it works entirely offline. Analyzed binaries are already on the analyst's machine. |
| **No RPC/SMB/LDAP calls** | pefile does not query remote systems, read registries, or enumerate directories. |
| **No authentication** | No credentials are sent, no logons are triggered. |
| **No event logs** | No Security, Sysmon, PowerShell, WMI-Activity, or other event-log entries on the target. |
| **No file modifications** | pefile is read-only by design (write support is only for overwriting fields in locally-stored PE copies). |
| **No process spawning** | pefile does not spawn child processes, threads, or remote services on any target. |
| **No registry access** | pefile does not read or modify target registries. |
| **No memory access** | pefile does not access target-machine memory (LSASS or otherwise). |

---

## Target binary as evidence

The only target-related artifact is the PE binary that was analyzed. The binary itself may be:

- **A malware sample:** discovered on the target via av/edr detection, dumped to a share, or exfiltrated
- **A staged payload:** downloaded by the target for execution (but pefile does not execute it, only parses it)
- **A legitimate binary:** copied from the target for analysis (e.g., `kernel32.dll` from a target system for fingerprinting)

**What an investigator finds on the target:**

- **The binary's presence** — if it was staged locally, it appears in filesystem forensics with creation/modification times and ACLs
- **Access logs** — if the binary was created/modified via SMB or RPC (e.g., via `Impacket/psexec/`), those tools' logs appear, not pefile's
- **Execution logs** — if the binary was executed, process-creation logs appear; pefile does not execute it

**Cross-reference needed:** If a malware binary was found on a target, investigate **how it got there** (via Impacket, Cobalt Strike, C2, etc.) — pefile's fingerprinting of the binary is forensically meaningless without knowing its origin vector.

---

## The actual attack chain context

A typical offensive workflow involving pefile looks like:

```
1. [Impacket/psexec/ or similar]    → stages payload.exe on target
2. [Target machine execution logs]  → payload.exe executes (defender sees this)
3. [Operator's machine, pefile]     → analyzes a sample of payload.exe
                                       (no target evidence at all)
```

A defender investigating the target sees only step 1 & 2. The pefile analysis (step 3) occurs entirely on the operator's disconnected machine — there is no "pefile traffic" to hunt, no "pefile event log entry" to find. The operator's machine is where all evidence of the analysis lives.

---

## Detection focus: upstream and downstream

For **hunting on the target**, focus on:

- **Upstream:** How did the binary arrive? (Impacket lateral movement, C2 staging, web download, phishing)
- **Downstream:** What did the binary do if executed? (Process creation, network connections, registry changes)

pefile itself contributes no signals to these investigations. If the binary *was* executed, standard execution forensics (process logs, memory dump, behavioral analysis) apply. If it was not executed (it was just analyzed), there are no downstream signals at all.

---

## Exception: Exfiltrated binary metadata

If pefile analysis results are written to a file that then reaches the target (e.g., via misconfigured share, accidental upload, or insider action), the target's filesystem/logs may contain evidence:

```python
# Example: Analyst script saves results to a shared drive
with open(r'\\target-server\share\analysis_report.json', 'w') as f:
    json.dump(analysis, f)
```

In this (atypical) scenario, the target's filesystem and audit logs would show:

| Artifact | Detail |
|---|---|
| **File creation on target** | `analysis_report.json` created on a network share |
| **Network SMB event (Sysmon 28 or WinRM logs)** | If remote write was over SMB, Sysmon or SMB_CLIENT_SECURITY logs show the connection and file write |

However, this is **analyst error**, not a pefile feature — the tool itself has no built-in remote-write capability. Standard file-sharing mechanisms carry the signal, not pefile.

---

## Conclusion

**For target-focused hunting:** pefile produces zero artifacts on victim machines. Focus investigative effort on:

1. **How the binary arrived** — Impacket, C2, exploit, phishing (see those tools' own 04 notes)
2. **Whether it executed** — process logs, memory forensics, behavioral analysis
3. **What it did** — network connections, registry changes, file modifications

pefile itself is transparent to target-host forensics. It's purely an **analyst's tool on their own machine**.

