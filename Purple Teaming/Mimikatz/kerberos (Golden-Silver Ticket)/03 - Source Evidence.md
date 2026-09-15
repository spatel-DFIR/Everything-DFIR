# Mimikatz — kerberos (Golden/Silver Ticket) — Source Evidence

Evidence left on the **operator's own** host — whichever machine actually ran `kerberos::golden`/`kerberos::ptt`. This module has an unusual evidentiary shape compared to its siblings: the *forging* step (`kuhl_m_kerberos_golden_data()`) is pure local computation with zero network I/O, so it leaves the same thin trail sekurlsa's local-only operations do. But the *injection* step (`kerberos::ptt`) writes the forged ticket into **this host's own LSA ticket cache** — meaning, uniquely among the techniques covered across this Mimikatz folder set, the strongest artifact isn't something the operator did, it's something now **sitting live in this machine's own session state**, recoverable the same way any cached Kerberos ticket would be.

## Contents
- [Shell History](#shell-history)
- [Dropped Binary / Loader / Ticket File Artifacts](#dropped-binary--loader--ticket-file-artifacts)
- [Live Process State](#live-process-state)
- [The Injected Ticket Itself — Local Ticket Cache](#the-injected-ticket-itself--local-ticket-cache)
- [Network Evidence](#network-evidence)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Shell History

| Shell | File | Notes |
|---|---|---|
| PowerShell | `PSReadLine` history — `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | If mimikatz was launched or scripted from PowerShell, the full command text lands here — and for `kerberos::golden`, that command line contains the **krbtgt or service account's key material in plaintext hex**, directly in the history file. This is a materially more sensitive artifact than the equivalent history line for `sekurlsa`/`lsadump` commands, which don't embed recovered secrets back into their own invocation syntax the way a forging command necessarily does |
| `cmd.exe` | No native history file | Same limitation noted throughout this folder set — nothing persists without separate console logging |
| bash/zsh (Linux operator box) | `~/.bash_history` / `~/.zsh_history` | Relevant if Impacket's `ticketer.py` (the Linux-native Golden/Silver Ticket equivalent) was used instead of mimikatz — same underlying forgery, same key-in-command-line exposure, different tool |

## Dropped Binary / Loader / Ticket File Artifacts

| Artifact | Notes |
|---|---|
| Dropped `mimikatz.exe`/`.dll` | Same as `sekurlsa (Credential Dumping)/03 - Source Evidence.md` — the binary itself, wherever staged; irrelevant if reflectively loaded |
| **`.kirbi` files** | If `/ptt` was **not** used, the forged ticket is written to disk (`/ticket:<name>`, default `ticket.kirbi`) — a durable, high-value artifact containing the complete forged ticket. Unlike a credential dump's output, a recovered `.kirbi` can be **directly replayed** by an investigator (or a second attacker) without any further cracking — treat it with the same sensitivity as a live credential |
| `.ccache` files | Present if `kerberos::ptc`/`kerberos::clist` (MIT/Heimdal interop) was used — same sensitivity as a `.kirbi` |
| Non-mimikatz forging tooling | Impacket's `ticketer.py` writes its output ccache to the path specified or the current directory by default; Rubeus's `golden`/`silver` commands behave analogously — the artifact category is the same regardless of which tool produced it |

## Live Process State

```powershell
Get-Process | Where-Object { $_.ProcessName -match 'mimikatz|ticketer' }
```
Same caveat as every sibling note in this folder set — a reflectively-loaded instance shows only as its host process (`powershell.exe`, a C2 agent), never as `mimikatz.exe` itself.

## The Injected Ticket Itself — Local Ticket Cache

**This is the artifact category unique to this module.** `kerberos::ptt` (or `kerberos::golden /ptt`) doesn't just run a command and exit — it leaves the forged ticket **resident in this host's own LSA session state** until the session ends or it's purged. If the operator ran mimikatz interactively on their own attack workstation (rather than via a remote-execution chain against a compromised pivot host), that workstation's own ticket cache now contains the forged ticket:

```powershell
klist
```
```powershell
mimikatz # kerberos::list
```
Both commands query the exact same underlying LSA state (`01 - Overview.md`) — a forged ticket appears identically to a legitimate one in either tool's output, distinguishable (if at all) only by inspecting field values a human operator would need to notice are wrong (an implausible expiry date, an account name that doesn't match the logged-on user, a `kvno` that doesn't match the domain's actual krbtgt key version). **This remains true if the injection happened on a remote/compromised pivot host reached via some other lateral-movement chain** — in that case, this same evidence lives on the pivot host, not the operator's own machine, and should be read as "target-side" evidence for that leg of the intrusion (cross-reference whichever remote-execution technique got the operator onto that host, e.g. `Impacket/psexec/04 - Target Evidence.md`).

## Network Evidence

**Sharply asymmetric depending on Golden vs. Silver — restate the split from `01 - Overview.md` here because it drives what's even worth looking for:**

| | Forging step | Using the ticket |
|---|---|---|
| Golden Ticket | Zero network traffic (pure local computation) | The **first** resource access after injection generates a real TGS-REQ to a DC (`01 - Overview.md` step 3) — visible from the operator's own host as outbound traffic to a DC on Kerberos (UDP/TCP 88), then an `AP-REQ` to the target service |
| Silver Ticket | Zero network traffic | **No DC contact ever** — the first (and only) network activity is the `AP-REQ` directly to the one target service the ticket was forged for |

```powershell
Get-NetTCPConnection -ErrorAction SilentlyContinue |
  Where-Object { $_.RemotePort -eq 88 -or $_.RemotePort -eq 464 }
```
An operator host showing an outbound connection to a Domain Controller on port 88 (Kerberos), immediately followed by a connection to an unrelated service host, in a short window after a `kerberos::golden`/`kerberos::ptt` command appears in shell history, is meaningful corroborating evidence for a Golden Ticket specifically — this pattern is **absent** for a Silver Ticket, whose only outbound connection is directly to the target service.

## OS-Level Audit Trail

If the operator's own pivot/staging box has command-line process-creation auditing enabled (Security 4688 with command-line logging, or Sysmon Event 1):
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'mimikatz|kerberos::golden|kerberos::ptt|ticketer\.py' }
```
Sysmon Event 1's `CommandLine` field, if command-line logging is enabled at the Sysmon config level, captures the **same sensitive key material** the PSReadLine history line above does — worth flagging specifically, since Sysmon logs are often retained/forwarded to a SIEM far more consistently than a user's own PSReadLine file, extending the exposure window for that recovered key well past the operator's own session.

## Memory Forensics

- Same dynamic as every sibling note: a reflectively-loaded mimikatz DLL is recoverable only via a live memory capture of its hosting process (`powershell.exe`, a C2 agent), never from disk.
- **Module-specific:** the forged ticket's plaintext contents (session key, PAC, the raw key used to build it) exist in the calling process's memory the entire time between forging and injection/file-write — a memory capture of the operator's process during that window recovers the forged ticket's full contents even if it was built and injected with `/ptt` and never touched disk at all.
- **After injection**, the ticket's encrypted form persists in `lsass.exe`'s own memory on whichever host received the injection (the operator's own box, or a remote pivot host) — recoverable via `sekurlsa::tickets` run against that host's LSASS, exactly as any other cached ticket would be (`sekurlsa (Credential Dumping)/02 - Hands-On Use Cases.md`).

## Timeline Correlation Value

Source-side evidence here splits cleanly by variant. For a **Golden Ticket**, the operator-side network evidence (outbound to a DC on 88, then to the target service), the shell-history command line (containing the exact forged identity and key), and the local ticket-cache entry together build a strong, provable chain — matched against the **target-side Event 4769-with-no-matching-4768 signature** documented in `04 - Target Evidence.md`, this is enough to tie a specific operator host to a specific forged identity and a specific DC interaction. For a **Silver Ticket**, there is no DC-side evidence to correlate against at all — the operator-side artifacts (shell history, local cache entry, the direct connection to the one target service) are the **only** record of the technique having occurred anywhere, which makes preserving them, when a compromised operator/pivot host is in scope, disproportionately important relative to how little this module's other techniques rely on source-side evidence.
