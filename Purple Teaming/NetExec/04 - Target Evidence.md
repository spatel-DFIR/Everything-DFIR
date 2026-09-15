# NetExec — Target Evidence

What an operation leaves on the **target/destination** host(s). NetExec's own `smb/wmiexec.py`, `smb/smbexec.py`, and `smb/atexec.py` are **independent Python reimplementations**, not thin wrappers around Impacket's example scripts — verified directly against the live source, and they use **different random-naming conventions** than the Impacket scripts already documented elsewhere in this repo. Where the underlying protocol/RPC mechanics are identical to an already-documented sibling page, this file cross-links rather than re-deriving them; where NetExec's own implementation differs in a checkable, evidentially relevant way, that's called out explicitly below.

## Contents
- [The Unconditional Null-Session and Admin-Check Probe](#the-unconditional-null-session-and-admin-check-probe)
- [Command Execution — Four Methods, Four Signatures](#command-execution--four-methods-four-signatures)
- [Credential/Secret Dumping Artifacts](#credentialsecret-dumping-artifacts)
- [LDAP-Side Artifacts (Kerberoasting, AS-REP Roasting, BloodHound Collection)](#ldap-side-artifacts-kerberoasting-as-rep-roasting-bloodhound-collection)
- [Event Log Summary Table](#event-log-summary-table)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint-Security-Product Behavior](#endpoint-security-product-behavior)
- [Memory Artifacts](#memory-artifacts)
- [Building a Timeline](#building-a-timeline)
- [Distinguishing NetExec from Its Impacket Siblings](#distinguishing-netexec-from-its-impacket-siblings)

---

## The Unconditional Null-Session and Admin-Check Probe

Per `01`'s red-flag callout, **every** `nxc smb` invocation against a target produces, before any real authentication attempt:

1. An anonymous SMB session-setup (`login("", "")`) — **Security 4624**, Logon Type 3, on a domain-joined target the account name resolves to `ANONYMOUS LOGON` (well-known SID `S-1-5-7`). This fires unconditionally, with no CLI flag suppressing it.
2. If `check_guest_account` is enabled in the operator's `nxc.conf` (**default: `False`**, confirmed in the shipped `nxc.conf`) — a Guest-account session-setup, a second **4624**/`4625` depending on whether Guest is enabled target-side.

Then, on **every successful real authentication** (unless `--no-admin-check` is passed):

3. A bind to the `\svcctl` named pipe over the same SMB session (IPC$), `OpenSCManagerW`, and `EnumServicesStatusW` — the exact **MS-SCMR** sequence `sc.exe` itself uses to query services, cross-link `LOLBins/sc/`. This is a **separate RPC round-trip from whatever the operator actually asked the tool to do** — it fires even on a pure credential-validation run with no `-x`/`-M` at all, purely to compute the `(Pwn3d!)` marker.

Both of these are unconditional-by-default, protocol-level behaviors independent of which module or exec-method is subsequently used — the single most reliable target-side fingerprint in this note.

## Command Execution — Four Methods, Four Signatures

`--exec-method` selects between four genuinely different mechanisms, each with its own target-side artifact set:

**`wmiexec` (default)** — `Win32_Process.Create()` over DCOM/WMI, same class of activity as `Impacket/wmiexec/`. Spawns the requested command as a child of **`WmiPrvSE.exe`**. Output is redirected to `\Windows\Temp\<gen_random_string(6)>` (a fresh random 6-character filename **on every single command**, not a session-persistent file) — a real difference from Impacket's own `wmiexec.py`, which reuses one `__<epoch-timestamp>` output file for the whole session (already documented in `Impacket/wmiexec/04 - Target Evidence.md`). NetExec's `execute_fileless()` variant goes further and redirects output to a share on the **operator's own machine** instead (`\\<operator-ip>\<random-share>\...`) — in that mode, literally nothing is written to the target's filesystem at all.

**`smbexec`** — Creates a **new service via `\svcctl`/MS-SCMR** (same RPC family as the admin check above) for **every individual command**, not once per session. Verified naming conventions, straight from `smb/smbexec.py` source:
- Service name: `gen_random_string()` with its default length of **10** — 10 random mixed-case letters, no digits (`random.sample(string.ascii_letters, 10)`). This is a **different length and character set from Impacket's own `smbexec.py`** (already documented in `Impacket/smbexec/` — cross-link that page's naming convention for the direct comparison).
- Batch file and output file: both `gen_random_string(6)` — a 6-character random name, e.g. `%TEMP%\<6-char>.bat` writing output to `\\%COMPUTERNAME%\<share>\<6-char>` (default share **`C$`**, matching this note's `01` switches table).
- The service is created, started, and deleted on every single command — the same per-command lifecycle already documented for `Impacket/smbexec/`, not a once-per-session model.

**`atexec`** — Registers a scheduled task via `\atsvc`/MS-TSCH. Verified from `smb/atexec.py` source, and genuinely distinctive:
- Task name: `gen_random_string(8)`. Output filename (when output is requested): `gen_random_string(8)`, dropped by default in **`\Windows\Temp\`**.
- **The generated task XML deliberately randomizes its own structure** — the source comment literally reads *"Random setting order to help with detection"* — shuffling the order of `<Settings>`/`<IdleSettings>` XML elements on every invocation, and separately randomizing **which of 8 equivalent `cmd.exe` path variants** is used (`cmd`, `cmd.exe`, `C:\Windows\System32\cmd.exe`, `C:\Windows\System32\..\System32\cmd.exe`, etc.) and **which of 7 equivalent argument-flag forms** (`/c`, `/C`, `/Q /c`, `/F:ON /c`, etc.). This is a genuine, source-verified, built-in anti-signature-matching measure — a static-string-match hunt against `"cmd.exe /c"` alone will miss a meaningful fraction of `atexec` invocations by design.
- **Windows Server 2025+ (build 26100) behavior differs**: the source notes that `RegistrationTrigger` no longer auto-starts a task over remote TSCH on this build, so NetExec explicitly calls `hSchRpcRun` as a fallback — worth knowing when correlating against a modern DC/member server's OS build.
- Cross-link `LOLBins/schtasks/04 - Target Evidence.md` for the full XML schema, `TaskCache` registry structure, and Event 4698/106/129/200/201 set this produces — not re-derived here.

**`mmcexec`** — Drives the existing `MMC20.Application` DCOM object rather than creating a service or task. **No service-creation, no scheduled-task, and no `\svcctl`/`\atsvc` RPC bind occurs for this method** — the only DCOM-launch artifact is whatever the DCOM/OLE activation itself logs (Microsoft-Windows-DistributedCOM Event 10016 warnings are common and non-specific), making this the quietest of the four exec methods from an event-log perspective, though the child process still spawns under `mmc.exe`.

## Credential/Secret Dumping Artifacts

- **`--sam regdump` / `--lsa regdump`**: uses Remote Registry — the service is **re-enabled and started if disabled, not newly created**, so there's no service-installation event (7045/4697) for this path, exactly the same finding already documented for `Impacket/secretsdump/`. Cross-link that page rather than re-deriving.
- **`--sam secdump` / `--lsa secdump`**: the `secretsdump`-style method, same DRSUAPI/registry-hive-copy mechanics as `Impacket/secretsdump/`.
- **`--ntds drsuapi` (default)**: DCSync-style replication — **Security 4662** with the `Replicating Directory Changes`/`...All` extended-right GUIDs on the domain object, identical mechanics to `Impacket/secretsdump/`'s `-just-dc` and `Mimikatz/lsadump (DCSync)/`. No files are dropped on the DC's own disk for this method.
- **`--ntds vss`**: creates a Volume Shadow Copy on the DC to read a locked `ntds.dit` — cross-link `LOLBins/ntdsutil/04 - Target Evidence.md` for the VSS-creation artifact set (`vssadmin`-equivalent activity, even though `ntdsutil.exe` itself is never invoked here).
- **`--dpapi`**: reads masterkey files and Credential Manager blobs under each profile's `AppData\Roaming\Microsoft\Protect\` and `Credentials\` — no execution or service artifact, purely a file-read pattern against DPAPI storage locations.

## LDAP-Side Artifacts (Kerberoasting, AS-REP Roasting, BloodHound Collection)

- **`--kerberoasting`**: requests a TGS for every SPN-bearing account discovered via an LDAP search — **Security 4769** per ticket, one encryption-type field per request (`0x17` RC4 vs. `0x11`/`0x12` AES). Full mechanics, LDAP filter, and hashcat-mode mapping already documented in `Impacket/GetUserSPNs (Kerberoasting)/` — this page does not re-derive them.
- **`--targeted-kerberoast`**: writes a temporary SPN onto the target account before roasting, then removes it — **Security 5136** (Directory Service object modified) if "Audit Directory Service Changes" + a SACL on the object are configured (non-default), the same detection gap already documented in `LOLBins/setspn/04 - Target Evidence.md` for the equivalent `setspn -S` write. **Event 4738 does not capture this** — that event tracks `msDS-AllowedToDelegateTo`, not `servicePrincipalName`.
- **`--asreproast`**: **Security 4768** issued for each `PASSWD_NOTREQD`-flagged/pre-auth-disabled account, with no preceding failed logon — distinguishable from a normal 4768 by the account's own UAC flags, not by the event itself.
- **`--bloodhound`**: a burst of LDAP search requests against the same naming contexts `BloodHound/SharpHound/` queries — if DC diagnostic-level logging is enabled (non-default, Field Engineering ≥5), **Directory Service Event 1644** may fire for the more expensive queries, the same caveat already documented in `AdFind/05 - Detection and Hunting.md` for this same DC-side visibility gap.

## Event Log Summary Table

| Event ID | Source | What it captures |
|---|---|---|
| 4624 (Logon Type 3, `ANONYMOUS LOGON`) | Security | The unconditional null-session probe on every target, every run |
| 4624/4625 | Security | Real credential attempts (matrix or paired) — a burst of these across many distinct source hosts/accounts in a short window is the spray signature |
| 5140/5145 | Security (Object Access, non-default) | Share access to `IPC$`/`ADMIN$`/`C$` and the specific named pipe (`\svcctl`, `\atsvc`, `\winreg`, `\samr`) opened |
| 7045 / 4697 | System / Security | Service creation — fires per-command for `smbexec`, **not** for `wmiexec`, `atexec`, or `mmcexec` |
| 4698 / 106 / 129 / 200 / 201 | Security / TaskScheduler-Operational | Scheduled-task lifecycle for `atexec` — see `LOLBins/schtasks/` for the full table |
| 5857 / 5860 / 5861 | WMI-Activity/Operational | WMI provider activity for `wmiexec`'s `Win32_Process.Create()` — 5860/5861 belong to event-subscription persistence, **not** this tool, per the existing `Impacket/wmiexec/` finding |
| 4662 | Security (DS Access, non-default) | DRSUAPI replication rights exercised by `--ntds drsuapi` |
| 4768 / 4769 | Security | AS-REP roasting / Kerberoasting TGT/TGS issuance |
| 5136 | Security (DS Changes, non-default) | Temporary SPN write for `--targeted-kerberoast` |
| 4103 / 4104 | Microsoft-Windows-PowerShell/Operational | `-X` PowerShell delivery — **off by default**, see `LOLBins/powershell/` for the full logging-posture caveat, which applies identically to any PowerShell NetExec pushes |
| 1644 | Directory Service (non-default) | Expensive LDAP queries from `--bloodhound` or bulk `--users`/`--computers` enumeration |

## Network-Layer Evidence

- A single `nxc` run against a range presents as **one source IP opening near-simultaneous connections to the same destination port across many distinct target IPs** (default 256 threads) — the fleet-wide fan-out pattern is itself a strong Zeek/NetFlow signal independent of protocol, distinguishable from normal one-to-one administrative traffic by connection-count-per-source-IP-per-minute alone.
- Per-protocol port set: 445 (SMB), 389/636 (LDAP/LDAPS), 5985/5986 (WinRM), 1433 (MSSQL), 22 (SSH), 3389 (RDP), plus dynamic RPC ports (135 + ephemeral) for DCOM-based `wmiexec`/`mmcexec`.
- `-6`/`--dns-server`/`--dns-tcp` — if a custom DNS server is specified, this itself is a minor anomaly (an operator's own resolver rather than the ambient network's) worth correlating against DNS query logs.

## Endpoint-Security-Product Behavior

- Because `nxc`'s own exec-method reimplementations deliberately randomize names/content (per the `atexec` XML-randomization finding above, and `gen_random_string()`'s use throughout), **static filename/string signature matching against the tool's own output artifacts is inherently unreliable** — EDR products instead tend to fingerprint the **behavioral pattern** (a single source host performing bulk SVCCTL/ATSVC/WMI activity against many destinations in a short window, or a single account's SMB session immediately followed by a service-create-start-delete cycle) rather than any fixed string.
- `--obfs`/`--amsi-bypass`/`--no-encode` on the PowerShell delivery path directly target AMSI/Defender-static-scan detection — cross-link `LOLBins/powershell/` for what AMSI actually does and doesn't see for a `-X`-delivered command.
- `nanodump` (a module, not a core exec method) is explicitly built around indirect syscalls specifically to survive AV/EDR hooking of the direct `MiniDumpWriteDump` call path — a materially different evasion posture than the LSASS-access pattern `sekurlsa` in `Mimikatz/` produces.

## Memory Artifacts

Because NetExec drives *remote* execution/dumping rather than running code in-process on the target (with the narrow exception of whatever `-x`/`-X`-delivered command itself does), target-side memory forensics is really about **the artifacts of the delivery mechanism**, not NetExec's own memory footprint:

- `wmiexec`/`mmcexec`: the spawned `WmiPrvSE.exe`/`mmc.exe` child process's own memory, same as any `Impacket/wmiexec/`-style intrusion.
- `-X` PowerShell delivery: the target `powershell.exe`/`pwsh.exe` process holds the decoded command in memory for the process's lifetime — AMSI's own scan buffer (where AMSI is engaged at all) is the most durable in-memory trace of the actual script content pushed, independent of whatever on-disk logging is or isn't enabled.
- `lsassy`/`nanodump`/`handlekatz` modules: whatever the underlying dumping technique's own memory-forensics profile is — `nanodump`'s indirect-syscall approach specifically minimizes the handle-access pattern Sysmon 10/ProcessAccess would otherwise catch against `lsass.exe`.

## Building a Timeline

1. Start from the source-host workspace database timestamp (`03 - Source Evidence.md`) for the intended scope/order of targets.
2. Anchor on the unconditional 4624 `ANONYMOUS LOGON` event — it fires on **every** target regardless of exec method or module, making it the most reliable "NetExec (or CrackMapExec) touched this host at this exact time" marker to search first.
3. Correlate the subsequent real-credential 4624/4625 within the same short window (same source IP, immediately following the anonymous logon).
4. If admin rights were confirmed (`(Pwn3d!)`), look for the `\svcctl` bind/`EnumServicesStatusW` call in the same session — present even on runs with no further execution requested.
5. Branch by whichever exec-method/module signature from the sections above actually fired, using the per-method artifact set to place the specific action in time.

## Distinguishing NetExec from Its Impacket Siblings

| | NetExec (`--exec-method smbexec`) | `Impacket/smbexec/` |
|---|---|---|
| Service name | `gen_random_string()`, default 10 random letters | Documented separately in `Impacket/smbexec/` — different length/charset, confirm against that page rather than assuming parity |
| Output share | `C$` (default, `--share` to override) | `C$` (already corrected from an earlier assumed `ADMIN$` in that page's own build) |
| Lifecycle | New service per command, then deleted | New service per command, then deleted — same per-command model |

| | NetExec (`--exec-method wmiexec`, default) | `Impacket/wmiexec/` |
|---|---|---|
| Output file | Fresh `gen_random_string(6)` **per command** | One `__<epoch-timestamp>` file reused for the **whole session** |
| Fileless variant | `execute_fileless()` relays output to a share on the **operator's own** machine — nothing written to target disk at all | No equivalent fully-fileless mode documented |

Where a target's evidence set doesn't cleanly match either this page's or the corresponding `Impacket/` page's naming convention, that's a real signal worth investigating on its own — it may indicate a different tool entirely, a modified/forked build, or a version skew from what was verified here.
