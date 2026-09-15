# Hashcat — Target Evidence

**This section is deliberately thin — not an oversight.** Hashcat runs entirely offline, on the operator's own compute, against hash material that was already captured by a separate tool. It never executes code on a target, never opens a network session against one, and never sends it a single packet. There is consequently **no hashcat-specific artifact of any kind on the target/victim host** — no event log entry, no filesystem trace, no registry key, no network flow. This is the same "floor not ceiling" principle this repo's template calls for (`PLANNING.md` §3): padding this file with generic content to match the shape of every other `04 - Target Evidence.md` in this repo would misrepresent where the actual evidence lives.

## Contents
- [Where the Real Target Evidence Actually Lives](#where-the-real-target-evidence-actually-lives)
- [The One Indirect Target-Side Effect — Credential Reuse](#the-one-indirect-target-side-effect--credential-reuse)

---

## Where the Real Target Evidence Actually Lives

Every hash type this repo tracks hashcat cracking has its own **acquisition** step, and that acquisition step — not the offline cracking that follows it — is what leaves target-side evidence:

| Hash type cracked here | How it was obtained from the target | Where the target-side evidence actually lives |
|---|---|---|
| NTLM (`-m 1000`) | DCSync (MS-DRSR replication abuse) or local SAM/LSA-secrets dump | `Mimikatz/lsadump (DCSync)/04 - Target Evidence.md` — Event 4662 (directory-replication rights use), the DRSGetNCChanges RPC call pattern |
| NTLM (`-m 1000`), alternate path | `secretsdump.py` (SAM/LSA/NTDS.dit extraction) | Planned: `Impacket/secretsdump/04 - Target Evidence.md` (not yet built in this repo) |
| NetNTLMv2 (`-m 5600`) | LLMNR/NBT-NS/mDNS poisoning, victim's own outbound NTLM authentication attempt | `Responder/04 - Target Evidence.md` — Security 4625/4624, Sysmon Event ID 3 (unexpected outbound connection) |
| Kerberos TGS-REP (`-m 13100`) | Kerberoasting — requesting a service ticket for any SPN-bearing account | Planned: `Impacket/GetUserSPNs (Kerberoasting)/04 - Target Evidence.md` (not yet built) — will cover Event 4769 (Kerberos service ticket request) filtered for RC4 (etype 0x17) encryption on accounts that support AES |
| Kerberos AS-REP (`-m 18200`) | AS-REP roasting — requesting an AS-REP for a pre-auth-disabled account | No dedicated Impacket sub-tool folder planned yet (`GetNPUsers.py`) — would similarly key off Event 4768 (Kerberos TGT request) for accounts with `DONT_REQ_PREAUTH` set |

If an investigation's goal is to prove a credential was **stolen**, the evidence is in those pages, not this one. This page's only legitimate scope is what happens *after* hashcat finishes.

## The One Indirect Target-Side Effect — Credential Reuse

The single point where hashcat's work re-enters target-side visibility is not hashcat's own action but the **operator's next step**: taking a cracked plaintext password (or, separately, a relayed/pass-the-hash use of an *uncracked* hash — not a hashcat concern) and authenticating to a real target with it. That authentication attempt is standard, well-instrumented target-side evidence, fully covered elsewhere in this repo and not re-derived here:

- **Security 4624/4625** (successful/failed logon) — cross-reference `Windows/05 - Users, Groups & Authentication.md`.
- A **previously-failing credential suddenly succeeding**, timed after a plausible cracking window (see `03 - Source Evidence.md`'s Timeline Correlation Value section), is the practical signal an analyst actually chases — not anything hashcat left behind, but the shape of a successful logon appearing where none should.
- If the recovered credential is then used for lateral movement, that tool's own `04 - Target Evidence.md` (e.g. `Impacket/psexec/04 - Target Evidence.md`) takes over from there.

Treat this file as a pointer, not a dead end: the absence of hashcat-specific target evidence is itself the finding, and the cross-links above are where the investigation actually continues.
