# Impacket — ntlmrelayx.py — Overview

> 🔴 **Red Flag Principle:** `ntlmrelayx.py` never cracks, guesses, or even sees a plaintext password — it forwards someone else's live NTLM authentication attempt, unmodified, to a target the victim never intended to talk to. The tell is a **mismatch between the authenticating identity and the connecting infrastructure's own identity**: Target B sees a successful logon "from" a workstation/service that never actually ran that logon, over a connection whose source doesn't match the identity presented (Victim's credentials, Attacker's IP, Target B's session). Structurally, this whole technique lives or dies on one setting per protocol — **SMB session signing** and **LDAP signing/channel binding**. If the target enforces either, relay to that specific protocol fails outright; the tool's own source code says as much: *"The only way to stop this attack is to enforce on the server SPN checks and or signing."*

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

`ntlmrelayx.py` lives in [`fortra/impacket`](https://github.com/fortra/impacket)'s `examples/` folder, same CORE Security → HelpSystems → Fortra lineage as every other tool already covered in this `Impacket/` folder. Its current source header credits three authors: **Alberto Solino (`@agsolino`)**, **Dirk-jan Mollema / Fox-IT**, and **Sylvain Heiniger / Compass Security**.

The lineage claim in this note's brief — that `ntlmrelayx.py` is the generalized successor to an earlier single-purpose `smbrelayx.py` — is verified directly against the repo's `ChangeLog.md`. Under the **Impacket v0.9.15 (June 2016)** release notes, in the "New Examples" section, the project's own changelog entry reads verbatim:

> `ntlmrelayx.py`: `smbrelayx.py` on steroids!. NTLM relay attack from/to multiple protocols (HTTP/SMB/LDAP/MSSQL/etc) (by @dirkjanm)

That same v0.9.15 changelog entry is also the **last** place `smbrelayx.py` is mentioned at all — every changelog entry after it references only `ntlmrelayx.py`. Confirmed live against the current `examples/` directory listing: **`smbrelayx.py` no longer exists in the repository.** The lineage is real and documented in the project's own history, not an inference: `smbrelayx.py` did SMB-to-SMB relay only; `ntlmrelayx.py` generalized the same core relay engine to arbitrary source/target protocol pairs and was eventually the only one of the two kept.

The tool's own module docstring states its scope plainly: *"This module performs the SMB Relay attacks originally discovered by cDc extended to many target protocols (SMB, MSSQL, LDAP, etc). It receives a list of targets and for every connection received it will choose the next target and try to relay the credentials... It is supposed to be working on any LM Compatibility level. The only way to stop this attack is to enforce on the server SPN checks and or signing."* That last sentence is the structural detection/defense principle this entire note is organized around.

Two source-verified, dated developments worth flagging up front because they show up as real CLI flags (covered below): **`--remove-mic`** exploits **CVE-2019-1040** (a message-integrity-code removal that enabled certain cross-protocol relay scenarios, patched by Microsoft in June 2019), and **`--remove-sign-seal`** exploits **CVE-2025-33073** (an NTLM-reflection technique — relaying a victim's authentication back to the same machine it came from — that strips the NTLMSSP SIGN/SEAL flags while preserving the MIC; Microsoft patched this in June 2025, and independent write-ups note that **SMB signing enforcement defeats it too**, same as every other SMB-relay variant this note covers).

## How It Works

### The step this note does *not* re-derive: getting an inbound authentication attempt at all

`ntlmrelayx.py` is a **relay** engine — it needs a live, in-progress NTLM authentication handshake arriving at one of its listening servers before it has anything to relay. That inbound handshake has to come from somewhere, and this note treats *how* it arrives as an upstream, out-of-scope step covered by other sub-tools/pages already built in this repo:

- **LLMNR/NBT-NS/mDNS poisoning** — a victim's own broadcast name-resolution fallback gets hijacked and pointed at the relay operator's host. Full mechanics: `Responder/01 - Overview.md` and `Responder/02 - Hands-On Use Cases.md`'s "Relaying Captured Auth Instead of Cracking It" use case, which shows the exact `Responder.conf` SMB/HTTP-off handoff into `ntlmrelayx.py`.
- **Authentication coercion** — PetitPotam (MS-EFSRPC `EfsRpcOpenFileRaw`), PrinterBug (MS-RPRN), ShadowCoerce (MS-FSRVP), or similar primitives that force a **specific machine account** (often a Domain Controller) to authenticate to an attacker-chosen host on demand, rather than waiting for organic broadcast traffic. MITRE catalogs this class of technique as **[T1187 — Forced Authentication](https://attack.mitre.org/techniques/T1187/)**, which explicitly names the EFSRPC/PetitPotam pattern as an example feeding directly into NTLM relay.
- **Organic cross-protocol auth** — some legitimate client behavior (an admin tool probing a stale name, a service account with a misconfigured target) triggers an authentication attempt that simply arrives at the relay listener without any active coercion at all.

None of these are `ntlmrelayx.py`'s own mechanics — this note picks up **after** an NTLM negotiation is already inbound.

### Protocol sequence — capture, relay, and the race against the clock

```
Victim                    ntlmrelayx.py (attacker,                    Relay Target
                           listening server)                          (Target B)
──────                    ────────────────────                       ────────────
1. Coerced or organic
   connection attempt ──▶ Listening server (SMB/HTTP/WCF/RAW/
                           RPC/WinRM/MSSQL/RDP — whichever is
                           enabled) accepts the connection

2. NTLM Type 1
   (NEGOTIATE_MESSAGE) ─▶ Received, and this exact NEGOTIATE
                           blob is forwarded, essentially
                           unmodified, to Target B ─────────────────▶ Target B's own
                                                                       auth stack processes
                                                                       it as if it came
                                                                       from a real client
                        ◀────────────────────────────────────────── Target B issues an
                                                                       NTLM Type 2
                                                                       (CHALLENGE_MESSAGE)
                                                                       containing a random
                                                                       server challenge

3. That SAME challenge
   is relayed back to
   the victim ◀───────── ntlmrelayx.py's listening server
                           passes Target B's exact challenge
                           back to the victim as its own
                           Type 2 response

4. NTLM Type 3
   (AUTHENTICATE_MESSAGE)
   — victim computes the
   correct response using
   its real password/hash
   against Target B's
   challenge, believing it
   is authenticating to
   ntlmrelayx.py ────────▶ Captured, and immediately
                            forwarded to Target B ──────────────────▶ Target B validates
                                                                       the response against
                                                                       its own challenge —
                                                                       IT MATCHES, because
                                                                       the relay never
                                                                       altered the exchange
                                                                       ◀── AUTH SUCCEEDS

5. Post-auth: ntlmrelayx.py now holds an authenticated
   session AS THE VICTIM against Target B — either drops
   into an interactive shell (-i) or fires whatever attack
   module matches Target B's protocol (see below)
```

The entire technique depends on **timing, not cryptography** — the operator never decrypts or derives the victim's password/hash at any point; they simply act as a transparent relay for one specific challenge-response exchange and have to complete steps 2-4 **before the victim's own client gives up waiting** (a matter of seconds in practice). This is also why `ntlmrelayx.py`'s own docstring says it works "on any LM Compatibility level" — the relay doesn't care which NTLM version or LM-compat setting is negotiated, because it never needs to solve the challenge itself.

### What happens once relay succeeds — interactive shell vs. attack module

Two distinct post-auth behaviors, selected by CLI flags:

- **`-i`/`--interactive`** — launches a locally-listening `smbclient`, LDAP console, or SQL shell (protocol-dependent) that an operator reaches over a local TCP port with something like `nc`, instead of running a fixed command.
- **Default (no `-i`)** — each relay-target protocol has its own **attack module**, verified directly against the current `impacket/examples/ntlmrelayx/attacks/` package listing on GitHub (not assumed from older write-ups, several of which are now out of date):

| Target protocol (client) | Attack module | Default behavior |
|---|---|---|
| SMB | `smbattack.py` | **Dumps local SAM hashes only** (`RemoteOperations.saveSAM()` → `SAMHashes`, the same primitive `secretsdump.py`'s Path 1 uses for its SAM leg — see `Impacket/secretsdump/01 - Overview.md`), unless `-c`/`-e` (run a command/drop a file) or `-i` is given. Verified directly in `smbattack.py`'s default branch: **no `LSASecrets`/`saveSecurity()` call exists in this path** — this is narrower than `secretsdump.py`'s combined SAM+LSA+cache default, an easy detail to get wrong from memory alone |
| HTTP(S) | `httpattack.py` + `httpattacks/adcsattack.py`, `sccmpoliciesattack.py`, `sccmdpattack.py` | Base HTTP relay; **ADCS** web-enrollment abuse (ESC8) via `--adcs`, **SCCM Management Point** secret-policy dump via `--sccm-policies`, **SCCM Distribution Point** package-file dump via `--sccm-dp` |
| LDAP(S) | `ldapattack.py` | By default: dumps directory info, then **prefers an ACL attack over a group-membership attack** — verified in `ldapattack.py`'s `run()`: it grants `DS-Replication-Get-Changes-All` directly on the domain object to an escalated/created user via a raw `nTSecurityDescriptor` write (`--no-acl` to suppress; the tool's own log calls this "more quiet"), and only falls back to literally adding an account to a privileged group (`--no-da` to suppress) if the relayed identity has group-add rights but not ACL-write rights. Both are default-enabled and can both fire in the same run. Also implements **RBCD grant** (`--delegate-access`, writes `msDS-AllowedToActOnBehalfOfOtherIdentity`), **Shadow Credentials** (`--shadow-credentials`, writes `msDS-KeyCredentialLink`), and LAPS/gMSA/ADCS-template/pre-Windows-2000-account enumeration dumps |
| DCSync (relay-only target) | `dcsyncattack.py` (a no-op stub) → the real work is in `clients/dcsyncclient.py`'s `DCSYNCRelayClient` | **Not a vanilla relayed DRSUAPI pull.** Verified live in `dcsyncclient.py`: DRSUAPI requires a signed+sealed RPC context that a pure relay cannot produce, so this client instead executes the **Zerologon exploit (CVE-2020-1472)** against the target DC's own Netlogon RPC service — an unauthenticated `NetrServerReqChallenge`/`NetrServerAuthenticate3` loop with an all-zero client credential, up to 6,000 attempts — to derive a usable Netlogon session key, then reuses that key as the DRSUAPI signing/sealing key before calling `secretsdump.py`'s own `NTDSHashes` class. Only fails ("Target likely patched!") against a DC enforcing Netlogon secure-channel signing (Microsoft's default since the Feb 2021 enforcement phase). With only the relayed credential (no `-auth-smb`), it dumps just three named accounts — `krbtgt`, the DC's own machine account, and `Administrator` — not the full domain; a full `-just-dc`-equivalent pull requires separately supplied working SMB creds via `-auth-smb`/`-hashes-smb`. The relayed victim's own privilege level is irrelevant to success, since the actual bypass is Zerologon against Netlogon, not a DS-Replication-Get-Changes-All check. Full mechanics in `02 - Hands-On Use Cases.md` and `04 - Target Evidence.md` |
| MSSQL | `mssqlattack.py` | Interactive SQL shell (`-i`) or query execution (`-q`) |
| RPC (named-pipe or raw) | `rpcattack.py` | `TSCH` mode (default) — Task Scheduler remote command execution, same primitive as `atexec.py`; `ICPR` mode — certificate enrollment via the raw **MS-ICPR** RPC interface instead of HTTP (an RPC-transport alternative to the ADCS HTTP/ESC8 path above) |
| IMAP(S) | `imapattack.py` | Searches/dumps mailbox contents for a keyword (default: `password`) or dumps everything with `-a` |
| WinRM | `winrmattack.py` | Interactive PowerShell-equivalent session |

**`-socks` mode is a distinct, third behavior**, layered on top of either of the above: instead of firing one fixed attack automatically, `ntlmrelayx.py` spins up a local **SOCKS5 proxy** (default `127.0.0.1:1080`) plus an HTTP control API (default port `9090`) that keeps each successfully relayed session alive and reachable, letting an operator point **any other tool** (`secretsdump.py`, `smbclient.py`, NetExec, a browser) through the still-live authenticated session on demand — useful when the value of a relayed session isn't known until later, or when multiple relayed identities need to stay available simultaneously rather than one attack firing once and the session ending. `--keep-relaying` extends this further by continuing to relay to a target even after one relay has already succeeded against it.

### SMB session signing and LDAP signing/channel binding — the structural defense

Verified directly in `impacket/examples/ntlmrelayx/clients/smbrelayclient.py` and `ldaprelayclient.py`:

- **SMB relay** — the client checks the target's negotiated `SMB2_NEGOTIATE_SIGNING_REQUIRED` flag (or `RequireMessageSigning` for SMB1) **before** attempting the relay. If signing is required, the tool logs `'Signing is required, attack won't work unless using -remove-target / --remove-mic'` and the relay to that target fails. **This is a hard, structural stop for plain SMB relay** — signing means every SMB packet after session setup carries a cryptographic signature keyed to the session key from the *real* authentication, which a relay operator never possesses. `--remove-mic` (CVE-2019-1040) and `--remove-sign-seal` (CVE-2025-33073) are narrow, patched bypasses for specific scenarios (cross-protocol relay and same-host reflection, respectively) — **neither is a general defeat of SMB signing enforcement on a fully patched target**, and both are moot the moment the target enforces signing and is patched.
- **LDAP relay** — relaying to plain LDAP (port 389, `-t ldap://...`) against a Domain Controller that enforces **LDAP server signing** fails with the LDAP server's own `RESULT_STRONGER_AUTH_REQUIRED` response; the tool's client code detects this and logs an explicit suggestion: *"Server rejected authentication because LDAP signing is enabled. Try connecting with TLS enabled (specify target as ldaps://hostname)"*. **This is the critical nuance:** LDAP signing enforcement blocks plain LDAP relay but does **not**, by itself, block relay to **LDAPS** (port 636, `-t ldaps://...`), because LDAPS's TLS layer supersedes the need for LDAP-level packet signing. What **does** block LDAPS relay is a separate, independently-configured control — **LDAP channel binding** (`LdapEnforceChannelBinding`), which cryptographically ties the NTLM authentication to the specific TLS channel it arrived on, so an authentication captured on one TLS session cannot be replayed into a different one. An environment that enforces LDAP signing but not channel binding is **still relayable over LDAPS** — both controls need to be enforced together to fully close LDAP relay.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Core relay mechanism | Real-time NTLM Type 1/2/3 forwarding between an inbound listening server and an outbound relay-target client — no password/hash cracking, no offline computation |
| Coercion/trigger (out of scope, cross-linked) | LLMNR/NBT-NS/mDNS poisoning (`Responder/`), authentication coercion — PetitPotam/PrinterBug/ShadowCoerce ([T1187](https://attack.mitre.org/techniques/T1187/)) |
| Listening (source) servers | SMB (445), HTTP/HTTPS (80, configurable multi-port), WCF/ADWS (9389), RAW (6666), RPC (135), WinRM/WinRMS, MSSQL (1433), RDP (3389) — verified against `impacket/examples/ntlmrelayx/servers/` |
| Relay-target (client) protocols | SMB, HTTP/HTTPS, LDAP/LDAPS, MSSQL, IMAP/IMAPS, SMTP, RPC, DCSync (a synthetic "protocol" that routes straight into a DRSUAPI pull) — verified against `impacket/examples/ntlmrelayx/clients/` |
| Structural defenses | SMB session signing (blocks SMB relay outright when required); LDAP server signing (blocks plain LDAP relay, does not block LDAPS); LDAP channel binding (blocks LDAPS relay specifically) |
| Post-relay attack surface | RBCD grant (`msDS-AllowedToActOnBehalfOfOtherIdentity`), Shadow Credentials (`msDS-KeyCredentialLink`), ADCS HTTP/RPC enrollment (ESC8-style), DCSync, SAM/LSA dump, SCCM policy/package dump, arbitrary command execution over SMB/WinRM/RPC(TSCH)/MSSQL |
| Multi-tool pivot | `-socks` — local SOCKS5 proxy + HTTP control API keeping relayed sessions alive for use by other tools |
| Recent CVEs exploitable via dedicated flags | CVE-2019-1040 (`--remove-mic`), CVE-2025-33073 (`--remove-sign-seal`) |

## Command-Line Switches — Quick Reference

Verified directly against the current `argparse` block in `examples/ntlmrelayx.py` in [fortra/impacket](https://github.com/fortra/impacket), plus the corresponding attack-module option groups. This tool's flag surface is large and has grown substantially across Impacket versions — do not trust older cheat sheets for this list.

**Core**

| Switch | Plain-English meaning |
|---|---|
| `-t, --target <target>` | Single relay target — IP, hostname, or full URL (`scheme://[domain\username@]host[:port]`). If omitted, relays **back to whichever client connected**, whatever protocol that implies |
| `-tf <file>` | File of multiple targets (hostnames or full URLs), one per line — relay rotates through them |
| `-w` | Watch the `-tf` file for changes and reload the target list automatically |
| `-i, --interactive` | Drop into a local interactive shell (SMB client / LDAP console / SQL shell) instead of firing an automatic attack module |
| `-ip, --interface-ip <ip>` | Bind listening servers to a specific local interface IP instead of all interfaces |
| `-ra, --random` | Randomize target selection from the target list instead of sequential rotation |
| `-r <SMBSERVER>` | Redirect HTTP requests to a `file://` path on a specified SMB server |
| `-l, --lootdir <dir>` | Directory to write loot files to. Default: current directory |
| `-of, --output-file <base>` | Base filename for saved encrypted-hash output |
| `-dh, --dump-hashes` | Print encrypted hashes to the console as they're captured |
| `-codec <codec>` | Character encoding used to decode target output |
| `-smb2support` | Enable SMB2 support on the listening SMB server (SMB1-only by default in older behavior) |
| `-ntlmchallenge <hex>` | Use a fixed NTLM server challenge instead of a random one per session |
| `-6, --ipv6` | Listen on IPv6 as well as IPv4 |
| `--remove-mic` | Strip the NTLM Message Integrity Code — exploits **CVE-2019-1040** for specific cross-protocol relay scenarios where signing would otherwise trigger |
| `--remove-sign-seal` | Strip NTLMSSP SIGN/SEAL negotiate flags while preserving the MIC — exploits **CVE-2025-33073**, an NTLM-reflection (relay-back-to-source) technique |
| `--serve-image <path>` | Local image file path to return to clients (social-engineering/decoy use) |
| `-c <command>` | Command to execute on the target once relay succeeds (protocol-dependent — SMB/WinRM/RPC-TSCH) |
| `--mssql-db <name>` | Database to use for MSSQL relay attacks |
| `-ts` | Timestamp every log line |
| `-debug` | Verbose debug output |

**Listening servers — enable/disable and ports**

| Switch | Plain-English meaning |
|---|---|
| `--no-smb-server` / `--no-http-server` / `--no-wcf-server` / `--no-raw-server` / `--no-rpc-server` / `--no-winrm-server` / `--no-mssql-server` / `--no-rdp-server` | Disable the named listening server (e.g. free the port for another tool, or narrow the attack surface an operator is exposing on a shared segment) |
| `--smb-port` | SMB listener port. Default **445** |
| `--http-port` | HTTP listener port(s) — supports comma lists and ranges (`80,8000-8010`). Default **80** |
| `--wcf-port` | WCF/ADWS listener port. Default **9389** |
| `--raw-port` | RAW listener port. Default **6666** |
| `--rpc-port` | RPC listener port. Default **135** |
| `--mssql-port` | MSSQL listener port. Default **1433** |
| `--rdp-port` | RDP listener port. Default **3389** |

**Relay behavior**

| Switch | Plain-English meaning |
|---|---|
| `--no-multirelay` | Disable multi-host relay (SMB and HTTP servers specifically) |
| `--keep-relaying` | Keep relaying to a target even after a successful connection on it, instead of stopping once one relay succeeds |

**SOCKS mode**

| Switch | Plain-English meaning |
|---|---|
| `-socks` | Enable SOCKS5 relay mode — keeps relayed sessions alive for reuse by other tools instead of firing one fixed attack |
| `-socks-address <ip>` | SOCKS5 (and HTTP API) bind address. Default **127.0.0.1** |
| `-socks-port <port>` | SOCKS5 listener port. Default **1080** |
| `-http-api-port <port>` | HTTP control-API port for the SOCKS server. Default **9090** |

**WPAD / proxy-auth harvesting**

| Switch | Plain-English meaning |
|---|---|
| `-wh, --wpad-host <host>` | Serve a WPAD file for a Proxy Authentication attack against the given hostname |
| `-wa, --wpad-auth-num <n>` | Prompt for authentication N times (default 1) — relevant for clients without MS16-077 installed |

**SMB client (attack) options**

| Switch | Plain-English meaning |
|---|---|
| `-e <file>` | Local file to push and execute on the SMB target |
| `--enum-local-admins` | If the relayed user isn't already admin, attempt a SAMR lookup to identify who is (pre-Windows-10-Anniversary targets only) |
| `--rpc-attack {TSCH,ICPR}` | Attack to perform over RPC-over-named-pipes when relaying SMB |

**RPC client options**

| Switch | Plain-English meaning |
|---|---|
| `-rpc-mode {TSCH,ICPR}` | Protocol to attack over RPC. Default **TSCH** (Task Scheduler exec) |
| `-rpc-use-smb` | Relay DCE/RPC over SMB named pipes rather than a raw RPC connection |
| `-auth-smb <[domain/]user[:pass]>` / `-hashes-smb <LM:NT>` | Credentials for the underlying SMB transport leg when `-rpc-use-smb` is set |
| `-rpc-smb-port {139,445}` | Destination port for the SMB transport leg. Default **445** |
| `-icpr-ca-name <name>` | Certificate Authority name for the `ICPR` (certificate-enrollment-over-RPC) attack |

**MSSQL client options**

| Switch | Plain-English meaning |
|---|---|
| `-q, --query <query>` | MSSQL query to execute (repeatable) |

**HTTP options**

| Switch | Plain-English meaning |
|---|---|
| `-machine-account <name>` / `-machine-hashes <LM:NT>` / `-domain <fqdn>` | Machine-account credentials + domain, used for a NETLOGON-based check on the HTTP relay path |
| `-remove-target` | Remove the target from the relay list after a relay attempt (success or failure) |
| `--https` | Serve HTTPS instead of plain HTTP on the listening server |
| `--certfile <path>` / `--keyfile <path>` | TLS certificate/key for the `--https` listener |

**LDAP client options**

| Switch | Plain-English meaning |
|---|---|
| `--no-dump` | Do not attempt to dump general LDAP directory information |
| `--no-da` | Do not attempt to create a new Domain Admin account (this happens **by default** otherwise) |
| `--no-acl` | Disable ACL-abuse attacks |
| `--no-validate-privs` | Skip privilege enumeration — assume permissions are sufficient for ACL attacks rather than checking first |
| `--escalate-user <user>` | Escalate an existing user's privileges instead of creating a new account |
| `--delegate-access` | Grant **Resource-Based Constrained Delegation** on the relayed computer account to a specified account — writes `msDS-AllowedToActOnBehalfOfOtherIdentity` |
| `--sid` | Use a SID rather than an account name for the delegation grant |
| `--dump-laps` | Dump any LAPS passwords the relayed identity can read |
| `--dump-gmsa` | Dump any Group Managed Service Account passwords the relayed identity can read |
| `--dump-adcs` | Dump ADCS enrollment-service and certificate-template information |
| `--dump-info-attr` | Dump the `info` attribute of all user/group objects (sometimes contains stashed credentials) |
| `--dump-pre2k` | Enumerate computer accounts still vulnerable to pre-Windows-2000 authentication (predictable password = computer name lowercased) |
| `--add-dns-record <NAME> <IPADDR>` | Add a DNS record via LDAP (relies on default authenticated-user DNS-record-creation rights) |

**Common SMB + LDAP option**

| Switch | Plain-English meaning |
|---|---|
| `--add-computer <NAME> [PASSWORD]` | Attempt to add a new computer account via SMB or LDAP (whichever the target implies), typically relying on the default `MachineAccountQuota` |

**IMAP client options**

| Switch | Plain-English meaning |
|---|---|
| `-k, --keyword <word>` | IMAP keyword to search mailbox content for. Default **`password`** |
| `-m, --mailbox <name>` | Mailbox to search. Default **INBOX** |
| `-a, --all` | Dump the entire mailbox instead of searching by keyword |
| `-im, --imap-max <n>` | Maximum number of emails to dump |

**AD CS (ESC8-style) attack options**

| Switch | Plain-English meaning |
|---|---|
| `--adcs` | Enable the AD CS web-enrollment relay attack |
| `--template <name>` | Certificate template to request. Defaults to **`Machine`** or **`User`** depending on whether the relayed account name ends in `$` |
| `--altname <name>` | Subject Alternative Name to request — used for ESC1/ESC6-style template abuse |
| `--altsid <sid>` | Alternative SID to embed via the SID security extension |
| `--enum-templates` | Enumerate certificate templates the relayed account can enroll against, without requesting one |

**Shadow Credentials attack options**

| Switch | Plain-English meaning |
|---|---|
| `--shadow-credentials` | Enable the Shadow Credentials attack — writes a new key-trust credential into `msDS-KeyCredentialLink` |
| `--shadow-target <account>` | Target account (user or `computer$`) to populate `msDS-KeyCredentialLink` on |
| `--pfx-password <pw>` | Password to protect the generated PFX certificate |
| `--export-type {PEM,PFX}` | Output format for the generated certificate/key. Default **PFX** |
| `--cert-outfile-path <path>` | Where to save the generated certificate/key |

**SCCM Policies attack options**

| Switch | Plain-English meaning |
|---|---|
| `--sccm-policies` | Enable SCCM secret-policy dumping from a Management Point (target: `http://<MP>/ccm_system_windowsauth/request`) — works best relaying a machine account |
| `--sccm-policies-clientname <name>` | Client name to register for policy retrieval. Defaults to the relayed account's own name |
| `--sccm-policies-sleep <seconds>` | Delay after client registration before requesting policies |

**SCCM Distribution Point attack options**

| Switch | Plain-English meaning |
|---|---|
| `--sccm-dp` | Enable SCCM package-file dumping from a Distribution Point (target: `http://<DP>/sms_dp_smspkg$/Datalib`) |
| `--sccm-dp-extensions <list>` | File extensions to look for. Default `.ps1,.bat,.xml,.txt,.pfx` |
| `--sccm-dp-files <file>` | File of specific URLs to download instead of extension-based indexing |

## Quick Use-Case List

- Basic SMB-to-SMB relay for command execution or remote-file drop (`-c`/`-e`)
- Default SMB relay with no attack flag — SAM-only hash dump (narrower than `secretsdump.py`'s combined SAM+LSA+cache default; see the corrected switches table above)
- Relay to LDAP(S) for a Resource-Based Constrained Delegation grant (`--delegate-access`)
- Relay to LDAP(S) for a Shadow Credentials write (`--shadow-credentials`)
- Relay straight into DCSync (`-t dcsync://<dc>`) — **not a vanilla relayed DRSUAPI pull**, this is a Zerologon (CVE-2020-1472) exploit chain against the target DC's own Netlogon service; only works against an unpatched/non-enforcing DC, and without extra `-auth-smb` creds only recovers three named accounts (`krbtgt`, the DC machine account, `Administrator`), not the full domain
- Relay to an ADCS HTTP enrollment endpoint for an ESC8-style certificate issuance (`--adcs`)
- Relay to an ADCS endpoint over raw RPC instead of HTTP (`-rpc-mode ICPR`)
- `-socks` mode — keep relayed sessions alive behind a local SOCKS proxy for use by any other tool
- Targeting a defined list of hosts via `-tf`, optionally randomized (`-ra`) or auto-reloaded (`-w`)
- Relaying to MSSQL for query execution / `xp_cmdshell`-style command execution (`-q`)
- Relaying to WinRM for an interactive PowerShell-equivalent session
- Relaying to SMB for Task Scheduler-based remote execution over RPC (`-rpc-mode TSCH`)
- Chained immediately after Responder (LLMNR/NBT-NS poisoning) or a coercion primitive (PetitPotam/PrinterBug/ShadowCoerce) as the upstream trigger
- Fleet-wide/multi-target relay from a single captured authentication attempt using `-tf` + `--keep-relaying`
- SCCM Management Point secret-policy dump (`--sccm-policies`) or Distribution Point package dump (`--sccm-dp`) via relayed machine-account HTTP auth
- Mailbox harvesting over relayed IMAP(S) authentication

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| An inbound NTLM authentication attempt to relay | Out of scope for this tool itself — via LLMNR/NBT-NS/mDNS poisoning (`Responder/`), a coercion primitive (PetitPotam/PrinterBug/ShadowCoerce, [T1187](https://attack.mitre.org/techniques/T1187/)), or organic cross-protocol auth |
| **SMB relay specifically:** target does not enforce SMB session signing | Verified in-tool — a signing-required target aborts the relay attempt with an explicit log message; this is the single strongest gate on SMB relay's viability |
| **LDAP relay specifically:** target does not enforce LDAP signing (plain LDAP) or LDAP channel binding (LDAPS) | Plain-LDAP relay is blocked by LDAP signing alone; LDAPS relay additionally requires channel binding to be **not** enforced — both controls need to be present together to fully close this path |
| **DCSync relay specifically:** target DC is vulnerable to Zerologon (CVE-2020-1472) — unpatched, or patched but **not** yet in Netlogon secure-channel enforcement mode | This is a hard structural gate, independent of SMB/LDAP signing entirely — a DC patched since August 2020 and enforcing (Microsoft's default since the Feb 2021 enforcement phase) rejects every attempt in the up-to-6,000-try loop and the relay logs "Target likely patched!" |
| Network position | The relay host must be reachable by both the victim (as the listening server) and the relay target (as the outbound client) — not necessarily the same network segment as required for LLMNR/NBT-NS poisoning itself |
| Elevated/root privileges on the relay host | Needed to bind low-numbered privileged listening ports (445, 389/636 target-side, 1433, 3389, etc.) |
| Relay-target-specific rights for the *attack module* to matter | E.g. the relayed identity needs local-admin-equivalent rights on an SMB target for the SAM dump to succeed, or sufficient AD write access for `--delegate-access`/`--shadow-credentials` to actually modify the target attribute — relay only forwards *whatever* rights the victim's identity holds, it grants none of its own |
