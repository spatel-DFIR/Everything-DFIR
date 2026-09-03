# Cobalt Strike — Overview

> 🔴 **Red Flag Principle:** Cobalt Strike is a **Malleable C2** platform by design — every network indicator a defender might blocklist (URIs, User-Agent, HTTP headers, TLS certificate fields, even the DNS record types used) is a text field in a profile the operator supplies at Team Server startup. Static content-based signatures decay fast. What survives profile customization is **behavioral**: the beacon's underlying check-in periodicity (sleep + jitter, statistically visible even when the wire content changes), the process-injection technique family, and — for unmodified installs — the small set of artifacts (named pipes, default `spawnto` process, the well-known default certificate) operators forget or don't bother to change. Chase the behavior, not the string.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Cobalt Strike is **closed-source commercial software** — there is no public GitHub repository to verify against, unlike every other tool in this repo. History here is verified against **Fortra's own official site ([cobaltstrike.com](https://www.cobaltstrike.com/)) and press materials**, cross-checked against MITRE ATT&CK's software entry, since no source tree exists to inspect directly.

- **Created in 2012 by Raphael Mudge**, initially built on top of the open-source Armitage GUI he'd previously written for Metasploit. Cobalt Strike was one of the first purpose-built, commercially distributed **red team command-and-control frameworks** — designed explicitly for "adversary simulation" (threat-representative testing that emulates a real intruder's post-exploitation tradecraft) rather than for exploit development or vulnerability scanning.
- Developed and sold for years through **Strategic Cyber LLC**, Mudge's own company — several older detection write-ups and default-certificate artifacts (see `04 - Target Evidence.md`) still reference `Strategic Cyber LLC` in certificate metadata from that era.
- **March 4, 2020 — acquired by Fortra** (announced while operating as HelpSystems; the company later rebranded to Fortra). The acquisition folded Cobalt Strike into Fortra's **Core Security** portfolio alongside Core Impact, per [Fortra's press release](https://www.fortra.com/resources/press-releases/helpsystems-acquires-cobalt-strike-expand-core-security-business). Raphael Mudge sold his interest at that point, stayed on briefly for the transition, and later stepped away from the security field — current development is owned by **Fortra's Cobalt Strike R&D team**, not Mudge personally.
- **Cobalt Strike 4.7 ("The 10th Anniversary Edition")** — a version milestone marking a decade since the tool's creation; also notable for continued investment in the **watermarking system** used to distinguish legitimate licensed installs from cracked/leaked copies (see [How It Works](#licensingwatermarking--the-cracked-copy-problem) below) as cracked-copy abuse in ransomware intrusions became a persistent industry problem.
- **MITRE ATT&CK tracks Cobalt Strike as [S0154](https://attack.mitre.org/software/S0154/)** — one of the most heavily technique-mapped entries in the framework (60+ associated technique/sub-technique IDs), reflecting both its legitimate red-team ubiquity and its adoption by real-world threat actors and ransomware affiliates.
- Distribution model: **paid annual license**, screened customers only (Fortra performs a vetting process before sale) — yet cracked/leaked copies remain in continuous circulation regardless (see the watermarking discussion below). Current release cadence and version-specific details should be verified against `cobaltstrike.com` at time of use rather than assumed static, since Fortra ships frequent point releases.

## How It Works

### Architecture — Team Server, Client, Beacon

Verified against Fortra's own architecture documentation and Google Cloud's technical breakdown of Cobalt Strike's components (["Defining Cobalt Strike Components & BEACON"](https://cloud.google.com/blog/topics/threat-intelligence/defining-cobalt-strike-components)):

```
[ Operator's Client (Windows/macOS/Linux) ] ──(TCP 50050, TLS)──▶ [ Team Server (Linux only) ]
                                                                          │
                                                                          │ generates listener jobs +
                                                                          │ compiles/serves payloads
                                                                          ▼
                                                          [ Listener: HTTP/HTTPS/DNS/SMB/TCP ]
                                                                          │
                                                                          ▼
                                                          [ Beacon (the payload, on target) ]
```

- **Team Server** — the C2 server process, distributed as a single Java `.jar` (`cobaltstrike.jar`, launched via a `teamserver` shell script), **Linux-only**. It manages listener jobs, compiles Beacon payloads on demand, brokers all operator commands to active sessions, and logs every operator action and beacon callback.
- **Client** — the operator's GUI console (Java, runs on Windows/macOS/Linux). Multiple operators connect to the same Team Server over its TCP **50050** management port (TLS-protected, password-authenticated) for true multiplayer red-team operations — every connected client sees the same session state.
- **Beacon** — Cobalt Strike's default payload/implant. Unlike a traditional reverse shell, Beacon is **asynchronous by design**: it checks in with the Team Server on a sleep/jitter schedule, retrieves any queued tasking, executes it, and reports results on its next check-in rather than holding an interactive connection open — the same "low-and-slow" operating model as Sliver's beacon mode (see `Sliver/01 - Overview.md`), and the model Cobalt Strike originated in this space.

### Listener types

| Listener | Transport | Notes |
|---|---|---|
| HTTP / HTTPS | TCP (default 80/443, operator-configurable) | The most common transport; heavily reshaped by Malleable C2 profiles (URIs, headers, User-Agent). HTTPS listeners can use a self-signed cert, an operator-supplied cert, or Let's Encrypt. |
| DNS | UDP 53 | Two modes: **Hybrid (DNS+HTTP)** — DNS carries the low-bandwidth beacon channel, HTTP carries bulk data — is the default; **Pure DNS** pushes both channels over DNS records (A/AAAA/TXT), slower but usable where only DNS resolution egresses the network. |
| SMB | Named pipe over SMB (port 445) | A **bind** listener, not a listen-for-inbound-callback one — used for **beacon chaining/pivoting**: an already-connected Beacon relays a second, internally-pivoted Beacon's traffic over a named pipe with no direct egress needed from the second host. |
| TCP | Raw TCP | Also a bind-style pivot listener, functionally parallel to SMB chaining but without SMB's protocol signature. |
| Foreign / External C2 | Varies | Foreign listeners let a Team Server accept a Metasploit Meterpreter callback directly; External C2 lets a third-party C2 channel (e.g. a custom covert channel) feed traffic to Beacon over a documented spec. |

### Staged vs. stageless payloads

Like most C2 frameworks, Cobalt Strike supports both models. A **stager** is a small initial shellcode blob that performs light sandbox checks and then downloads the full Beacon backdoor from the Team Server; a **stageless** payload embeds the entire backdoor (with its config) in one artifact. Per Google Cloud's writeup, HTTP(S) stager downloads default to a **4-character alphanumeric URI with an embedded 8-bit checksum** validating the request — meaning a defender who requests a syntactically valid stager URL can actually pull the stage even without operator interaction, unless the operator sets the Malleable profile's `host_stage` option to `false` to disable that behavior.

### Malleable C2 profiles

The mechanism that gives Cobalt Strike its name and its evasion flexibility. A Malleable C2 profile is a plain-text configuration file, loaded when the Team Server starts, that rewrites nearly every network-observable detail of Beacon's HTTP(S)/DNS traffic — verified against Fortra's own [Malleable Command and Control documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_main.htm):

```
set sleeptime "60000";      # global option: base check-in interval (ms)
set jitter    "20";         # global option: % randomization on sleeptime
set useragent "Mozilla/5.0 ...";

http-get {
    set uri "/load";
    client  { header "Accept" "*/*"; }
    server  { header "Content-Type" "text/html"; output { print; } }
}

http-post {
    set uri "/submit.php";
    client  { output { base64; print; } }
}

http-stager {
    client  { uri_x86 "/stage86"; uri_x64 "/stage64"; }
}

dns-beacon {
    set maxdns "255";
}
```

- **Global options** (`sleeptime`, `jitter`, `useragent`, `host_stage`, `maxdns`, etc.) apply framework-wide.
- **Protocol-transaction blocks** (`http-get`, `http-post`, `http-stager`, `dns-beacon`, `https-certificate`, etc.) shape one specific transaction's client/server request-response shape independently — operators publish profiles that disguise Beacon traffic as jQuery CDN requests, Microsoft OneDrive/Graph API calls, Amazon S3/AWS SDK traffic, Google Search/Analytics beacons, or OCSP validation traffic (per Palo Alto Unit 42's [Malleable C2 profile research](https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2-profile/)). Applying a new profile requires a Team Server restart and payload regeneration — it is not a live/hot-swappable setting.
- Because profiles are widely published (e.g. the community [`threatexpress/malleable-c2`](https://github.com/threatexpress/malleable-c2) and [`rsmudge/Malleable-C2-Profiles`](https://github.com/rsmudge/Malleable-C2-Profiles) repos), a huge share of both legitimate and illegitimate Cobalt Strike traffic on the internet runs one of a relatively small set of publicly known profiles — a real detection opportunity, since a fully custom profile is more work than most operators bother with.

### Sleep, jitter, and Kill Date

`sleeptime` sets Beacon's base check-in interval (**default 60 seconds** per Fortra's own documentation, changeable interactively with the console's `sleep` command); `jitter` adds a randomized percentage on top of that interval per check-in to defeat naive fixed-interval detection. A **Kill Date** — a hard stop date after which the Beacon payload refuses to run — can only be set at Team Server startup and only takes effect if a Malleable C2 profile is also specified (per Fortra's own ["What happened to my Kill Date?"](https://www.cobaltstrike.com/blog/what-happened-to-my-kill-date) post); it is an operator OPSEC/scoping control, not a security feature defenders can rely on.

### Process injection and `spawnto`

Beacon's post-exploitation jobs (running a BOF, spawning a new session, executing a `run`/`shell` command) frequently execute inside a **temporary sacrificial process** rather than Beacon's own process — the `spawnto` setting controls which binary that sacrificial process is. Verified against Fortra's own ["Cobalt Strike's Process Injection: The Details"](https://www.cobaltstrike.com/blog/cobalt-strikes-process-injection-the-details-cobalt-strike) post:

- The historical/commonly-cited default is **`rundll32.exe`** — notably, if an x64 Beacon needs to spin up a temporary x86 job (or vice versa), it also falls back to `rundll32.exe` for the cross-architecture spawn.
- The default injection primitive is the classic **`VirtualAllocEx` → `WriteProcessMemory` → thread-creation** pattern — a well-understood, heavily signatured sequence in EDR telemetry.
- `spawnto x86 <path>` / `spawnto x64 <path>` (console commands, since CS 3.6) let an operator override the sacrificial process per architecture; Malleable C2 profiles can set this at compile time too.
- **Cobalt Strike 4.5** introduced a **User-Defined Reflective Loader (UDRL) Kit** and reworked injection internals, letting licensed operators supply fully custom loader/injection code — meaning the "default injection signature" story only holds for un-customized installs, and a well-resourced operator can defeat process-injection-pattern detection entirely. Treat process-injection signatures as a **medium-confidence, defeatable-with-effort** signal, not a guarantee.

### Licensing/watermarking — the cracked-copy problem

Because Cobalt Strike is closed-source and commercially licensed, Fortra built a **watermarking system** to trace which license a given Beacon payload came from — directly relevant to why so much real-world ransomware activity uses this specific tool despite it being a paid, screened-customer product. Verified against Google Cloud's technical breakdown and corroborated by Google's own 2023 research disrupting cracked copies:

- Every Beacon stager and full backdoor embeds a **watermark value derived from the Team Server's `CobaltStrike.auth` license file**. A matching watermark across two Beacons means they came from the *same auth file* — it does **not** by itself prove the same physical server or the same operator, since an auth file (licensed or fraudulently obtained) can be copied.
- **Legitimate licensed installs** carry a distinct, traceable watermark. **Cracked/leaked copies** are produced either by patching a trial JAR to bypass the license check, or by fabricating a fake `CobaltStrike.auth` file — a **watermark value of `0`** (or, per some published research, `1`) has been publicly associated with known-cracked distributions, though operators of cracked copies have also been observed setting arbitrary watermark values, so this is a strong-but-not-absolute signal, not a guarantee.
- **Google Cloud Threat Intelligence identified 34 distinct cracked/leaked release families** (spanning versions 1.44 through 4.7, ~275 unique JAR files) circulating in the wild, and published YARA/detection signatures for them — a direct illustration of how large the illegitimate-copy ecosystem is.
- Fortra has partnered with **Microsoft and the Health-ISAC** on legal/technical disruption campaigns targeting infrastructure hosting cracked Cobalt Strike, given how disproportionately cracked copies show up in ransomware intrusions (see the CISA #StopRansomware sourcing note in `02 - Hands-On Use Cases.md`'s illegitimate-use scenario).
- **Open question:** the exact byte layout/length of the watermark value and precise algorithm are not publicly documented by Fortra (closed-source, by design, to keep the anti-piracy mechanism itself from being trivially bypassed) — third-party research describes it as a short numeric value derived from the auth file, but exact technical specifics beyond that should be treated as third-party-inferred, not vendor-confirmed.

### Arsenal Kits — licensed customization surface

Licensed (and, by extension, cracked) installs ship with **Arsenal Kits** that let an operator customize evasion-relevant internals without waiting on a Fortra release: **Artifact Kit** (customize the compiled EXE/DLL/shellcode templates), **Resource Kit** (customize script-based loader templates — PowerShell, VBA, etc.), **Sleep Mask Kit** (customize Beacon's in-memory obfuscation while sleeping — directly defeats memory-scanning signatures), **User-Defined Reflective Loader (UDRL) Kit** (custom loader/injection code, added alongside Sleep Mask Kit), **Elevate Kit** (public on GitHub — plugs in privilege-escalation exploits), and **Mimikatz Kit** (lets Beacon's bundled Mimikatz be updated independently of Cobalt Strike's own release cycle). Each kit directly widens the gap between "default install" IOCs (documented throughout `04 - Target Evidence.md`) and a well-resourced operator's actual traffic/binary — factor this into hunting-signal confidence per `05 - Detection and Hunting.md`'s priority table.

### Execution surface: BOFs, `execute-assembly`, and Aggressor Scripts

Three distinct extension mechanisms, worth not conflating:
- **`execute-assembly`** — spawns a temporary sacrificial process and injects a .NET assembly (e.g. Rubeus, Seatbelt) into it for in-memory execution. Subject to AMSI scanning if AMSI is active and not separately bypassed.
- **Beacon Object Files (BOFs)** — small, compiled C programs executed **directly inside Beacon's own process**, no new process spawn or injection required — the stealthier of the two, but single-threaded (a running BOF blocks other Beacon tasking until it completes).
- **Aggressor Scripts** — Perl-derived ("Sleep" language) automation macros that run **only in the operator's own Client console**, not on the Team Server or inside Beacon — they automate/chain existing commands rather than add new Beacon-side capability (e.g. auto-running Mimikatz against any new session that logs in).

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| C2 transport | HTTP/HTTPS (TCP 80/443 default), DNS (UDP 53, hybrid or pure), SMB named-pipe pivot (TCP 445), raw TCP pivot |
| Team Server management | TLS-protected TCP 50050 (operator client ↔ Team Server) |
| Process injection | `VirtualAllocEx`/`WriteProcessMemory`/remote-thread creation (default), fully custom via UDRL Kit (licensed) |
| Credential access | Bundled Mimikatz integration (`logonpasswords`, `hashdump`, `dcsync`), browser pivoting (session/cookie theft) |
| Lateral movement | SMB/ADMIN$ (`jump psexec`), WinRM (`jump winrm`), WMI (`remote-exec wmi`), SSH |
| Encoding/obfuscation | Base64/NetBIOS encoding of C2 traffic, timestomping, process-argument spoofing, sleep-time memory obfuscation (Sleep Mask Kit) |
| Discovery | Port scanning, share/session enumeration, process/service listing, AD group membership queries |
| Exfiltration | Data chunking for large transfers over the same C2 channel |

## Command-Line Switches — Quick Reference

**Team Server startup** (`./teamserver <host> <password> [profile] [kill-date]`) — run on the Linux Team Server host:

| Argument | Plain-English meaning |
|---|---|
| `<host>` | Externally reachable IP the Team Server advertises to itself (mandatory) |
| `<password>` | Shared password operators use to authenticate their Client console to this Team Server (mandatory) |
| `[profile]` | Path to a Malleable C2 profile file — optional, but **required** if a Kill Date is also being set |
| `[kill-date]` | `YYYY-MM-DD` — hard stop date after which generated Beacons refuse to execute; only takes effect with a profile also specified |

**Malleable C2 profile syntax basics** (plain-text file, loaded at Team Server startup):

| Element | Plain-English meaning |
|---|---|
| `set <option> "<value>";` | A **global** option applied framework-wide (e.g. `sleeptime`, `jitter`, `useragent`, `host_stage`, `maxdns`) |
| `<transaction-block> { ... }` | A **protocol-transaction block** (`http-get`, `http-post`, `http-stager`, `dns-beacon`, `https-certificate`) shaping one specific request/response type |
| `client { header "X" "Y"; }` | Customizes what the **Beacon** sends (headers, URIs, cookies) |
| `server { header "X" "Y"; }` | Customizes what the **Team Server** responds with |
| `output { base64; print; }` | Instructions for how task-result data is encoded into the transaction |

**Beacon console commands — grouped quick reference:**

| Category | Commands | Plain-English meaning |
|---|---|---|
| Session/C2 | `sleep <n> [jitter]`, `checkin`, `jobs`, `jobkill <n>` | Adjust check-in cadence; force an immediate callback; view/kill background jobs |
| Code execution | `shell`, `run`, `powershell`, `powerpick`, `execute-assembly` | Run a native command, a PowerShell command (with/without spawning `powershell.exe`), or an in-memory .NET assembly |
| Discovery | `getuid`, `ps`, `netstat`, `net logons`, `net localgroup`, `net dclist` | Identify current privilege context, running processes, connections, logged-on users, group/domain membership |
| Credential access | `logonpasswords`, `hashdump`, `mimikatz <command>`, `dcsync <fqdn> <user>` | Dump LSASS-resident plaintext/hashes, local SAM hashes, arbitrary Mimikatz commands, or a DCSync-style domain credential pull |
| Lateral movement | `jump <method> <target> <listener>`, `remote-exec <method> <target> <cmd>`, `pth <domain>\<user> <hash>`, `make_token` | Deploy/execute a payload on a remote host via a named method (`psexec`, `psexec64`, `psexec_psh`, `winrm`, `winrm64`, `wmi`); pass-the-hash; forge a token from known creds |
| Injection/spawn | `spawn <arch> <listener>`, `inject <pid> <arch> <listener>`, `spawnto <x86\|x64> <path>` | Start a new Beacon in a fresh sacrificial process, inject into an existing PID, or set which process future sacrificial spawns use |
| Pivoting | `socks <port> [socks5 [...]]`, `rportfwd <src-port> <iface> <dst-port>`, `connect`/`link` | Stand up a SOCKS4a/5 proxy through Beacon, forward a remote port back, or connect/attach to a chained TCP/SMB Beacon |
| Collection | `screenshot`, `screenwatch`, `keylogger`, `clipboard`, `upload`/`download` | Capture desktop state, log keystrokes, read clipboard, transfer files |
| Housekeeping | `rev2self`, `exit`, `kill` | Revert an impersonated token, gracefully exit, or kill the Beacon process |

## Quick Use-Case List

- Standing up a Team Server with a Malleable C2 profile (baseline infrastructure setup)
- Generating a stageless HTTP(S) Beacon for straightforward, self-contained delivery
- Generating a staged Beacon for size-constrained delivery contexts
- Standing up a DNS listener for covert beaconing where HTTP(S)/direct egress is restricted
- Tuning `sleep`/`jitter` for a long, low-noise engagement
- Customizing a Malleable C2 profile to blend into expected web traffic (jQuery/OneDrive/S3-style masquerading)
- Lateral movement via `jump psexec`/`psexec64` (service-based)
- Lateral movement via `jump winrm`/`winrm64` (PowerShell-over-WinRM)
- Pivoting internal hosts with no direct egress through SMB/TCP beacon chaining
- Standing up a SOCKS proxy through an established Beacon for tool-agnostic pivoting
- Credential harvesting via the bundled Mimikatz integration (`logonpasswords`, `hashdump`, `dcsync`)
- Process injection/migration (`spawn`, `inject`, `spawnto`) to move off a risky initial process
- Running third-party .NET tradecraft in-memory via `execute-assembly` (Rubeus, Seatbelt, etc.)
- Browser pivoting to inherit an already-authenticated browser session
- Chained workflow: Cobalt Strike Beacon → credential/AD-recon tooling (BloodHound's SharpHound collector, already covered in this repo's `BloodHound/` folder; Rubeus, planned separately in this repo's Wave 2 build)
- Illegitimate/cracked-license use as a ransomware-precursor C2, per CISA #StopRansomware advisories (Play, BlackSuit)

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Team Server infrastructure | A Linux host to run `teamserver`; Java runtime; a valid Fortra license (`CobaltStrike.auth`) for legitimate use |
| Network egress from target | At least one listener transport reachable: direct TCP to HTTP(S)/50050-adjacent infrastructure, or DNS resolution reaching a delegated domain for DNS C2, or SMB/TCP reachability to a pivot host for chained Beacons |
| DNS delegation (DNS listener) | Operator must control a registered domain with NS records pointed at the Team Server's DNS listener |
| TLS certificate (HTTPS) | A supplied cert/key pair, Let's Encrypt auto-provisioning, or (least stealthy) the tool's own self-signed default |
| Malleable C2 profile | Optional but standard practice — required if a Kill Date is also desired; must be supplied at Team Server startup, not hot-swappable |
| `jump psexec`/`winrm`/`remote-exec` | Valid credentials (or an existing token) with admin rights on the target; SMB/ADMIN$ or WinRM reachability respectively |
| `execute-assembly` | Windows target; a Beacon session with sufficient privilege in the sacrificial/target process context |
| Arsenal Kit customization | Licensed install — kits are a paid-license feature, not available to a bare trial |
