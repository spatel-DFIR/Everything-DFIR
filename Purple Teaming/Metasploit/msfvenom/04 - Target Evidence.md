# Metasploit — msfvenom — Target Evidence

Evidence left on the **target/destination** host once a msfvenom-generated payload actually executes there. This note covers the artifacts specific to msfvenom's own contribution — the delivered file's structure, static signature behavior, and initial execution — and **deliberately does not re-derive** what happens once a Meterpreter payload is running (reflective loading, TLV traffic, `migrate`, `getsystem`, `kiwi`) — that's fully covered in `../Meterpreter/04 - Target Evidence.md`, cross-linked at each relevant point below rather than repeated.

## Contents
- [Filesystem](#filesystem)
- [Registry](#registry)
- [Process Artifacts](#process-artifacts)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon](#sysmon-if-deployed)
- [Web-Application-Format Payloads (WAR/JSP/PHP/ASP)](#web-application-format-payloads-warjspphpasp)
- [Static and Behavioral AV/EDR Signature Notes](#static-and-behavioral-avedr-signature-notes)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)

---

## Filesystem

| Artifact | Detail |
|---|---|
| The delivered file itself | Whatever `-f` format and `-o` name the operator chose — `.exe`/`.dll`/`.elf`/`.apk`/etc., landing wherever the delivery mechanism placed it (email attachment path, download folder, USB, a dropper's own staging directory). Unlike Impacket's `psexec.py` (see `../../Impacket/psexec/04 - Target Evidence.md`), msfvenom itself has **no fixed drop location or naming convention** — that's entirely a function of the delivery mechanism, not msfvenom |
| File hash | **Consistent across runs only if the operator changed nothing between generations** — same `-p`/`-e`/`-i`/`-x`/`-f` arguments and same Framework version produce byte-identical output; changing *any* of them (a new `-i` count, a different `-x` template, a re-roll of `--smallest`'s encoder search) produces a different hash. This is the core reason hash-based hunting is comparatively weak against msfvenom output relative to a tool like Impacket's `psexec.py` that drops a near-invariant binary by default |
| Zone.Identifier / MOTW | Present if delivery crossed a zone boundary Windows tracks (web download, email attachment, extracted from a downloaded archive) — absent for USB/SMB-share delivery. A MOTW-tagged `.exe` opened despite a SmartScreen/Office warning is a distinct behavioral-evidence angle from the file's own content |
| Prefetch | `C:\Windows\Prefetch\<NAME>.EXE-<HASH>.pf` if the delivered file fully executes and Prefetch tracing is enabled — see `Windows/06 - Evidence of Program Execution/Prefetch.md`. Filename is whatever the operator chose (no fixed pattern to hunt on, unlike `psexec.py`'s random-8-character default) |
| Amcache / ShimCache | Record path, SHA1, and (Amcache) compile timestamp of the executed file — see `Windows/06 - Evidence of Program Execution/Amcache.md` and `.../ShimCache (AppCompatCache).md`. The compile timestamp on a `-x`-templated file is the **original template's** build time in most cases, not a msfvenom-generation timestamp — don't misread it as "when this specific trojanized copy was built" |
| `-x` template artifacts | If the payload was injected into a real, recognizable application (e.g. a trojanized PuTTY or Calculator), the resulting file may still carry that application's version resource, icon, and (with `-k`) functioning original behavior — a user-facing "it still works" signal that is itself evidence of `-x`/`-k` use once identified |

## Registry

msfvenom's own generated payloads make **no registry changes by default** — the payload is a self-contained executable/DLL/etc., not a persistence mechanism. Registry evidence only appears if:
- The chosen payload is a service-binary format (`-f exe-service`, `--service-name`) and something separately installs it as a service (`HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>` — see `Windows/10 - Persistence Mechanisms/Services.md`, not re-derived here).
- A *separate* persistence step (a `post`/`local` Metasploit module run from a resulting Meterpreter session, or an entirely different tool) writes a Run key, scheduled task, or similar — covered generally in `Windows/10 - Persistence Mechanisms/` and specifically for Meterpreter-launched persistence in `../Meterpreter/02 - Hands-On Use Cases.md`'s "Establishing Persistence from a Session."

## Process Artifacts

| Artifact | Detail |
|---|---|
| Initial process creation | The delivered file launching — parent process is whatever ran it (Explorer for a double-clicked attachment, a script host for a chained delivery mechanism, `services.exe` if installed as a service) |
| `-k`-injected template | If `-x -k` was used, the process tree shows the **original template's** expected behavior (e.g. `putty.exe` actually connecting somewhere) running alongside a second thread executing the payload — a single process exhibiting two unrelated behavior patterns simultaneously is itself a tell, distinct from a normal trojanized binary that simply replaces the original functionality outright |
| Post-execution behavior | Entirely dependent on which payload module was chosen. If it's a Meterpreter variant, everything from this point — reflective loading, `metsrv.dll` residency, TLV traffic, `migrate` — is covered in full in `../Meterpreter/04 - Target Evidence.md`. If it's a single (non-Meterpreter) shell payload, the process simply spawns a `cmd.exe`/`/bin/sh` back to the handler with no additional in-memory-loading mechanic to look for |

## Windows Event Logs

| Log | Event ID | Signal |
|---|---|---|
| Security | 4688 (if command-line/process-creation auditing enabled) | The delivered file launching — command line shows the exact executable path and any arguments |
| Security | 4624 (Logon Type varies) | Only relevant if the payload's execution led to further authenticated activity (e.g. lateral movement from a resulting session) — not generated by the payload's own launch |
| System | 7045 | Only if the delivered file was a service-binary format (`-f exe-service`) that got installed as a service — see the Registry section above and `Windows/10 - Persistence Mechanisms/Services.md` |

Notably **absent**: like Meterpreter itself, there is no dedicated "msfvenom" event source — every entry above is a generic Windows event that happens to be a side effect of how the specific delivered payload behaves, not a purpose-built log record naming msfvenom.

## Sysmon (if deployed)

| Event ID | Signal |
|---|---|
| 1 (Process Create) | The delivered file's initial launch — `Hashes` field is directly comparable against known-bad hash lists if the operator didn't vary generation parameters between targets |
| 3 (Network Connect) | The payload's first outbound (or inbound, for `bind_tcp`) connection to its configured `LHOST:LPORT` — see the payload-specific network behavior in `../Meterpreter/04 - Target Evidence.md` if it's a Meterpreter variant |
| 7 (Image/DLL Load) | For a `-f dll` payload delivered via a normal `LoadLibrary`-based load (not a reflective/in-memory technique), this **does** fire — unlike Meterpreter's own reflectively-loaded `metsrv.dll`, a msfvenom-generated DLL loaded the conventional way is visible here |
| 8 (CreateRemoteThread) | Fires if the payload's own post-execution behavior includes process injection (e.g. a Meterpreter session's later `migrate` — see `../Meterpreter/04 - Target Evidence.md`) — not generated by msfvenom's own delivery/launch step |
| 11 (File Create) | The delivered file's write-to-disk event, if that happened locally (download, extraction) rather than the file being carried in on removable media pre-existing |

## Web-Application-Format Payloads (WAR/JSP/PHP/ASP)

`-f war`/`-f jsp`/`-f raw` (for PHP)/`-f asp`/`-f aspx` payloads land on a **web server or application server**, not a general-purpose Windows endpoint — the evidence shape above (Prefetch, Amcache, Windows-service registry keys) largely doesn't apply, and the host itself may well be Linux. This category has its own artifact set:

| Artifact | Detail |
|---|---|
| Web root / webapps directory | The delivered file itself — a `.war`'s contents auto-explode into the servlet container's `webapps/<app>/` directory on deployment (Tomcat), a `.jsp`/`.php`/`.asp`/`.aspx` file drops directly into an existing web root. Unlike a Windows filesystem drop, this file is **immediately remotely reachable and executable by any client that can reach the URL** — no separate "launch" step the way a delivered EXE needs a user or service to run it |
| Web server access logs | The HTTP request(s) that deployed the file (a `PUT`/`POST` to Tomcat Manager's `/manager/text/deploy` endpoint, an upload-form `POST`, or an LFI/RFI request chain for PHP) followed by the first `GET`/`POST` to the dropped file's own path — this **is** the execution-trigger event for a web-shell-format payload, functionally equivalent to Sysmon Event ID 1 for a normal EXE. Covered by IIS/Apache/Tomcat's own log format, not a Windows Event Log ID |
| Application-server process tree | The servlet container's own process (`java.exe`/`catalina.sh`-launched JVM for Tomcat, `httpd`/`php-cgi`/`php-fpm` for PHP, `w3wp.exe` for IIS/ASP.NET) spawning a child shell (`cmd.exe`, `powershell.exe`, `/bin/sh`) is the single strongest process-tree anomaly for this category — a web server process has no legitimate reason to spawn an interactive command interpreter, and this holds regardless of which msfvenom evasion flag was used to build the underlying payload |
| Tomcat Manager credential reuse | If delivery was via Tomcat Manager, the authentication event (default/weak `manager-gui`/`manager-script` credentials, or credentials recovered elsewhere in the engagement) is itself a distinct, earlier evidence point worth correlating — see `02 - Hands-On Use Cases.md`'s Java WAR/JSP scenario |
| No MOTW, no Prefetch, no Amcache | None of Windows's download-provenance or program-execution artifacts apply to a file executed *by* a web server process rather than opened by a user or the OS loader — don't go looking for them on this category |

## Static and Behavioral AV/EDR Signature Notes

- **Static signature matching** works best against **default, unmodified msfvenom output** — the Framework's stock `msf/data/templates/` files and well-known encoder decoder stubs (`shikata_ga_nai`'s stub shape, in particular) are heavily signatured by mainstream AV/EDR products precisely because they're the default, most commonly seen configuration. This is the inverse of the situation with Impacket's `psexec.py` (a tool with almost no configurability, so its default binary is *always* the hunting target) — msfvenom's entire design surface (`-x`, `-e`/`-i`, `-f`, `--encrypt`) exists to move a generated file away from that default shape.
- **The entropy signal from this page's red-flag callout (`01 - Overview.md`) is the most evasion-resistant static angle**: raw shellcode injected into a compiler-built template produces a high-entropy code region inside an otherwise normal-entropy binary, regardless of which specific encoder or template was used — because the *injection mechanic itself*, not any particular encoder's byte pattern, is what creates the contrast.
- **Behavioral EDR** — API-call sequences characteristic of shellcode execution (`VirtualAlloc`/`VirtualProtect` with RWX permissions, followed by execution from that region), and, for Meterpreter-family payloads specifically, the reflective-loading and process-injection behaviors fully covered in `../Meterpreter/04 - Target Evidence.md` — is the detection layer least affected by any of msfvenom's own evasion flags, since none of them change what the payload *does* once it's running, only how it looks on disk beforehand.
- A target with modern EDR and no alert on a confirmed msfvenom-delivered payload (via event-log/Sysmon correlation) suggests either the product's static/behavioral detection was bypassed by unusual generation parameters, or the product's relevant detection capability is disabled/misconfigured — not that the payload is inherently undetectable.

## Memory Forensics

If the delivered payload is a Meterpreter variant, the memory-forensics angle — `malfind`-class detection of a private executable region with no backing file, `ldrmodules` PEB-vs-VAD mismatches, YARA against extracted regions — is **identical to and fully covered by** `../Meterpreter/04 - Target Evidence.md`'s Memory Forensics section; this note doesn't repeat it. For a **non-Meterpreter single payload** (a plain reverse shell, for instance), the memory footprint is simpler: the payload typically runs directly in the delivered process's own memory space (no reflective self-loading mechanic, since single payloads don't carry one) — standard process-memory string/YARA search against the running process is the relevant technique rather than VAD-anomaly hunting.

## Building a Timeline

The delivery/execution event (Sysmon 1, Security 4688) is the anchor — everything upstream (which build host generated the file, when) lives in `03 - Source Evidence.md`'s shell-history/hash-correlation angle, and everything downstream (session establishment, further attacker activity) depends entirely on which payload module was chosen: for a Meterpreter payload, follow `../Meterpreter/04 - Target Evidence.md`'s "Building a Timeline" walkthrough from the first network connection onward; for a plain single shell payload, the timeline is comparatively short — process creation, first network connection, and whatever the operator does over that shell (itself outside msfvenom's scope to characterize generically). For a WAR/JSP/PHP/ASP web-application-format payload, the anchor shifts entirely to the **web server's own access log** (the deploy/upload request, then the first request to the dropped file's path) followed immediately by the application-server process spawning a shell — there is no Sysmon 1/Security 4688 "delivery" event distinct from the web request itself.
