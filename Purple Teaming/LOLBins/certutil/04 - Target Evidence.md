# LOLBins — certutil.exe — Target Evidence

Evidence left on the **target/victim** host — where every technique in this note actually executes. Because there's no dropped custom binary and no service/scheduled-task persistence involved in the techniques themselves, the strongest evidence classes here are **process command-line capture** and a certutil-specific **disk cache written as a side effect of its own download machinery**, independent of whatever output path the operator specified.

## Contents
- [Filesystem](#filesystem)
- [Registry](#registry)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon](#sysmon-if-deployed)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Signatures](#endpoint-security-product-signatures)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)
- [Distinguishing Abuse from Legitimate CA Administration](#distinguishing-abuse-from-legitimate-ca-administration)

---

## Filesystem

| Artifact | Detail |
|---|---|
| Explicit output file | Whatever path the operator gave as `OutFile` to `-urlcache`/`-verifyctl`/`-encode`/`-decode`/`-encodehex`/`-decodehex` — no fixed naming convention, entirely operator-controlled |
| **CryptnetUrlCache — user context** | `%LOCALAPPDATA%Low\Microsoft\CryptnetUrlCache\MetaData\<hash>` and `...\Content\<hash>` — written as a side effect of **any** download-verb invocation (`-urlcache`, `-verifyctl`, `-URL`), regardless of whether an explicit output path was also given. Verified independently against the LOLBAS Project's `Certutil.yml` technique notes, Velociraptor's `Windows.Forensics.CertUtil` artifact documentation, and Adam/@hexacorn's `-URL`-technique writeup — all three name this exact path |
| **CryptnetUrlCache — SYSTEM context** | `C:\Windows\ServiceProfiles\<...>\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\*` (and the matching `Content\` sibling) when `certutil.exe` runs as SYSTEM (e.g. tasked by a SYSTEM-context C2 implant or scheduled task) rather than as an interactive user — confirmed via Velociraptor's own dual user/system path handling for this artifact |
| `MetaData\<hash>` contents | The source URL (UTF-16 string), a Windows FILETIME download timestamp, the fetched file's size, and a hash value — effectively a self-contained download log an analyst can parse without needing a separate proxy/firewall log, per Velociraptor's documented parsing of this structure |
| ADS technique output | `<hostfile>:<streamname>` — invisible to a default directory listing; requires `Get-Item -Stream *` (PowerShell) or `dir /r` to enumerate. See `Windows/08 - Deleted Items and File Existence.md` for general ADS-enumeration technique this note doesn't re-derive |
| Prefetch | `CERTUTIL.EXE-<HASH>.pf` updates on every run — **low-uniqueness on its own**, since `certutil.exe` also runs for entirely legitimate CA-administration reasons on many estates. See `Windows/06 - Evidence of Program Execution/Prefetch.md` |
| Amcache / ShimCache | Record `certutil.exe` executions — same low-uniqueness caveat as Prefetch; useful only as corroboration once a specific timestamp is already suspected from stronger evidence below. See `Windows/06 - Evidence of Program Execution/Amcache.md` and `.../ShimCache (AppCompatCache).md` |
| Zone.Identifier / MOTW | **Not applied by certutil's own download verbs** — unlike a browser download, nothing in the verified sources for this note documents certutil writing a Mark-of-the-Web `Zone.Identifier` alternate stream on the file it fetches. A fetched executable that would normally trigger SmartScreen/MOTW-based warnings when downloaded via a browser does **not** carry that marker when fetched via certutil — a real, meaningful evasion property worth flagging on its own |

## Registry

No certutil-specific registry key was found or verified for these techniques across the sources reviewed for this note (LOLBAS, Microsoft's own `certutil` reference, Velociraptor's artifact documentation) beyond the `CryptnetUrlCache` **files** documented above, which live on disk, not in the registry. Treat "no distinctive registry artifact" as the accurate, verified position here rather than assuming one exists by analogy with other techniques in this module.

## Windows Event Logs

| Log | Event ID | Signal |
|---|---|---|
| **Security** | **4688** (Process Creation) | **The primary evidence source for this technique** — captures the full `certutil.exe` command line verbatim if command-line auditing is enabled (`Include command line in process creation events` policy, or the equivalent registry value). Without this, 4688 alone only confirms *that* certutil ran, not with what arguments — see the caveat this repeats from `Windows/Threat Landscape and Playbooks/LOLBIN Abuse Hunting Playbook.md` |
| Security | 4689 | Process termination — of limited independent value here since certutil's abuse techniques are typically short-lived, single-shot invocations |
| System | 7036 | **Not applicable** — no service is created or started by any technique in this note, a genuine contrast with the SCM-based tools elsewhere in this module (`Impacket/smbexec/`, `Impacket/psexec/`) |

## Sysmon (if deployed)

| Event ID | Signal |
|---|---|
| **1 (Process Create)** | **Highest-value single artifact for this technique.** `CommandLine` captures the full verb and arguments — `-urlcache -f <url> <outfile>`, `-decode <infile> <outfile>`, etc. — regardless of whether native 4688 command-line auditing is separately enabled, since Sysmon captures it independently. `Image` will read `certutil.exe` unless the renamed/relocated-binary variant from `02 - Hands-On Use Cases.md` was used, in which case only `OriginalFileName` (from the PE's own embedded metadata, which Sysmon also captures) and the Authenticode signature still tie it back to the genuine Microsoft binary |
| 3 (Network Connect) | Outbound HTTP/HTTPS connection for the download verbs, absent entirely for the local-only encode/decode/hex verbs — a useful binary split when triaging which technique class fired |
| 11 (File Create) | Fires for both the explicit `OutFile` and the `CryptnetUrlCache\Content\<hash>` side-effect write — two Sysmon 11 events per download-verb invocation is itself a distinguishing pattern versus a single file-create from an ordinary tool |
| 13 (Registry Value Set) | **Not expected** — consistent with the "no verified registry artifact" finding above |
| 22 (DNS Query) | The hostname resolution preceding the download verbs' HTTP(S) connection |

## Network-Layer Evidence

| Source | What It Shows |
|---|---|
| Proxy / firewall access logs | The request itself, plus certutil's own characteristic **`User-Agent`** strings — `Microsoft-CryptoAPI/10.0` or `CertUtil URL Agent`, both listed as IOCs directly in the LOLBAS Project's `Certutil.yml` detection/IOC catalog. Either UA appearing against an unexpected destination (not a known Microsoft/CA endpoint) is a strong independent signal, catchable even without endpoint telemetry |
| Zeek `http.log` | The full request URI, response size, and the certutil UA string in one place — useful for a fleet-wide pivot once one host's certutil-UA request against a suspicious host is confirmed |
| NetFlow | A short-lived outbound TCP 80/443 connection, one per download-verb invocation — no persistent session the way a C2 beacon or an interactive tool's connection would show |

## Endpoint Security Product Signatures

Because the delivery mechanism is a legitimate, Microsoft-signed binary and the payload transform (Base64/hex) is not inherently malicious, static file-signature detection on `certutil.exe` itself is a non-starter — detection instead depends on behavioral/command-line heuristics. This is well-trodden enough ground that public detection-rule repositories carry specific, maintained rules for exactly these patterns — cited directly from the LOLBAS Project's own `Certutil.yml` detection catalog:

- **Sigma:** [`proc_creation_win_certutil_download.yml`](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_certutil_download.yml), [`proc_creation_win_certutil_encode.yml`](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_certutil_encode.yml), [`proc_creation_win_certutil_decode.yml`](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_certutil_decode.yml)
- **Elastic:** [`defense_evasion_suspicious_certutil_commands.toml`](https://github.com/elastic/detection-rules/blob/4a11ef9514938e7a7e32cf5f379e975cebf5aed3/rules/windows/defense_evasion_suspicious_certutil_commands.toml), [`command_and_control_certutil_network_connection.toml`](https://github.com/elastic/detection-rules/blob/12577f7380f324fcee06dab3218582f4a11833e7/rules/windows/command_and_control_certutil_network_connection.toml)
- **Splunk:** [`certutil_download_with_urlcache_and_split_arguments.yml`](https://github.com/splunk/security_content/blob/3f77e24974239fcb7a339080a1a483e6bad84a82/detections/endpoint/certutil_download_with_urlcache_and_split_arguments.yml), [`certutil_download_with_verifyctl_and_split_arguments.yml`](https://github.com/splunk/security_content/blob/3f77e24974239fcb7a339080a1a483e6bad84a82/detections/endpoint/certutil_download_with_verifyctl_and_split_arguments.yml), [`certutil_with_decode_argument.yml`](https://github.com/splunk/security_content/blob/3f77e24974239fcb7a339080a1a483e6bad84a82/detections/endpoint/certutil_with_decode_argument.yml)

Most mainstream EDR products carry equivalent built-in behavioral detections for the `-urlcache`/`-decode` command-line patterns given how long this technique has been public — the absence of any such alert on a host that otherwise shows the Sysmon/4688 pattern above is itself worth investigating (product misconfiguration, exclusion, or tamper).

## Memory Forensics

`certutil.exe` instances involved in these techniques run as ordinary, short-lived, non-hidden processes — standard process-listing/injection-detection tooling (see `Windows/17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md`) shows nothing structurally unusual. The technique's forensic value in memory is limited: the command-line arguments (URL, file paths) are already fully recoverable from Sysmon 1/Security 4688 if either is enabled, and the encode/decode verbs never hold long-lived secrets in memory the way a credential-handling tool would — the only content passing through process memory is the payload bytes themselves during the brief conversion window.

## Building a Timeline

The tightest anchor sequence, per invocation: **Sysmon 1 (process create, full command line) → Sysmon 22 (DNS query, download verbs only) → Sysmon 3 (network connect, download verbs only) → Sysmon 11 ×2 (explicit `OutFile` create + `CryptnetUrlCache\Content\<hash>` create, download verbs only) → Security 4688 (if command-line auditing is separately enabled, corroborating Sysmon 1).** For the encode/decode verbs, drop the network-related steps entirely — the sequence collapses to just process-create plus a single file-create for `OutFile`. Because the `CryptnetUrlCache\MetaData\<hash>` entry itself carries a parseable download timestamp, it functions as a secondary, independently-recoverable timeline source even in an environment with no process-creation logging at all.

## Distinguishing Abuse from Legitimate CA Administration

> 🔴 A `certutil.exe` process-creation event alone is not a finding — this binary runs constantly and legitimately on any estate running AD CS. **The command-line argument is the entire signal.**

| Dimension | Legitimate CA administration | Abuse (this note) |
|---|---|---|
| Verb | `-CAInfo`, `-ping`, `-store`, `-dump`, `-GetCRL` against a known internal CA | `-urlcache`, `-verifyctl`, `-URL` against an arbitrary Internet URL; `-encode`/`-decode`/hex variants against non-certificate files |
| Target | Internal CA hostname, local certificate store name | Internet URL, or an `InFile`/`OutFile` pair with no certificate-related file extension or content |
| Typical operator | Domain-joined PKI/CA administrator, often from the CA server itself or a dedicated admin workstation | Any process with code execution — a macro, a script, a C2 implant |
| Network destination | Internal CA/AD infrastructure | External IP/domain, frequently newly-registered or otherwise low-reputation |
| CryptnetUrlCache entries | Legitimate CRL/AIA/CTL fetches from Microsoft or the organization's own CA endpoints | An `.exe`/`.ps1`/`.b64` payload fetched from attacker infrastructure — the `MetaData` URL field is the fastest way to tell the two apart once the cache entry is located |
