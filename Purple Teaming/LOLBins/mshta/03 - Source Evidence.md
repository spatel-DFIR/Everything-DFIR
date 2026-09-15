# LOLBins — mshta.exe — Source Evidence

**Framing note:** `mshta.exe` is a native Windows binary that always runs on the victim/target host — there is no separate "mshta operator box." Source-side evidence is: (1) the **attacker-controlled infrastructure** hosting the HTA payload, (2) the **delivery/tasking layer** that issued the mshta command, and (3) whatever the operator did on their own machine to craft the HTA file. All of `mshta.exe`'s own execution evidence is target-side, covered in `04 - Target Evidence.md`.

## Contents
- [Attacker-Side Web/Payload-Hosting Infrastructure](#attacker-side-webpayload-hosting-infrastructure)
- [C2 Tasking Layer](#c2-tasking-layer)
- [HTA Creation on the Operator's Own Machine](#hta-creation-on-the-operators-own-machine)
- [Delivery-Mechanism Artifacts](#delivery-mechanism-artifacts)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Attacker-Side Web/Payload-Hosting Infrastructure

For every remote HTA use case, the HTTP/HTTPS request lands on attacker infrastructure:

| Artifact | Where | Notes |
|---|---|---|
| Web server access log | `access.log` (Apache/nginx) | A request for `payload.hta` or similar will show in access logs with a `User-Agent` from `mshta.exe` — typically `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT ...)` (mshta uses the IE rendering engine) or a bare system user-agent. A burst from the same source IP indicates multiple victims fetching the same HTA. |
| Requested filename | Same log | The exact filename/URI requested (`payload.hta`, `stage2.hta`, etc.) correlates against target-side Sysmon records independently. |
| TLS certificate / hosting metadata | Passive DNS, certificate transparency logs, WHOIS | Standard attacker-infrastructure attribution work. |
| HTA source code | Seized server storage | The `.hta` file itself is human-readable HTML; if recovered, provides visibility into the exact payload logic, C2 identifiers, and staging mechanics. |

## C2 Tasking Layer

Where `mshta.exe` was invoked via a C2 framework's command-execution feature:

- **C2 server task history** logs the exact `mshta http://...` command tasked to the implant, including timestamp and target host.
- If the C2 server is recovered, this history is a complete, timestamped record of every mshta invocation across every compromised host.

## HTA Creation on the Operator's Own Machine

If the operator generated/crafted the HTA file locally (e.g., using msfvenom, Empire launcher, or custom scripts) before uploading to the attacker's hosting infrastructure:

| Artifact | Notes |
|---|---|
| PowerShell/cmd history | Evidence of HTA-generator tools being run (e.g., `msfvenom -f hta-psh ...`) |
| Generated `.hta` intermediate file | If not securely deleted, recoverable via forensics — a human-readable HTML file disclosing the payload logic |
| Temporary files | Generator tools often create temp files during build; may survive on the staging box |

## Delivery-Mechanism Artifacts

The mechanism that delivered the mshta command (macro, script, C2 task) carries its own independent evidence trail, covered in that delivery mechanism's own tool documentation.

## Timeline Correlation Value

Target-side evidence (the mshta command-line URL and timestamp) is the primary anchor. Source-side artifacts (attacker-hosted HTA, C2 task history) extend that timeline outward.
