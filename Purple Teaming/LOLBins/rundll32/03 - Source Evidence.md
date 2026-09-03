# LOLBins — rundll32.exe — Source Evidence

**Framing note:** `rundll32.exe` is a native Windows binary that always runs on the victim — there is no separate "rundll32 operator box." Source-side evidence is: (1) the **attacker-controlled infrastructure** hosting the DLL (if remote loading), (2) the **delivery/tasking layer** that issued the rundll32 command, and (3) whatever the operator did on their own machine to build the malicious DLL. All of `rundll32.exe`'s own execution evidence is target-side, covered in `04 - Target Evidence.md`.

## Contents
- [Attacker-Side DLL-Hosting Infrastructure](#attacker-side-dll-hosting-infrastructure)
- [C2 Tasking Layer](#c2-tasking-layer)
- [DLL Creation on the Operator's Own Machine](#dll-creation-on-the-operators-own-machine)
- [Delivery-Mechanism Artifacts](#delivery-mechanism-artifacts)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Attacker-Side DLL-Hosting Infrastructure

For remote DLL loading (where supported/used):

| Artifact | Where | Notes |
|---|---|---|
| Web server access log | `access.log` | A request for `payload.dll` with `User-Agent` from rundll32 (`Mozilla/4.0` or minimal system UA). |
| DLL binary itself | Seized server storage | The actual `.dll` file (Windows PE binary) is recoverable; reverse engineering provides visibility into the payload logic and capabilities. |
| TLS metadata | Passive DNS, certificate transparency | Standard attacker-infrastructure attribution. |

## C2 Tasking Layer

Where `rundll32.exe` was invoked via C2 task history:

- **C2 server logs** record the exact `rundll32 <DLL> <function>` command tasked, including timestamp and target host.
- If recovered, this provides a complete timeline of rundll32 abuse across compromised hosts.

## DLL Creation on the Operator's Own Machine

If the operator compiled/generated the malicious DLL locally:

| Artifact | Notes |
|---|---|
| Visual Studio / compiler artifacts | If compiled locally, the `.pdb` debug file, intermediate object files, build logs may exist (if not cleaned). |
| Reverse-engineering artifacts | IDA Pro, Ghidra, or other analysis tool artifacts from the operator's development machine. |
| Payload generator execution | Evidence of `msfvenom -f dll ...`, a C# compiler (for inline C# payloads), or other DLL-build tools running on the staging box. |
| Generated `.dll` file | If not securely deleted, the DLL itself is recoverable. |

## Delivery-Mechanism Artifacts

The mechanism that delivered the rundll32 command (macro, script, C2 task) carries its own independent evidence trail.

## Timeline Correlation Value

Target-side evidence (the rundll32 command-line DLL path/URL and timestamp) is the primary anchor. Source-side infrastructure/development artifacts extend that timeline outward.
