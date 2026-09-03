# Metasploit — Encoders and Evasion — Target Evidence

Encoders and evasion modules don't independently create target-side artifacts beyond what the **wrapped payload itself** produces once executed — full payload-behavior evidence (Meterpreter's process/network/memory footprint, service-based execution artifacts, etc.) is covered in depth in `../Meterpreter/04 - Target Evidence.md` and is not re-derived here. This file focuses on what's specific to the **fact that the delivered file was encoded or built by an evasion module**, layered on top of that baseline.

## Contents
- [Filesystem](#filesystem)
- [Static File Structure](#static-file-structure)
- [Endpoint-Security-Product Signature Behavior](#endpoint-security-product-signature-behavior)
- [Behavioral / Runtime Evidence](#behavioral--runtime-evidence)
- [Memory Artifacts](#memory-artifacts)
- [Building a Timeline](#building-a-timeline)
- [Distinguishing Encoded/Evasive Payloads from Legitimate Software](#distinguishing-encodedevasive-payloads-from-legitimate-software)

---

## Filesystem

The dropped file itself is the primary target-side artifact — same filesystem-timeline value (creation/modification timestamps, MFT entry, `$STANDARD_INFORMATION`/`$FILE_NAME` timestamp comparison for anti-forensic timestomping) as any dropped executable, covered generically for msfvenom output in `../msfvenom/04 - Target Evidence.md`'s Filesystem section — not re-derived here. What's specific to *encoded* output: the file's on-disk bytes differ from an unencoded generation of the same payload, so hash-based detection/hunting (a known-bad hash list, a prior IOC from the same campaign) only works if the specific encoded variant was already seen — a re-encode with a different `-i` count or a different encoder produces a different hash even though the underlying payload and its runtime behavior are identical. This is the direct target-side consequence of the mechanic described in `01 - Overview.md`'s How It Works.

## Static File Structure

- **Entropy contrast** — the same signal `../msfvenom/01 - Overview.md`'s red-flag callout and `../msfvenom/04 - Target Evidence.md` describe for msfvenom output generally applies here, with one refinement specific to encoding: the encoded payload region (decoder stub + XORed/transformed body) is **itself high-entropy relative to the stub's own decoder logic** — a byte-level entropy scan across the file will show the low-entropy decoder-stub instructions immediately followed by a sharp jump into the high-entropy encoded body, a two-tier pattern that's slightly more specific than the flat "injected code region" signature of an unencoded payload.
- **Decoder-stub byte pattern** — `shikata_ga_nai`'s GetPC-stub-plus-additive-feedback-XOR construction has a recognizable instruction-sequence shape at the *start* of the encoded blob, even though the polymorphic engine varies the specific opcodes/ordering each time. YARA rules targeting `shikata_ga_nai` output typically match structural/statistical properties of this stub region (instruction-class sequences, common register-usage patterns for the GetPC mechanism) rather than a fixed byte string — this is why "the decoder stub itself is signatured" (per `01 - Overview.md`'s red-flag) survives the polymorphic mutation in a way a literal byte-string match wouldn't.
- **Evasion-module-specific structure** — RC4-encrypted shellcode (`windows_defender_exe`) presents as high-entropy ciphertext rather than a recognizable decoder-stub pattern, since RC4 key material and the decrypt routine are separate from the payload bytes; the custom-compiler output structure and specific anti-emulation check implementation are module-specific details **not verified in this pass** — flagged consistent with `01 - Overview.md`'s scope note for the deferred follow-up.

## Endpoint-Security-Product Signature Behavior

- **Static AV** — this is the layer encoding was designed to affect, and mainstream products have closed the gap substantially: both the raw payload signature *and* well-known decoder-stub shapes (`shikata_ga_nai` foremost among them, given its age and ubiquity) are commonly signatured. A modern AV product failing to flag a `shikata_ga_nai`-encoded Meterpreter payload on-disk is a more notable finding today than one that does.
- **Behavioral EDR** — unaffected by encoding, full stop. Per `01 - Overview.md` and consistent with `../Meterpreter/05 - Detection and Hunting.md`'s treatment of the same point: encoding changes what the file looks like before the decoder stub runs, not what the payload does once it's running. The API-call sequence, memory-permission transitions (`VirtualAlloc`/`VirtualProtect` RWX), and any reflective-loading/process-injection behavior are identical whether the payload was encoded zero times or ten.
- **Evasion-module-specific behavioral considerations** — a module's anti-emulation check (per `windows_defender_exe`'s documented technique) specifically targets the **emulation/sandbox stage** of a detection pipeline, not live EDR on an actual endpoint; once running on a real machine (not a sandbox), the payload's runtime behavior is subject to the same behavioral detection as any other instance of that payload.

## Behavioral / Runtime Evidence

Fully inherited from the wrapped payload — see `../Meterpreter/04 - Target Evidence.md` for Meterpreter-family payloads specifically (process tree, reflective DLL loading signature, network protocol detail) and `../msfvenom/04 - Target Evidence.md` for payload-agnostic behavioral notes. Nothing about having been encoded or generated via an evasion module changes this layer.

## Memory Artifacts

Once the decoder stub has run and the payload is executing, in-memory forensics sees the **decoded** payload, not the encoded on-disk representation — a memory-resident scan (Volatility `malfind`, YARA-in-memory) targeting the raw payload's known signature works identically regardless of what encoding wrapped the file on disk, since decoding has already happened by the time the payload is live in memory. This is a materially different picture from static disk-based detection and is worth stating explicitly in a report: **encoding defeats static disk scanning; it has zero effect on memory-resident detection of the running payload.** Full memory-forensics detail for the payload itself is in `../Meterpreter/04 - Target Evidence.md`.

## Building a Timeline

1. **Filesystem drop** — creation timestamp of the encoded/evasive file on the target (adjust for timestomping if `$STANDARD_INFORMATION`/`$FILE_NAME` diverge).
2. **Execution** — Prefetch, process-creation event (Security 4688, Sysmon 1), or service-start artifact, depending on delivery mechanism — same event sources as `../msfvenom/04 - Target Evidence.md` and `../Meterpreter/04 - Target Evidence.md`, not duplicated here.
3. **Decode-to-execute gap** — for a heavily-iterated encoding (`-i` high count) or a compiler-heavy evasion module, there can be a measurable startup delay between process creation and the payload's first network callback, as the decoder stub(s) unwind and any anti-emulation check runs — a longer-than-typical gap between a process-creation event and the corresponding network-connection event for that process is a soft timeline signal worth noting, though not one to rely on alone.
4. **Correlate to source** — match the target-side dropped file's hash/structural fingerprint back to the source-side generated-file artifact in `03 - Source Evidence.md`, where a filesystem timestamp or history-line timestamp on the operator host anchors the "when was this built" side of the timeline against "when did it land/run" on the target.

## Distinguishing Encoded/Evasive Payloads from Legitimate Software

The clearest tell that a binary is msfvenom/evasion-module output rather than legitimate software isn't the encoding itself — it's the **structural injection signature** (entropy contrast, template-vs-injected-code mismatch) described throughout `../msfvenom/01 - Overview.md` and `04 - Target Evidence.md`, which persists regardless of encoding choice. Encoding/evasion-module use is best read as a **secondary confirming signal** ("this operator specifically tried to defeat static AV, versus just wrapping a payload in a template unencoded") rather than the primary detection hook — treat a decoder-stub match or RC4-ciphertext-shaped high-entropy region as evidence of *intent and sophistication level*, and the underlying injection/template mismatch as the primary "this file is msfvenom/evasion-module output" determination.
