# Impacket — ticketer.py — Target Evidence

`ticketer.py`'s own execution, in its default mode, touches **no target host at all** — the forging step is pure local computation (`01 - Overview.md`). This file is organized around that fact rather than fighting it: it covers (1) the genuine, tool-specific target-side evidence `-request`/`-impersonate` generate **at forging time** — evidence that has no equivalent anywhere in the Mimikatz note, since Mimikatz has no "fetch a real ticket first" mode — and (2) evidence of the forged ticket's **use**, which is identical regardless of which tool forged it and is therefore cross-linked to `Mimikatz/kerberos (Golden-Silver Ticket)/04 - Target Evidence.md` rather than re-derived, plus what's specifically different about *how* a `.ccache`-based ticket shows up when consumed via an Impacket tool's `-k` flag versus the four already-built Impacket sub-tools' own password/hash-based Target Evidence coverage.

## Contents
- [Default Forge (Golden/Silver, No -request/-impersonate) — Zero Target Evidence at Creation](#default-forge-goldensilver-no--request-impersonate--zero-target-evidence-at-creation)
- [-request (Diamond) — Genuine KDC Contact at Forging Time](#-request-diamond--genuine-kdc-contact-at-forging-time)
- [-impersonate (Sapphire) — A Second Genuine Exchange](#-impersonate-sapphire--a-second-genuine-exchange)
- [Evidence of Using the Forged Ticket](#evidence-of-using-the-forged-ticket)
- [Building a Timeline](#building-a-timeline)

---

## Default Forge (Golden/Silver, No `-request`/`-impersonate`) — Zero Target Evidence at Creation

> 🔴 **Say this plainly rather than padding it:** no Domain Controller, no target application server, and no intermediate network device sees anything at all when `ticketer.py` runs in its default mode. There is no file, no registry key, no event log entry, no network packet — nothing for any target-side detection surface to observe, because the tool's own execution never leaves the operator's machine. This is the exact same structural fact `Impacket/secretsdump/04 - Target Evidence.md`'s Path 3 (offline/local mode) documents for that tool, and `Mimikatz/kerberos (Golden-Silver Ticket)/03 - Source Evidence.md` documents for `kuhl_m_kerberos_golden_data()` — all three are pure local computation with the same zero-target-footprint consequence.

**Once the resulting `.ccache` is used**, the target-side evidence is **identical** to what `Mimikatz/kerberos (Golden-Silver Ticket)/04 - Target Evidence.md` documents in full depth — the DC-side 4768/4769 missing-prior-issuance heuristic, the MDI Golden-Ticket-family alerts (2027/2032/2040/2022/2009/2013), the Silver Ticket detection gap, the target-application-server 4624/4672 evidence — because the technique being exploited (a KDC/target server trusting a signature computed with a key it genuinely holds) is exactly the same regardless of which tool produced the forged bytes. **Not re-derived here.** The one caveat worth restating explicitly: that note's PAC/event-ID analysis was written against Mimikatz's `.kirbi` output injected via `kerberos::ptt` into a Windows LSA session; a `ticketer.py`-forged ticket reaches the same protocol state via a different path — consumed via `-k`/`KRB5CCNAME` by another Impacket example script, entirely on Linux, with no Windows LSA session ever involved. The DC-side and target-application-server evidence is unaffected by this distinction (the wire protocol is identical either way); what *does* differ is covered below.

## `-request` (Diamond) — Genuine KDC Contact at Forging Time

This is the one target-side evidence category that is **entirely specific to `ticketer.py`** and has no Mimikatz equivalent, verified directly from `createBasicTicket()`'s `-request` branch (`01 - Overview.md`):

| Event | Fires when | Tied to |
|---|---|---|
| **Security 4768** (TGT requested) | Always, for any `-request` run | The `-user` account supplied for authentication — **not** the forged identity (`target`) the final ticket will claim to be |
| **Security 4769** (TGS requested) | Only if `-spn` is also set (a Diamond-style Silver forge, cloning a TGS template instead of a TGT) | Same `-user` account, requesting the specific `-spn` given |

**The critical analytical point:** these are **completely genuine, correctly-issued** Kerberos events — the KDC is doing real work for a real (if possibly low-privileged) account, and there is nothing structurally anomalous about either event in isolation. What makes this worth hunting is the **sequence**: a `-user` account that legitimately requests a TGT/TGS, immediately followed — from the same source host — by that source host later presenting a *different* forged identity's ticket somewhere else in the environment (the "use" evidence below). Neither half alone is suspicious; the pairing is. This is a fundamentally different hunt shape from anything in `Mimikatz/kerberos (Golden-Silver Ticket)/05 - Detection and Hunting.md`, which has no "real template fetch" step to correlate against at all.

## `-impersonate` (Sapphire) — A Second Genuine Exchange

If `-impersonate` is layered on top of `-request`, `getKerberosS4U2SelfU2U()` generates a **second, separate** genuine `TGS-REQ`/`TGS-REP`:

| Event | Detail |
|---|---|
| **Security 4769** | Fires for the `-user` account, requesting (via S4U2Self) a service ticket "to itself," naming the `-impersonate` target in the request's `PA-FOR-USER` padata, with `enc-tkt-in-skey` set (the User-to-User flag) |

Structurally, this is the same shape any legitimate S4U2Self+U2U usage produces (constrained-delegation-capable services routinely do this for real business reasons) — there is no field in this event that flags it as illegitimate on its own. **This repo does not currently have a dedicated S4U2Self/constrained-delegation-abuse note to cross-link for deeper mechanics** — treat this section as a pointer to a real, source-verified gap rather than an implied "see elsewhere" that doesn't exist yet. The practically useful signal is the same pairing logic as the Diamond Ticket case above: an account not normally configured for constrained delegation, suddenly performing S4U2Self+U2U, from a source host that shortly afterward presents a different, high-privilege identity's ticket elsewhere.

**No Microsoft Defender for Identity alert specific to this exact `-request`+`-impersonate` sequence is confirmed here** — MDI's published Golden-Ticket-family alerts (`Mimikatz/kerberos (Golden-Silver Ticket)/04 - Target Evidence.md`) key on the *forged ticket's use*, not on a legitimate-looking S4U2Self+U2U exchange that merely *feeds* a forgery. Flag this as an open question rather than asserting an alert ID that hasn't been verified against Microsoft's current alert catalog.

## Evidence of Using the Forged Ticket

Once a `.ccache` (forged by any of the modes above) is exported via `KRB5CCNAME` and consumed by another tool's `-k` flag, the resulting target-side evidence belongs to *that* tool's own Target Evidence coverage — not re-derived here:

- `Impacket/psexec/04 - Target Evidence.md`
- `Impacket/wmiexec/04 - Target Evidence.md`
- `Impacket/smbexec/04 - Target Evidence.md`
- `Impacket/secretsdump/04 - Target Evidence.md`

**What's specifically different about `-k`/ccache-based authentication versus those files' primary password/hash-based coverage:** Security 4624's `AuthenticationPackageName` field reads **`Kerberos`** instead of **`NTLM`**, and the NTLM-specific sub-fields those events normally carry (`LmPackageName`, `KeyLength` in the NTLM sense) are absent/blank — the logon looks structurally like *any* Kerberos-authenticated session, because from the target's perspective, it is one; nothing at the target server distinguishes a `ticketer.py`-forged ticket's `AP-REQ` from a legitimate one at this layer (same limitation `Mimikatz/kerberos (Golden-Silver Ticket)/04 - Target Evidence.md`'s "Target Application Server: Memory Forensics" section documents for Mimikatz-forged tickets). Where those four sibling files' hunts lean on NTLM-specific fields or command-line-embedded password/hash material, a `-k`-authenticated session run from a forged ticket **will not produce that evidence at all** — an investigator expecting to find a hash or password in a 4624/process-creation event for a `-k`-driven `psexec.py`/`wmiexec.py`/`smbexec.py` session will find none, because none was ever presented.

## Building a Timeline

**Default forge, then used via another Impacket tool:**
```
[Forging — pure local computation, zero artifacts anywhere except the operator's own host/process memory]
  → [.ccache saved to disk, KRB5CCNAME exported — 03 - Source Evidence.md]
  → [Some later time: -k auth via psexec.py/wmiexec.py/smbexec.py/secretsdump.py]
      → [Target-side evidence identical to that tool's own 04, but AuthenticationPackageName: Kerberos]
      → [If Golden: DC-side 4769-with-no-prior-4768, MDI alerts — Mimikatz/kerberos (Golden-Silver Ticket)/04]
      → [If Silver: NOTHING DC-side, ever — same detection gap as the Mimikatz note documents]
```

**`-request` (Diamond) forge:**
```
[Genuine 4768 (or 4768+4769 if -spn set) for the -user account — REAL target-side evidence,
 generated by ticketer.py's OWN execution, unique to this tool among everything covered
 in this Impacket folder]
  → [Ticket decrypted/modified/re-signed locally — no further network activity]
  → [.ccache saved — 03 - Source Evidence.md]
  → [Some later time: used via another tool, same "Evidence of Using" pattern above]
```

**`-request` + `-impersonate` (Sapphire) forge:** identical to the Diamond sequence above, with an additional genuine 4769 (S4U2Self+U2U, `-user` requesting on behalf of `-impersonate`) inserted between the initial TGT fetch and the local PAC-splicing/re-signing step.
