# Acquiring Memory

Live **memory acquisition** on macOS is **hard** — SIP, kernel hardening, and Apple Silicon block the kernel-memory access that RAM imaging needs, so most free tools fail on modern systems. The practical reality: **Volexity Surge** is effectively the **only reliable** acquisition tool, **Volatility 3** has limited (often broken) macOS support, and **Volexity Volcano** is the best bet for analysis. EDR/XDR can frequently grab memory on demand too.

> 🔴 Memory is **volatile** — capture it **before shutdown** (a reboot loses it forever) and before other live actions if you can. RAM holds FileVault keys, injected code, decrypted data, network state, and process artifacts that exist **nowhere on disk**.

## Contents
- [Quick Triage](#quick-triage)
- [Why It Is Hard on macOS](#why-it-is-hard-on-macos)
- [Acquisition Tools](#acquisition-tools)
- [Analysis Tools](#analysis-tools)
- [EDR and XDR Option](#edr-and-xdr-option)
- [Workflow](#workflow)
- [Pitfalls and Chain of Custody](#pitfalls-and-chain-of-custody)
- [Resources](#resources)

---

## Quick Triage

```
1. Decide FAST — memory is volatile; do NOT reboot/shutdown first.
2. Acquire with Volexity Surge (reliable, supports Apple Silicon + current macOS)
   — or trigger an EDR/XDR memory dump if you have one deployed.
3. Capture to EXTERNAL evidence media; hash the dump.
4. Analyze with Volexity Volcano (best) or Volatility 3 (limited on macOS).
```

---

## Why It Is Hard on macOS

| Obstacle | Effect |
|---|---|
| 🔴 **SIP / kernel hardening** | No `/dev/mem`; reading kernel memory needs a signed kext / special entitlement |
| 🔴 **Apple Silicon** | Architecture + Secure Enclave make raw RAM capture far harder; many tools don't support it |
| Frequent kernel changes | Symbol tables / profiles break across macOS versions |
| Notarization/codesigning | A capture kext must be Apple-blessed — most open tools aren't |

> The result: the old "load a kext, dump RAM" approach largely **doesn't work** on modern, SIP-enabled, Apple-Silicon Macs — which is why a maintained commercial tool is usually required.

---

## Acquisition Tools

| Tool | Notes |
|---|---|
| 🔴 **Volexity Surge** (paid) | The **reliable** choice — supports current macOS incl. **Apple Silicon**; handles the kernel-access problem |
| Open-source kext-based dumpers | Generally **broken/unsupported** on modern macOS (SIP, signing, Apple Silicon) |
| EDR/XDR memory dump | On-demand, gated — often works (see below) |

---

## Analysis Tools

| Tool | Notes |
|---|---|
| 🔴 **Volexity Volcano** | Best bet for **macOS memory analysis** |
| **Volatility 3** | macOS support exists but is **limited** — symbol-table/version issues; may not parse modern captures |
| Surge (built-in analysis) | Surge also assists with triage/analysis of its captures |

> Build/obtain the correct **symbol table** for the exact macOS/kernel version if using Volatility 3 — version mismatch is the usual failure.

---

## EDR and XDR Option

🔴 If the environment has **EDR/XDR**, it's **not hopeless**: most can perform **process** or even **full memory** dumps — usually **gated and on-demand** rather than continuous. In an enterprise IR, triggering an EDR/XDR memory collection is often a viable way to grab RAM when you can't run a local acquisition tool.

---

## Workflow

1. **Don't reboot/shutdown** — memory is volatile.
2. Prefer **Volexity Surge** on the live system (or trigger an **EDR/XDR** memory dump).
3. Write the capture to **external evidence media**.
4. **Hash** the dump; record collector, time (TZ), host, macOS/kernel version.
5. If the Mac has **FileVault on and is unlocked**, RAM may hold the key — capture memory **before** powering down (cross-ref FileVault).
6. Analyze with **Volcano** (or Volatility 3 with the matching symbol table).

---

## Pitfalls and Chain of Custody

| 🔴 Pitfall | Avoid by |
|---|---|
| Rebooting/shutting down first | Capture memory **before** any power change |
| Relying on free kext dumpers on modern macOS | Use Surge / EDR — open tools usually fail |
| Wrong Volatility symbol table | Match the exact macOS/kernel version |
| Writing to subject disk | External evidence media only |
| No integrity record | Hash the dump; document host/time/version |
| Assuming Apple Silicon = impossible | Surge supports it; EDR can often dump |

---

## Resources

- Volexity Surge (acquisition): https://www.volexity.com/products-overview/surge/
- Volexity Volcano (analysis): https://www.volexity.com/products-overview/volcano/
- Volatility 3 macOS tutorial: https://volatility3.readthedocs.io/en/latest/getting-started-mac-tutorial.html
- How to Perform Memory Forensic Analysis in macOS Using Volatility 3: https://cpuu.hashnode.dev/how-to-perform-memory-forensic-analysis-in-macos-using-volatility-3
