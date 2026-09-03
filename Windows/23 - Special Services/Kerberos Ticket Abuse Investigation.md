# Kerberos Ticket Abuse Investigation

Ticket mechanics, the AS-REQ/TGS-REQ flow, the DC-side event IDs (4768/4769/4770/4771), and the four classic abuse techniques' baseline DFIR signatures — Golden Ticket, Silver Ticket, Kerberoasting, AS-REP Roasting — are already covered in full in [`05b - Active Directory & Domain Forensic Artifacts` § Kerberos Fundamentals for DFIR](<../05b - Active Directory & Domain Forensic Artifacts.md#kerberos-fundamentals-for-dfir>) and [§ Kerberos Abuse Techniques and Their DFIR Signatures](<../05b - Active Directory & Domain Forensic Artifacts.md#kerberos-abuse-techniques-and-their-dfir-signatures>). This note does not re-explain any of that. It exists for the moment an analyst is past "what is Kerberos abuse" and into "I have a lead — a SIEM alert, a suspicious 4769, a hunch about a stolen ticket — now what do I actually do, in order, on the host and against the DC, to work this case." `05b` is the reference catalog; this is the operational workflow that sits on top of it.

> 🔴 **The central investigative principle this whole note is built around: Kerberos ticket abuse lives at the seam between two logs that no single host holds both halves of.** The DC sees ticket issuance; the target host sees the session the ticket bought. Golden and AS-REP abuse show up as an odd *pattern* within DC-side events; Silver Ticket abuse shows up as the *absence* of a DC-side event that should have paired with something real on the target host; Pass-the-Ticket abuse shows up as the *same* legitimate-looking ticket surfacing in two places it shouldn't both be. None of these are visible from either log in isolation — every step below is, at its core, a specific way of correlating DC-side ticket events against host-side session/ticket-cache evidence.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Investigation Workflow](#investigation-workflow)
  - [Step 1 — Triage the Suspicious Ticket Event (4768/4769/4771)](#step-1--triage-the-suspicious-ticket-event-476847694771)
  - [Step 2 — Live Host Ticket-Cache Inspection](#step-2--live-host-ticket-cache-inspection)
  - [Step 3 — Golden Ticket Investigation](#step-3--golden-ticket-investigation)
  - [Step 4 — Silver Ticket Investigation](#step-4--silver-ticket-investigation)
  - [Step 5 — Pass-the-Ticket Investigation](#step-5--pass-the-ticket-investigation)
  - [Step 6 — Delegation-Abuse Live-Investigation Sequence](#step-6--delegation-abuse-live-investigation-sequence)
  - [Step 7 — Estate-Wide Kerberoasting Sweep](#step-7--estate-wide-kerberoasting-sweep)
- [Technique Comparison](#technique-comparison)
- [Investigative Sequence Summary](#investigative-sequence-summary)
- [Pitfalls](#pitfalls)
- [Red Flags](#red-flags)
- [MITRE ATT&CK Techniques Covered](#mitre-attck-techniques-covered)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native `klist` first-class alongside PowerShell here — ticket-cache inspection has no PowerShell-native equivalent, and the DC-side pulls below lean on `-FilterXPath` (per note 11's guidance) rather than guessing at `.Properties[]` array indices, which drift across OS builds.

```powershell
# Current logon session's live ticket cache - no elevation required, the fastest first look (Step 2)
klist

# Enumerate every logon session on this host (elevated prompt required) - find the LogonId to target next (Step 2)
klist sessions

# Inspect a specific logon session's ticket cache by LogonId (elevated prompt required) - the other-session/service-account pull (Step 2)
klist -li 0x<LogonId>

# One suspicious 4769, full field dump via XML rather than fragile .Message regex - the Step 1 triage pull
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4769]]" -MaxEvents 1 |
    ForEach-Object { ([xml]$_.ToXml()).Event.EventData.Data | Select-Object Name, '#text' }

# Domain's actual configured Kerberos ticket-lifetime policy - the ground truth for Step 3's lifetime-vs-policy check
secedit /export /cfg $env:TEMP\kerbpol.cfg /areas KERBEROS
Select-String -Path $env:TEMP\kerbpol.cfg -Pattern 'MaxTicketAge|MaxRenewAge|MaxServiceAge|MaxClockSkew'

# RC4 4769s against many distinct SPNs from one account, last 2 hours, this DC only - condensed single-DC version of Step 7's estate sweep
$xpath = "*[System[(EventID=4769) and TimeCreated[timediff(@SystemTime) <= 7200000]] and EventData[Data[@Name='TicketEncryptionType']='0x17']]"
Get-WinEvent -LogName Security -FilterXPath $xpath -ErrorAction SilentlyContinue | ForEach-Object {
    $d = ([xml]$_.ToXml()).Event.EventData.Data
    [PSCustomObject]@{ Account = ($d | Where-Object Name -eq 'TargetUserName').'#text'; SPN = ($d | Where-Object Name -eq 'ServiceName').'#text' }
} | Group-Object Account | Select-Object Name, Count, @{N='DistinctSPNs'; E={($_.Group.SPN | Sort-Object -Unique).Count}}
```

## Investigation Workflow

### Step 1 — Triage the Suspicious Ticket Event (4768/4769/4771)

The lead is almost always one event: an alert fires on a 4769, or an analyst is handed a single 4768/4771 to make sense of. Before deciding this is (or isn't) abuse, pull the full field set — not just the account name — and read three fields specifically.

**The encryption-type field is the single strongest tell available in one field, and it's worth understanding *why* before anything else.** Windows clients from Vista/Server 2008 onward request **AES** (`0x11` = AES128, `0x12` = AES256) by default whenever the target account's `msDS-SupportedEncryptionTypes` advertises AES support — which almost every account in a modernized domain does. **RC4 (`0x17`)** on a domain that has supported AES for years is not merely "different," it is the specific downgrade an attacker's tooling chooses deliberately: an RC4-encrypted service ticket is orders of magnitude cheaper to brute-force offline than an AES256 one (a single RC4/MD4-family round versus AES's far more expensive key-derivation path), so Kerberoasting and Golden/Silver Ticket tooling defaults to requesting or forging RC4 specifically to make the attacker's own offline cracking job easier — not because RC4 is somehow more compatible or convenient. Seeing `0x17` where the environment's baseline is AES is the attacker showing you their hand.

🔴 **Baseline before you conclude anything from encryption type alone.** A legacy service account whose `msDS-SupportedEncryptionTypes` was never updated after a domain-wide AES rollout will legitimately request/receive RC4 for *its own* tickets forever, regardless of attacker activity — check that attribute on the specific target account before treating a lone RC4 hit as a finding (see the Pitfalls table).

**Ticket Options field** — a bitmask carried on 4768/4769, distinct from ticket encryption type, that records what kind of ticket was actually issued (forwardable, renewable, proxiable, `ok-as-delegate`, and others per RFC 4120/Microsoft's Kerberos extensions). Two flags matter most for this note's purposes: **forwardable/proxiable** tickets are what unconstrained and constrained delegation actually rely on to move a client's identity from one hop to the next (Step 6), and a ticket carrying `ok-as-delegate` tells you the *target service* is itself trusted for delegation — worth cross-referencing against `05b`'s delegation-misconfiguration hunts the moment you see it on a ticket tied to a suspicious session. Exact bit-value mappings shift slightly across documentation sources and are easy to get wrong from memory — pull the raw hex value and verify it against current Microsoft/RFC 4120 KDCOptions references rather than eyeballing it, especially before writing a bit value into a report.

**Failure codes on 4768/4771** — these tell you *why* a TGT request failed, and several are operationally distinguishable from "someone forgot their password":

| Failure code | Meaning | Operational read |
|---|---|---|
| `0x6` | Client not found in Kerberos database | Unknown username — a batch of these across many different account names from one source is username enumeration, not typo |
| `0x12` | Client's credentials have been revoked | Account disabled, expired, or locked out — repeated attempts against a *specific* disabled/expired account post-incident is worth a second look (someone still trying to use a credential that should be dead) |
| `0x17` | Password has expired | Routine, unless clustered with other suspicious activity from the same source |
| `0x18` | Pre-authentication information was invalid | The common "bad password" code — already covered in `05b` for brute-force context |
| `0x19` | Additional pre-authentication required | Normal mid-negotiation response during a standard AS-REQ exchange, not itself a failure worth flagging on its own |
| `0x20` / `0x21` | Ticket expired / not yet valid | Usually clock-skew or stale-ticket noise; cross-check `0x25` (below) before assuming malice |
| `0x25` | Clock skew too great | Infrastructure/time-sync problem far more often than an attack — but also exactly the symptom a deliberately backdated/postdated forged ticket can produce if the forger got the domain's clock tolerance wrong |
| `0x2E` | KDC has no support for the requested encryption type | A client explicitly requesting an encryption type the KDC won't honor — worth checking what type was requested; deliberately requesting a weak/unsupported type is itself a downgrade-attempt shape |

Pulling the full field set correctly (not by guessing `.Properties[N]` array positions, which are not stable across event schema/OS versions) means reading the event's raw `EventData` by name:

```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4769]]" -MaxEvents 1 | ForEach-Object {
    $d = ([xml]$_.ToXml()).Event.EventData.Data
    [PSCustomObject]@{
        Account         = ($d | Where-Object Name -eq 'TargetUserName').'#text'
        ServiceName     = ($d | Where-Object Name -eq 'ServiceName').'#text'
        EncryptionType  = ($d | Where-Object Name -eq 'TicketEncryptionType').'#text'
        TicketOptions   = ($d | Where-Object Name -eq 'TicketOptions').'#text'
        FailureCode     = ($d | Where-Object Name -eq 'Status').'#text'
        TransitedServices = ($d | Where-Object Name -eq 'TransmittedServices').'#text'
        IpAddress       = ($d | Where-Object Name -eq 'IpAddress').'#text'
    }
}
```

`TransmittedServices`/Transited Services is pulled here deliberately — it's this note's Step 6 tell, not something to notice for the first time mid-delegation-investigation.

### Step 2 — Live Host Ticket-Cache Inspection

Once a lead points at a specific host or session, `klist` is the fastest way to see what tickets are actually cached there right now — and it requires no elevation for the current session.

```powershell
klist                    # Current session's cached tickets - Server, encryption type, flags, Start/End/Renew Time
klist tgt                 # Isolates the current session's TGT specifically
```

**To inspect a *different* logon session's cache** — another interactively logged-on user, or a service account's session — `klist` supports this natively, but it requires an elevated prompt:

```
klist sessions              :: Elevated. Lists every logon session on the box with its LogonId (hex - 0x3e7 is the well-known SYSTEM LUID)
klist -li 0x<LogonId>       :: Elevated. Targets that specific session's ticket cache
```

**What a normal cache looks like:** a handful of tickets — the session's TGT plus service tickets for whatever the user actually touched that session (a file share, an internal web app, a SQL instance) — with plausible target SPNs matching the user's actual role, encryption types matching the domain's baseline (AES if modernized), and `Start`/`End`/`Renew Time` values that land inside the domain's configured policy window (Step 1's `secedit` pull gives you that window).

**Anomaly patterns to key on:**

| Pattern | What it suggests |
|---|---|
| A ticket's `End Time` (or, more tellingly, its span from `Start Time`) is wildly longer than the domain's configured `MaxTicketAge`/`MaxRenewAge` — years rather than hours | Forged ticket — a legitimately-issued ticket cannot exceed what the KDC enforces at issuance time; only an offline-forged ticket can carry an arbitrary lifetime (Step 3) |
| A cached ticket's target SPN or client identity doesn't match what the interactively logged-on user's role plausibly needs | Injected ticket — a low-privilege user's session unexpectedly holding a TGT or service ticket for a privileged/unrelated account is a Pass-the-Ticket candidate (Step 5) |
| A valid, currently-usable TGT for an account that Active Directory shows as disabled, expired, or renamed since the ticket's claimed start time | Strong Golden Ticket candidate — Windows Kerberos does not universally guarantee an already-issued ticket stops working the instant the account's state changes, so a still-functional ticket for an account that "shouldn't" have one is a real, often-overlooked tell, not a false lead (cross-check the account's current state directly, don't assume) |
| Tickets present for far more distinct SPNs than the session's actual usage pattern would explain, especially clustered tightly in time | Kerberoasting tool activity in progress on this session (Step 7) |
| An oddly small ticket count for a session that's supposedly been active a long time, or a session's TGT missing entirely while service tickets are present | Selective ticket-cache manipulation/clearing — worth treating with the same suspicion as a cleared event log |

`klist` shows ticket-level metadata; it does **not** decode the PAC (Privilege Attribute Certificate) embedded in a ticket. Confirming SID-history/group-membership claims baked into a specific ticket's PAC needs a dedicated tool (Rubeus, or offline analysis of an extracted `.kirbi`) — see Tooling.

### Step 3 — Golden Ticket Investigation

This is the highest-severity scenario in this note — a confirmed krbtgt-key compromise means an attacker can mint a valid-looking TGT for any identity, domain-wide, until remediated. Work it in this order.

**1. Establish krbtgt reset history as ground truth.** Don't rebuild this — `05b`'s 🎯 Hunt Evil block already has the `Get-ADReplicationAttributeMetadata` one-liner against the krbtgt object; run that first and record every `LastOriginatingChangeTime` it returns for the account's password attribute.

**2. Know which reset iteration you're actually standing on.** The krbtgt account (like any AD account) retains its immediately-previous password/key alongside the current one for a compatibility window — a **single** reset does not fully invalidate tickets forged against the *prior* key, because that prior key can still validate for a grace period. Microsoft's own remediation guidance for a confirmed krbtgt compromise is to reset **twice**, with replication allowed to converge between resets, specifically to push the compromised key fully out of the two-generation retention window. Before drawing any conclusion, confirm from the metadata above whether you're looking at one reset or two, and how much time has passed between them and now.

**3. Hunt for a TGT-usage discontinuity across the reset boundary.** This is the actual, practical investigative technique — an analyst in the field cannot decrypt a ticket to directly verify which krbtgt key generation it was forged against, but a legitimate session is *structurally required* to re-authenticate (produce a fresh 4768) the moment the krbtgt key it depends on stops validating. So: for any account under suspicion, pull its 4768/4769 activity spanning the confirmed (double) reset boundary. **Continuous 4769 service-ticket activity for an account, with no corresponding fresh 4768 straddling the reset, is the tell** — it means whatever TGT is powering those service-ticket requests was never re-issued by this domain's current krbtgt key, which is exactly what a Golden Ticket forged before the reset looks like when it's still being used after it.

```powershell
$account = '<SuspectAccount>'
$resetTime = '<Confirmed-second-krbtgt-reset-timestamp>'
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4768 or EventID=4769)]]" -ErrorAction SilentlyContinue |
    ForEach-Object {
        $d = ([xml]$_.ToXml()).Event.EventData.Data
        [PSCustomObject]@{
            Time    = $_.TimeCreated
            EventId = $_.Id
            Account = ($d | Where-Object Name -in 'TargetUserName').'#text'
        }
    } | Where-Object { $_.Account -eq $account -and $_.Time -gt $resetTime } | Sort-Object Time
# Read the output looking for 4769s with no preceding 4768 after $resetTime - that gap is the finding
```

**4. Cross-check the ticket's actual lifetime against domain policy.** The domain's real, configured Kerberos ticket-lifetime policy lives in the Default Domain Policy GPO's Kerberos Policy section — it is **not** exposed by `Get-ADDefaultDomainPasswordPolicy` (that cmdlet returns password/lockout policy only, not ticket lifetimes). Pull it natively:

```powershell
secedit /export /cfg $env:TEMP\kerbpol.cfg /areas KERBEROS
Get-Content $env:TEMP\kerbpol.cfg
# [Kerberos Policy] section: MaxTicketAge (hours), MaxRenewAge (days), MaxServiceAge (minutes), MaxClockSkew (minutes)
```

Compare that against the `Start`/`End`/`Renew Time` values from Step 2's `klist` output (or from a captured ticket). A TGT whose actual span from `Start Time` to `End Time`/`Renew Time` exceeds what `MaxTicketAge`/`MaxRenewAge` allows is not something the KDC could have legitimately issued through the normal AS-REQ path — a client cannot request more lifetime than policy grants, only an offline forger can. Multi-year lifetimes, or suspiciously round custom values, are the classic version of this tell.

### Step 4 — Silver Ticket Investigation

Silver Ticket is the harder of the two forged-ticket techniques to catch precisely because of the design choice that makes it work: the ticket is forged directly against **one service's own key** (or a computer account's), and the forging process **never contacts a Domain Controller at all**. There is no 4768 (no TGT was ever needed), and there is no 4769 (no TGS-REQ was ever sent) — the first anyone "sees" of the session may be the service itself being accessed.

**The actual investigative workaround is a gap-hunt that requires both logs, not either one alone:**

1. On the **target service host**, pull the 4624 (logon) events for the account/timeframe under suspicion — `AuthenticationPackageName = Kerberos`, typically Logon Type 3 for a network service access.
2. For that same account and timeframe, pull 4768/4769 from **every DC that could plausibly have serviced it** (see the Pitfalls table on multi-DC coverage).
3. **The absence of a matching 4769 — often no 4768 either — for a 4624 that clearly happened is the signature.** A logon session with no paired ticket-request event anywhere in the DC's log, for a window where you'd otherwise expect one, is what Silver Ticket abuse looks like from the outside.

🔴 **Critical nuance before calling this a finding: Kerberos tickets are cached and reused for their full validity window (up to `MaxServiceAge`, commonly 10 hours by default).** A legitimate service access does not necessarily produce a *fresh* 4769 at the exact moment of that access — the client may have already obtained and cached a valid service ticket earlier in the session. The gap-hunt has to check for **any** 4769 for that account/SPN pair anywhere within the service ticket's validity window preceding the access, not just in the seconds immediately before it, or normal ticket caching will read as false-positive Silver Ticket abuse on every single access. Widen the DC-side search window to at least the domain's `MaxServiceAge` before concluding a gap is real.

```powershell
$account = '<SuspectAccount>'; $accessTime = '<4624-TimeCreated-on-target-host>'
$window  = ($accessTime | Get-Date).AddHours(-10)   # matches a 10h MaxServiceAge baseline - confirm against Step 3's secedit pull
foreach ($dc in (Get-ADDomainController -Filter *).HostName) {
    Get-WinEvent -ComputerName $dc -LogName Security -FilterXPath "*[System[(EventID=4769) and TimeCreated[@SystemTime>='$($window.ToUniversalTime().ToString('o'))']]]" -ErrorAction SilentlyContinue |
        ForEach-Object { ([xml]$_.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' -and $_.'#text' -eq $account } }
}
# No output across every DC, for the full validity window, against a 4624 that clearly happened = the Silver Ticket gap
```

Note the loop across **every** DC — a single-DC query that comes back empty proves nothing if the ticket (real or absent) could have been serviced by a peer DC instead; this mirrors `05b`'s own callout that Kerberos requests aren't guaranteed to land on the same DC every time.

### Step 5 — Pass-the-Ticket Investigation

Pass-the-Ticket (PtT) forges nothing — the attacker steals an already-issued, entirely legitimate ticket directly out of a compromised host's memory and replays it as-is on another host. Every individual event it produces (4769, 4624) is completely normal-looking Kerberos activity, because it *is* a real ticket, correctly issued by the real DC. The anomaly is exclusively in the **pattern of reuse**, not any single event.

**Theft mechanics** — how the ticket gets out of memory in the first place — are LSASS-memory territory, already covered in depth in [`17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits)` § Credential Theft From Memory](<../17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md#credential-theft-from-memory--lsass-and-mimikatz>) — LSASS handle-access detection (Sysmon Event ID 10), `.dmp`-file discovery, Credential Guard's mitigating effect. Do not re-derive that here; if a PtT investigation needs to establish *how* the ticket was obtained, that note is the next stop.

**The tell this note owns is what happens after theft — the injection and reuse pattern:**

- An injected ticket (via `kerberos::ptt` or Rubeus's `ptt` action, loading a `.kirbi` into the current session's LSA cache) shows up in `klist` on the receiving host **exactly like a legitimate ticket** — which is precisely why Step 2's cache-inspection anomaly patterns matter: a low-privilege interactive session suddenly holding a TGT or service ticket for an unrelated, higher-privileged identity is the on-host injection tell.
- On the log side, the tell is **the same ticket's issuing-host context being reused rapidly, from multiple unrelated hosts, in a pattern inconsistent with normal user movement.** A single legitimate user session moves between hosts at human/RDP-session speed and in a coherent path (workstation → jump box → target, say); a stolen ticket replayed via PtT can surface authenticating *from* multiple, geographically or organizationally unrelated source hosts within minutes of each other — something a Kerberos ticket, unlike a physical badge, has no built-in mechanism to prevent, since it isn't cryptographically bound to a single source machine under typical (non-FAST-armored) configurations.

```powershell
# Same account authenticating (4769/4624) from more than one distinct source in a short window - the PtT reuse shape
$account = '<SuspectAccount>'
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4769) and TimeCreated[timediff(@SystemTime) <= 1800000]]]" -ErrorAction SilentlyContinue |
    ForEach-Object {
        $d = ([xml]$_.ToXml()).Event.EventData.Data
        [PSCustomObject]@{ Time = $_.TimeCreated; Account = ($d | Where-Object Name -eq 'TargetUserName').'#text'; Source = ($d | Where-Object Name -eq 'IpAddress').'#text' }
    } | Where-Object Account -eq $account | Sort-Object Time
# More than one distinct IpAddress for the same account inside a 30-minute window is the finding to chase, not routine multi-homing
```

Cross-reference source-IP plausibility the same way note 05's workstation-side logon-type triage does — impossible or implausibly fast travel between the sources is the corroborating signal, not the query alone.

### Step 6 — Delegation-Abuse Live-Investigation Sequence

`05b`'s 🎯 Hunt Evil block already has the config-side hunts for **finding** misconfigured delegation — `TrustedForDelegation` (unconstrained), `msDS-AllowedToDelegateTo` (constrained), `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD). This step does not repeat those. Its job is different: **what does successful delegation *abuse* look like in the log sequence as it actually happens**, once you already know (or suspect) a delegation-trusted principal exists.

**The field-level tell: the `TransmittedServices`/Transited Services field on 4769.** Constrained delegation abuse works through two chained Kerberos operations — **S4U2Self** (a front-end service asks the KDC for a ticket to *itself*, on behalf of a target user, without that user's own credentials) followed by **S4U2Proxy** (the front-end service presents that self-ticket to obtain a ticket to the *back-end* target service, still impersonating the user). Every 4769 generated by an S4U2Proxy leg carries a populated `TransmittedServices` field naming the service(s) that performed the delegation hop — **a 4769 with this field non-empty means the ticket was obtained via a delegation transition, not a direct client request.** That single field is the difference between "this user authenticated to this service normally" and "some other service authenticated to this service *as* this user."

**What to actually look for once you're watching a suspect delegation-trusted account:**

| Signal on 4769 | What it means |
|---|---|
| `TransmittedServices` populated, `TargetUserName` = a high-value account (Domain Admin, service account, etc.) | Ticket was proxied — the requester's own identity is *not* the identity the ticket was issued for |
| `IpAddress`/source of the request = the delegation-trusted server's own address, not the target user's normal workstation | The request physically originated from the delegating service, not from the impersonated user sitting at a keyboard — exactly what S4U2Proxy produces, and exactly what a legitimate direct logon would not |
| No corresponding 4768/4624 for the target user, from their own workstation, around the same time | The impersonated user was never actually present for this authentication — their identity was borrowed by the delegating service |
| Service Name (target SPN) is a resource the delegation-trusted account has no ordinary business reaching | The delegation was pointed somewhere it wasn't configured/expected to go — cross-check against `05b`'s `msDS-AllowedToDelegateTo` hunt for what that account was actually *supposed* to be limited to |

**Unconstrained delegation abuse has a distinct earlier step worth watching for:** a delegation-trusted host only becomes valuable once a high-privilege account's TGT lands in *its* LSASS memory — which happens the moment that account authenticates *to* the unconstrained-delegation host (a 4624 on that host, from the victim account, any logon type that deposits a forwarded TGT). Attackers routinely force this via a coercion technique (e.g., forcing a DC or high-privilege service to connect to the delegation-trusted host) rather than waiting for it to happen naturally. Once that 4624 exists, the abuse from that point forward is pure Pass-the-Ticket (Step 5) against the now-captured TGT.

**RBCD-specific sequencing:** watch for a **4742** (computer account changed) on the DC — the event that fires when `msDS-AllowedToActOnBehalfOfOtherIdentity` is written — occurring shortly **before** a 4769 chain (S4U2Self then S4U2Proxy, `TransmittedServices` populated) from that same computer account against a sensitive SPN. The 4742-then-delegation-chain sequence is the operational signature of an attacker setting up RBCD and using it in the same operational window, rather than a long-standing legitimate configuration.

🔴 **Don't over-read `TransmittedServices` alone.** Populated Transited Services on a properly configured, intentionally-delegating front-end service (an IIS app pool doing Kerberos double-hop to a back-end SQL instance, for example) is completely normal and expected — the tell is an **unexpected** account/SPN pairing riding that delegation chain, not the mere presence of S4U traffic on a host known to legitimately delegate.

### Step 7 — Estate-Wide Kerberoasting Sweep

Individual-event triage (Step 1) catches one suspicious ticket; this step catches the tool-driven pattern — one account requesting service tickets against **many distinct SPNs in a short window**, the signature of automated Kerberoasting tooling (Rubeus, Impacket's `GetUserSPNs.py`, and similar) working through a target list. Because 4769 is DC-only, "estate-wide" here means **aggregating across every DC**, not across workstations — a multi-DC domain can service one attacker's request stream across several DCs via normal site-affinity/load distribution, and a single-DC query will systematically undercount.

```powershell
$dcs = (Get-ADDomainController -Filter *).HostName
$xpath = "*[System[(EventID=4769) and TimeCreated[timediff(@SystemTime) <= 7200000]] and EventData[Data[@Name='TicketEncryptionType']='0x17']]"

$hits = foreach ($dc in $dcs) {
    Get-WinEvent -ComputerName $dc -LogName Security -FilterXPath $xpath -ErrorAction SilentlyContinue | ForEach-Object {
        $d = ([xml]$_.ToXml()).Event.EventData.Data
        [PSCustomObject]@{
            DC      = $dc
            Time    = $_.TimeCreated
            Account = ($d | Where-Object Name -eq 'TargetUserName').'#text'
            SPN     = ($d | Where-Object Name -eq 'ServiceName').'#text'
        }
    }
}

$hits | Group-Object Account | Select-Object Name, Count,
    @{N='DistinctSPNs'; E={($_.Group.SPN | Sort-Object -Unique).Count}},
    @{N='FirstSeen'; E={($_.Group.Time | Measure-Object -Minimum).Minimum}},
    @{N='LastSeen';  E={($_.Group.Time | Measure-Object -Maximum).Maximum}} |
    Where-Object DistinctSPNs -gt 3 | Sort-Object DistinctSPNs -Descending
```

Run this across every DC in the same 2-hour window (`timediff` in the XPath is milliseconds) and group by requesting account. **The distinct-SPN-count threshold (`-gt 3` above) is a tunable heuristic, not a fixed rule** — a normal user rarely legitimately requests tickets for more than one or two services in a session, but the exact cutoff worth alerting on depends on the environment's own baseline; tune it against a quiet-period run before trusting it operationally. This complements — it does not replace — `05b`'s own "Advanced" one-liner, which cross-references SPN-bearing/no-preauth accounts against raw ticket volume; this sweep is narrower and specifically shaped around the RC4 + distinct-SPN-count combination that separates automated roasting tools from a busy legitimate account.

## Technique Comparison

The single most useful visual in this note — what's actually forged/abused, whether the DC ever sees it, and where each technique's blind spot lives.

| Technique | DC-Visible? | Key Material Used to Forge/Abuse | Primary Investigative Tell | Primary Blind Spot |
|---|---|---|---|---|
| **Golden Ticket** | Indirectly only — the forged TGT itself is never issued by a DC, but every service ticket obtained *with* it produces a normal-looking 4769 | The domain's **krbtgt** account hash — a single domain-wide secret shared by every DC | 4769 activity for an account with no corresponding fresh 4768 across a confirmed (double) krbtgt-reset boundary; ticket lifetime exceeding configured Kerberos policy (Step 3) | Once krbtgt is compromised, any identity — including a disabled, renamed, or nonexistent one — can be minted domain-wide until krbtgt is reset **twice**; the forging step itself leaves zero DC-side record |
| **Silver Ticket** | No — never touches the DC at all, by design | One **service account's** (or computer account's) own password hash | A confirmed service access (4624 on the target host, or application-log evidence) with no matching 4769 — often no 4768 either — anywhere across every DC, for the ticket's full validity window (Step 4) | Scoped to whichever single service's key was stolen, but structurally invisible to Kerberos event logging entirely; absence of DC evidence proves nothing without target-host correlation |
| **Kerberoasting** | Fully — every request is a normal, successful 4769 | No key is stolen up front; the target **SPN-bearing account's** password hash is what the offline-cracked ticket exposes | RC4 (`0x17`) encryption type against multiple distinct SPNs from one account in a short window (Step 7; also `05b`) | A strong, long, random service-account password defeats the offline crack even though the ticket-request activity itself is completely normal, error-free Kerberos protocol usage — the "attack" and legitimate use are procedurally identical without the encryption-type + volume signature |
| **AS-REP Roasting** | Fully — a normal-looking 4768 | The target account's own password hash, for any account with **"Do not require Kerberos preauthentication"** set | 4768 with no preceding 4771, for an account flagged `DONT_REQUIRE_PREAUTH` (`05b`) | Requires zero authentication to attempt — an attacker with only a username list, no credentials at all, can probe every account and passively collect crackable AS-REPs from whichever happen to be misconfigured |
| **Pass-the-Ticket** | Indirectly — the replayed ticket produces entirely normal-looking 4769/4624 events, just from an unexpected source | No hash is used to forge anything — a real, already-issued, correctly-signed ticket is stolen directly out of LSASS memory and replayed as-is | The same ticket's issuing-host/session context reused rapidly across unrelated hosts in a pattern inconsistent with normal user movement (Step 5) | Every individual event the ticket produces is completely legitimate — the DC issued it correctly the first time; the only anomaly is the *pattern* of reuse across hosts/time, never any single event in isolation |

## Investigative Sequence Summary

| # | Step | Primary artifact/command | Goal |
|---|---|---|---|
| 1 | Triage the suspicious event | Full `EventData` pull on the 4768/4769/4771; encryption type, Ticket Options, failure code | Decide, from one event, whether this warrants deeper investigation and along which of the paths below |
| 2 | Live ticket-cache inspection | `klist`, `klist sessions`, `klist -li 0x<LogonId>` | Establish what's actually cached on the host right now, and whether it matches a normal pattern |
| 3 | Golden Ticket investigation | `05b`'s krbtgt metadata pull → reset-iteration check → 4768/4769 discontinuity hunt → `secedit` lifetime-vs-policy check | Confirm or rule out a forged, krbtgt-keyed TGT in active use |
| 4 | Silver Ticket investigation | Target-host 4624 vs. every-DC 4768/4769, widened to the ticket validity window | Find the logon-without-a-paired-ticket-request gap |
| 5 | Pass-the-Ticket investigation | `17`/Memory Analysis (theft) + cross-host 4769/4624 source-IP correlation (reuse pattern) | Detect a legitimate ticket replayed from an inconsistent set of sources |
| 6 | Delegation-abuse sequence | 4769 `TransmittedServices` field, source-IP-vs-expected-workstation check, 4742-then-delegation-chain sequencing for RBCD | Catch S4U2Self/S4U2Proxy abuse as it happens, not just the static misconfiguration |
| 7 | Estate-wide Kerberoasting sweep | Multi-DC `-FilterXPath` RC4 + distinct-SPN-count aggregation | Surface automated-tooling volume patterns a single-event or single-DC view would miss |
| 8 | Hand off | Fundamentals/config-side detection → `05b` · Memory mechanics → `17` · Event-log mechanics → `11` | This note's scope ends at the ticket/host-level workflow — deeper reference material lives in the sibling notes |

## Pitfalls

| 🔴 Pitfall | Why it matters |
|---|---|
| Treating RC4 (`0x17`) as absolute proof of abuse without first checking the target account's own `msDS-SupportedEncryptionTypes` | Legacy service accounts that were never updated after an AES rollout legitimately request/receive RC4 for their own tickets forever — baseline per-account before alerting estate-wide (Step 1, Step 7) |
| Running the Silver Ticket gap-hunt against only the exact moment of access, rather than the full ticket-validity window preceding it | Kerberos tickets are cached and reused — a legitimate access frequently has no *fresh* 4769 at that exact moment because the client already held a valid cached ticket; this reads as a false-positive Silver Ticket finding on every normal access unless the search window is widened (Step 4) |
| Assuming a single krbtgt reset fully invalidates a Golden Ticket | The immediately-previous key is retained for a compatibility window — Microsoft's own guidance is to reset **twice**; know which iteration you're standing on before concluding anything from the reset timestamp alone (Step 3) |
| Querying only one Domain Controller when the domain has more than one | Site-affinity/load distribution means a client's requests — and an attacker's — aren't guaranteed to land on the same DC every time; a "missing" 4768/4769 might simply be sitting on a peer DC's log you didn't pull (Steps 4, 7; `05b`) |
| Treating any populated `TransmittedServices` field as inherently malicious | Legitimate, intentionally-configured constrained delegation (IIS-to-SQL double-hop, for example) produces this routinely — the tell is an *unexpected* account/SPN pairing riding the delegation chain, not the field's mere presence (Step 6) |
| Relying on `klist` alone to assess a ticket's PAC contents (SID history, group claims) | `klist` shows ticket-level metadata only — it does not decode the PAC; deeper identity/claims verification needs a dedicated tool (Rubeus or offline `.kirbi` analysis) (Step 2) |
| Reading a raw `.Message` string with regex instead of pulling `EventData` by name | Message text formatting and field indices are not guaranteed stable across OS builds and event-schema versions; every code block in this note pulls named `EventData` fields for exactly this reason, consistent with note 11's own methodology |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| 4769 activity continuing uninterrupted across a confirmed double krbtgt reset, with no fresh 4768 straddling the boundary | Golden Ticket forged against a key generation this domain no longer trusts (Step 3) |
| A cached ticket's `Start`/`End`/`Renew Time` span exceeds the domain's actual `MaxTicketAge`/`MaxRenewAge` (per `secedit /areas KERBEROS`) | A legitimately-issued ticket cannot exceed configured policy — only an offline forger can produce this (Step 3) |
| A valid, currently-usable ticket in `klist` for an account AD shows as disabled, expired, or renamed since the ticket's claimed start time | Golden Ticket for an identity that "shouldn't" still have a working credential (Step 2, Step 3) |
| A confirmed service access with no matching 4769 (or 4768) on any DC across the full ticket-validity window | Silver Ticket — the logon-without-a-paired-ticket-request gap (Step 4) |
| The same account's tickets authenticating from multiple, unrelated source IPs within an implausibly short window | Pass-the-Ticket — a stolen ticket replayed from a source it was never issued to (Step 5) |
| A 4769 with `TransmittedServices` populated, `TargetUserName` a high-value account, and no corresponding 4768/4624 from that user's own workstation | Delegation abuse — someone else authenticated to the target service *as* that user (Step 6) |
| A 4742 (computer account changed) on a computer object, followed shortly by an S4U2Self/S4U2Proxy chain from that same account against a sensitive SPN | RBCD set up and used within the same operational window — not a long-standing legitimate configuration (Step 6) |
| Multi-DC RC4 + distinct-SPN-count sweep surfaces one account spiking against far more SPNs than its own historical baseline | Automated Kerberoasting tooling, not routine legitimate use (Step 7) |
| Investigation scoped to a single DC's Security log in a multi-DC domain | Structural blind spot — the missing evidence may simply be on a peer DC (Steps 4, 7) |

## MITRE ATT&CK Techniques Covered

| Technique | ID | Where it shows up in this note |
|---|---|---|
| Steal or Forge Kerberos Tickets: Golden Ticket | T1558.001 | Step 3 — the krbtgt-reset-boundary discontinuity hunt and lifetime-vs-policy check; baseline signature owned by `05b` |
| Steal or Forge Kerberos Tickets: Silver Ticket | T1558.002 | Step 4 — the logon-without-a-paired-ticket-request gap-hunt across target host and every DC |
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | Step 7 — the multi-DC RC4/distinct-SPN estate-wide sweep; per-event signature owned by `05b` |
| Steal or Forge Kerberos Tickets: AS-REP Roasting | T1558.004 | Referenced in the Technique Comparison table; full detection signature owned by `05b` |
| Use Alternate Authentication Material: Pass the Ticket | T1550.003 | Step 5 — cross-host reuse-pattern detection; theft mechanics owned by `17`/Memory Analysis |
| Access Token Manipulation | T1134 | Step 6 — S4U2Self/S4U2Proxy impersonation as it appears in the live log sequence; config-side misconfiguration hunts owned by `05b` |

## Tooling

| Tool | Use |
|---|---|
| **`klist`** | Live ticket-cache inspection — current session unelevated, other sessions via `sessions`/`-li` elevated (Step 2) |
| **`Get-WinEvent -FilterXPath`** | Engine-level, schema-stable field extraction from 4768/4769/4771 — used throughout in place of fragile `.Message` regex or unstable `.Properties[N]` indices |
| **`secedit /export /areas KERBEROS`** | Native pull of the domain's actual configured Kerberos ticket-lifetime policy — the ground truth for Step 3's lifetime check |
| **`repadmin` / `Get-ADReplicationAttributeMetadata`** | krbtgt reset-history ground truth — full usage owned by `05b`'s Hunt Evil block |
| **Rubeus** | Live ticket enumeration/dump/monitor and PAC inspection beyond what `klist` decodes — understanding its default behaviors (forced RC4, common `/ptt` usage) is directly useful for recognizing attacker tradecraft in the log/cache evidence above |
| **Mimikatz** (`kerberos::list`, `sekurlsa::tickets`, `kerberos::ptt`, `kerberos::golden`) | The canonical tool behind most of what this note detects — understanding its defaults (RC4 preference, ticket-injection mechanics) directly informs the tells in Steps 3–5 |
| **Impacket** (`GetUserSPNs.py`, `ticketer.py`, `secretsdump.py`) | Cross-platform equivalent tooling — its request/forge patterns produce the same log-side signatures this note hunts for |
| **Volatility** | Offline extraction of ticket material from a memory image when live `klist`/Rubeus access isn't available — full memory-forensics depth owned by `17` |
| **EvtxECmd / Event Log Explorer** (Eric Zimmerman) | Offline `.evtx` review when working from acquired DC/host logs rather than live `Get-WinEvent` access |

## Correlate With

| To go deeper on… | Open | Division of labor |
|---|---|---|
| Kerberos fundamentals (TGT vs. ST, the AS-REQ/TGS-REQ flow), DC-side event ID reference, and each technique's baseline DFIR signature | [`05b - Active Directory & Domain Forensic Artifacts`](<../05b - Active Directory & Domain Forensic Artifacts.md>) | Primary sibling note — fundamentals and config-side/static detection (SPN inventory, no-preauth flags, delegation misconfiguration hunts, krbtgt-metadata pull) live entirely in `05b`; this note is the live, ticket-and-host-level investigation workflow that runs once a lead already exists |
| LSASS credential-theft mechanics underlying Pass-the-Ticket — handle-access detection, `.dmp`-file discovery, Credential Guard's effect | [`17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits)`](<../17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md#credential-theft-from-memory--lsass-and-mimikatz>) | This note owns the reuse-pattern/network-side PtT tell (Step 5); note 17 owns how the ticket got out of memory in the first place |
| Full `Get-WinEvent`/`-FilterXPath` methodology, EVTX mechanics, audit-policy prerequisites | [`11 - Event Log Analysis`](<../11 - Event Log Analysis.md>) | This note's field-extraction pattern (named `EventData`, not `.Message` regex) follows note 11's own established methodology rather than re-deriving it |
| Onward lateral movement once a stolen/forged ticket is confirmed in use | [`12 - Lateral Movement`](<../12 - Lateral Movement.md#pass-the-hash--pass-the-ticket--the-credential-theft-angle>) | Brief PtH/PtT mention there covers the remote-execution angle; this note owns the ticket-investigation depth |
| DC-only-role context if the investigation is being worked directly on a Domain Controller | [`23 - Special Services/Domain Controller — Role-Specific Forensics`](<Domain Controller — Role-Specific Forensics.md>) | That note flags the KDC as DC-exclusive and defers all ticket-abuse depth here/to `05b`; this note is where that depth actually lives |

## Resources

- Microsoft Learn — Kerberos authentication overview: https://learn.microsoft.com/windows-server/security/kerberos/kerberos-authentication-overview
- Microsoft Learn — Security Options: `Kerberos Policy` settings reference (`MaxTicketAge`/`MaxRenewAge`/`MaxServiceAge`/`MaxClockSkew`): https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/kerberos-policy
- Microsoft Learn — `klist` command reference: https://learn.microsoft.com/windows-server/administration/windows-commands/klist
- Microsoft Learn — Kerberos error/failure code reference (KDC_ERR_* status values): https://learn.microsoft.com/openspecs/windows_protocols/ms-kile/
- Microsoft Learn — resetting the KRBTGT account password/keys (double-reset guidance): https://learn.microsoft.com/windows-server/security/kerberos/manage-kerberos-tickets
- Microsoft Learn — S4U2Self and S4U2Proxy protocol extensions: https://learn.microsoft.com/openspecs/windows_protocols/ms-sfu/
- MITRE ATT&CK **T1558.001** (Golden Ticket) — https://attack.mitre.org/techniques/T1558/001/
- MITRE ATT&CK **T1558.002** (Silver Ticket) — https://attack.mitre.org/techniques/T1558/002/
- MITRE ATT&CK **T1558.003** (Kerberoasting) — https://attack.mitre.org/techniques/T1558/003/
- MITRE ATT&CK **T1558.004** (AS-REP Roasting) — https://attack.mitre.org/techniques/T1558/004/
- MITRE ATT&CK **T1550.003** (Use Alternate Authentication Material: Pass the Ticket) — https://attack.mitre.org/techniques/T1550/003/
- MITRE ATT&CK **T1134** (Access Token Manipulation) — https://attack.mitre.org/techniques/T1134/
- SANS FOR508 course syllabus (public) — Kerberos ticket-attack investigation workflow used as a coverage checklist only; no course content reproduced verbatim
