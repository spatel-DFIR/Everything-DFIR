# Phishing and BEC Initial Access Playbook

Phishing is the highest-volume initial-access vector into Windows enterprise environments, and it comes in two shapes that investigate very differently. The **malware-delivery shape** — a malicious attachment or link that gets a user to execute a payload — hands the attacker a foothold on a Windows endpoint, at which point the investigation becomes largely execution/persistence evidence this module already owns. The **pure-BEC shape** — no malware at all, just a stolen credential or a session cookie used to log into a mailbox or cloud identity — never touches the endpoint's disk in a way that matters; the entire investigation happens in authentication logs and mailbox audit trails. This playbook covers both shapes end to end: detecting the delivery, confirming the user actually engaged with it, confirming whether that engagement turned into a genuine account compromise, and — because it's the single technique that most often gets missed — walking the classic BEC persistence mechanism of compromised-mailbox inbox-rule abuse through to a scoped, provable answer of what the attacker actually did with the access.

> 🔴 **Scope boundary.** This playbook stops at the **foothold or account compromise** — establishing that the phish succeeded (either as executed malware or as a captured credential/session) and scoping what happened during that access window. It deliberately does not re-cover the full ransomware kill chain (credential harvesting for domain-wide movement, mass encryptor deployment, shadow-copy deletion) — that belongs to the **Ransomware Playbook** in this same folder, which a malware-delivery phish frequently feeds into once the initial foothold escalates. It also does not re-derive mailbox-level evidence mechanics owned by [`15 - Email Forensics`](<../15 - Email Forensics.md>), logon/auth-event mechanics owned by [`05 - Users, Groups & Authentication`](<../05 - Users, Groups & Authentication.md>), or browser-side evidence owned by [`14 - Web Browser Forensics`](<../14 - Web Browser Forensics>) — this playbook sequences and applies those artifacts to this one incident type rather than re-explaining them.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Scenario Framing](#scenario-framing)
- [Step 1 — Detect the Phish / Delivery Mechanism](#step-1--detect-the-phish--delivery-mechanism)
- [Step 2 — Confirm User Interaction: Execution or Credential Entry](#step-2--confirm-user-interaction-execution-or-credential-entry)
- [Step 3 — Confirm Account Compromise (Logon / Session Evidence)](#step-3--confirm-account-compromise-logon--session-evidence)
- [Step 4 — Detect Inbox-Rule Abuse (The Classic BEC Persistence Mechanism)](#step-4--detect-inbox-rule-abuse-the-classic-bec-persistence-mechanism)
- [Step 5 — Detect MFA-Bypass / Adversary-in-the-Middle Session Theft](#step-5--detect-mfa-bypass--adversary-in-the-middle-session-theft)
- [Step 6 — Scope Impact: Who Else Received Attacker Mail, What Was Accessed](#step-6--scope-impact-who-else-received-attacker-mail-what-was-accessed)
- [Step 7 — Remediation Handoff](#step-7--remediation-handoff)
- [Investigative Sequence Summary](#investigative-sequence-summary)
- [Pitfalls](#pitfalls)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage for the host-visible half of this playbook — delivery artifacts and Track A execution/logon evidence. The mailbox-side half (inbox rules, sign-in anomalies, AiTM session patterns) lives in Cloud/M365 and Entra ID logs, not native Windows PowerShell — see Steps 3-6 below for the exact hand-off points.

```powershell
# Recently landed attachment-shaped files in common drop locations, with MOTW (Zone.Identifier) status - absence on an otherwise-recent file is itself worth a look (Step 1)
Get-ChildItem "$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:USERPROFILE\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook" -File -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-2) -and $_.Extension -in '.docm','.xlsm','.one','.iso','.img','.lnk','.hta','.js','.vbs' } |
    ForEach-Object { [PSCustomObject]@{ Name = $_.Name; LastWriteTime = $_.LastWriteTime; HasMOTW = [bool](Get-Item -Path "$($_.FullName):Zone.Identifier" -ErrorAction SilentlyContinue) } }

# Currently-mounted disk images - the ISO/LNK-smuggling live tell (Step 1); MOTW does not propagate to files inside these
Get-Volume | Where-Object DriveType -eq 'CD-ROM' | Select-Object DriveLetter, FileSystemLabel, FileSystemType

# Recently created LNK files outside the normal Recent-Items folder - a staged-from-ISO tell (Step 1); deep LNK parsing lives in note 07
Get-ChildItem "$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:TEMP" -Filter *.lnk -File -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-2) } | Select-Object FullName, CreationTime

# Office app spawning a known interpreter/shell as a direct child - the Track A execution tell (Step 2)
Get-CimInstance Win32_Process | Where-Object { (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.ParentProcessId)").Name -in 'WINWORD.EXE','EXCEL.EXE','POWERPNT.EXE','ONENOTE.EXE' } |
    Where-Object Name -in 'cmd.exe','powershell.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe' |
    Select-Object Name, ProcessId, ParentProcessId, CommandLine

# Recent logons (success/failure) for a specific suspected-phished account - fast on-host triage version of Step 3's pivot; swap in the account name
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625; StartTime=(Get-Date).AddDays(-3)} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match '<AccountName>' } |
    Select-Object TimeCreated, Id, @{N='LogonType';E={$_.Properties[8].Value}}, @{N='SourceIP';E={$_.Properties[18].Value}}
```

## Scenario Framing

Every phishing/BEC investigation starts from one of three trigger reports, and the correct first move differs by which one it is: a user or the SOC flags a suspicious email before anyone clicked anything (the good case — pure containment, no compromise yet to scope); a user reports "I think I clicked something" or "I entered my password on a page that didn't look right" (engagement confirmed, compromise unconfirmed — this playbook's core scenario); or finance/HR reports a fraudulent wire transfer or an unusual reply chain, with no one having noticed a phish at all (compromise already happened, possibly weeks ago, and the phishing/credential-theft event has to be reconstructed backward from the fraud).

The attack chain this playbook covers branches into two tracks that share Steps 1-3 and diverge after:

```
Delivery (Step 1)
   │  attachment/link/QR code reaches the mailbox
   ▼
User interaction (Step 2)
   │
   ├── Track A: Malicious payload executed
   │      → foothold on the Windows endpoint
   │      → hand off to note 06 (execution evidence) + note 10 (persistence)
   │      → may escalate into the Ransomware Playbook (this folder)
   │
   └── Track B: Credential entered on a fake login page
          → Step 3: did the stolen credential/session actually get used?
          │
          ├── Simple credential reuse → interactive/OWA logon (Step 3)
          ├── AiTM session-cookie theft → live session with MFA already
          │   satisfied, no password-reset alone fixes it (Step 5)
          └── Compromised mailbox → inbox-rule abuse → lateral phishing
              or wire fraud from a trusted internal account (Step 4)
```

Track A is largely a pointer into this module's existing execution/persistence depth once the payload runs — this playbook does not re-derive that. Track B (credential/session-based BEC) is where this playbook carries the most original depth, because a compromised mailbox with no malware anywhere is exactly the scenario that has no natural home in this module's artifact-by-artifact structure.

## Step 1 — Detect the Phish / Delivery Mechanism

Modern phishing delivery has moved well past the "obvious macro doc" stereotype specifically because macro-enabled Office documents from the internet have been blocked by default (VBA blocked with Mark of the Web since Office builds released 2022 onward) and SmartScreen/Defender for Office 365 (Safe Attachments/Safe Links) catch the crudest attempts. Current delivery techniques exist largely *because* they route around those specific controls:

| Technique | How it evades the obvious controls | Endpoint evidence to pull |
|---|---|---|
| **Macro-enabled Office doc** (`.docm`/`.xlsm`) | Still works if VBA-blocking-on-MOTW is disabled by policy, or the file arrives without MOTW (e.g., inside a container that strips it) | Zone.Identifier ADS on the doc (NTFS/03), Office Trust Records / Protected View bypass (note 07), `WINWORD.EXE`/`EXCEL.EXE` spawning a child process (note 06 process-tree context) |
| **ISO/LNK smuggling** | An ISO or IMG file mounted by double-click auto-assigns a drive letter and, critically, **does not propagate Zone.Identifier/MOTW to the files inside it** — a LNK or script inside an ISO attachment inherits none of the "downloaded from the internet" warnings the outer container triggered | USB/mounted-image evidence (note 09's mount-related keys), the LNK file itself (note 07), Zone.Identifier present on the outer ISO but absent on its extracted contents — that mismatch is itself diagnostic |
| **HTML smuggling** | The malicious payload is assembled/decoded client-side by JavaScript inside an HTML attachment or a linked page, so the file that actually lands on disk is built locally rather than transiting the network/mail-gateway as a recognizable malicious binary | Browser download artifacts (note 14 — download history, the reconstructed file's own MOTW/Zone.Identifier showing it originated from the browser rather than the mail client) |
| **Malicious OneNote (.one)** | Rose specifically as a stand-in once macro docs got harder — OneNote attachments can embed and auto-launch an attached file behind a fake "double-click to view" graphic | Look for an embedded-file launch inside a `.one` attachment; OneNote's own embedded-object storage is a newer artifact this module doesn't carry a dedicated parsing section for — treat as a gap and fall back to execution-evidence (note 06) for whatever the embedded object actually launched |
| **Malicious PDF** | A PDF containing a link (rather than an active exploit, in the overwhelming majority of current cases) redirecting to a credential-harvesting page or a fake "open with Acrobat online" prompt that itself smuggles a payload | Browser navigation from the PDF viewer/link (note 14), rather than the PDF file itself carrying executable content |
| **QR-code phishing ("quishing")** | The malicious URL never appears as clickable text or a scannable link in the email body — it's embedded in an image, decoded by the user's **phone** camera, which routes the credential-harvesting page load entirely around the corporate endpoint and its EDR/browser telemetry | This is the key operational implication: **the compromise-relevant evidence for a QR-phish frequently never touches the Windows host at all.** The endpoint may only show the *inbound email containing the image* (note 15) — corroborating evidence of what happened after scanning lives on the mobile device (out of this module's scope) or, once the attacker actually authenticates, in the cloud-side sign-in logs (Step 3) |

The email itself — headers, sender-domain spoofing/lookalike-domain analysis, the attachment/link chain — is [`15 - Email Forensics`](<../15 - Email Forensics.md>)'s job; this step is about recognizing which delivery technique is in play so the right corroborating artifact gets pulled next, not re-deriving header analysis.

### PowerShell

Check MOTW (the `Zone.Identifier` alternate data stream) on a single suspect attachment:

```powershell
Get-Item -Path 'C:\path\to\attachment.iso' -Stream Zone.Identifier -ErrorAction SilentlyContinue
```

The ISO/LNK-smuggling mismatch shows that the outer container has MOTW, but the file mounted/extracted from inside it does not — treat that mismatch as diagnostic, not as evidence the inner file is clean:

```powershell
$outer = Get-Item -Path 'C:\path\to\attachment.iso' -Stream Zone.Identifier -ErrorAction SilentlyContinue
$inner = Get-Item -Path 'D:\payload.lnk' -Stream Zone.Identifier -ErrorAction SilentlyContinue
[PSCustomObject]@{ OuterHasMOTW = [bool]$outer; InnerHasMOTW = [bool]$inner }
```

## Step 2 — Confirm User Interaction: Execution or Credential Entry

The delivery mechanism reaching the mailbox proves nothing by itself — spam filters miss things constantly, and most phishing email that lands is never acted on. This step establishes whether the user actually engaged.

**Track A — payload execution.** Confirm via the standard execution-evidence family: Prefetch, ShimCache, Amcache, BAM/DAM (full artifact-by-artifact depth and each one's presence-vs-execution guarantees in [`06 - Evidence of Program Execution`](<../06 - Evidence of Program Execution>)). Look specifically for the delivery vector's own process spawning an unexpected child — `WINWORD.EXE`/`EXCEL.EXE` launching `cmd.exe`/`powershell.exe`/`mshta.exe`, or an unusual parent for a script host following an ISO-mount or OneNote-attachment event. Once execution is confirmed, the resulting foothold's persistence and further activity is [`10 - Persistence Mechanisms`](<../10 - Persistence Mechanisms>)'s territory — this playbook does not re-walk that chain.

**Track B — credential entry on a fake login page.** The user visited a page and typed a password. This lives entirely in browser evidence: navigation history to the phishing domain (a lookalike domain or a compromised/throwaway legitimate site hosting the kit), form-autofill/password-manager prompts, and — if the phishing kit is a reverse-proxy AiTM kit rather than a simple static clone — the browser's own cookie store may show a session cookie for the *real* corporate identity provider domain that the user never legitimately authenticated a session for on this device. Full mechanics: [`14 - Web Browser Forensics`](<../14 - Web Browser Forensics>) (Chromium/Firefox history, cache, and password-store notes). **Critically, confirming the user typed a credential into a phishing page does not by itself confirm compromise** — that credential may never get reused successfully, may be caught by MFA, or may be entered into a page that was itself sinkholed/taken down before the attacker retrieved it. Step 3 is where that gets resolved.

### PowerShell

Track A: pull a full child-process listing for every Office/OneNote parent process, not just the known-interpreter allowlist the Hunt Evil block filters to — this confirms the delivery vector actually executed something before handing off to note 06's execution-evidence depth:

```powershell
Get-CimInstance Win32_Process | Where-Object Name -in 'WINWORD.EXE','EXCEL.EXE','POWERPNT.EXE','ONENOTE.EXE' | ForEach-Object {
    $office = $_
    Get-CimInstance Win32_Process -Filter "ParentProcessId=$($office.ProcessId)" |
        Select-Object @{N='OfficeParent';E={$office.Name}}, Name, ProcessId, CommandLine
}
```

Track B's browser-side confirmation (navigation history, cookie stores) is native PowerShell-hostile without third-party parsing — that depth is [`14 - Web Browser Forensics`](<../14 - Web Browser Forensics>)'s job, not repeated here.

## Step 3 — Confirm Account Compromise (Logon / Session Evidence)

This is the pivot point: did the stolen credential (or, in the AiTM case, the stolen session) actually get used to access something.

**On-host / interactive evidence** — if the compromised account subsequently authenticates to the Windows endpoint itself (a domain account logging on somewhere with the harvested credential), the full Logon Type / 4624 / 4625 / 4648 evidence chain applies exactly as it does for any other credential-based compromise: [`05 - Users, Groups & Authentication`](<../05 - Users, Groups & Authentication.md#logon-types-event-id-4624--4625>). An unfamiliar source IP/workstation authenticating as the phished user, especially outside the account's normal hours or geography, is the same anomaly pattern note 05's Logon-Type Triage table already names generically.

**Cloud/M365 evidence — usually where BEC actually plays out.** Most modern BEC compromise is a mailbox/cloud-identity event, not a Windows-endpoint logon event at all — a compromised M365 account is accessed via OWA, Outlook mobile, or Microsoft Graph/API access, none of which necessarily touch a corporate Windows host's Security log. This is squarely [`Cloud/Microsoft/Entra ID/Sign-in Logs`](<../../Cloud/Microsoft/Entra%20ID/Sign-in%20Logs/Sign-in%20Logs%20for%20DFIR.md>)'s territory: pull sign-in events for the account around the phishing timestamp, checking for an unfamiliar IP/ASN, an impossible-travel pattern against the user's known-good sign-ins, and — critically for the AiTM case — a **successful sign-in with MFA already satisfied that the user does not recall performing** (Step 5 develops this further). Don't stop at "a sign-in occurred" — confirm it's genuinely anomalous against the account's own baseline, the same caution note 05 and the RDP Brute-Force Playbook both apply to a bare logon-success event.

### PowerShell

On-host / interactive evidence: pull 4648 explicit-credential logons for the phished account, distinct from the Hunt Evil block's 4624/4625 sweep — 4648 corroborates that a *different* credential was explicitly supplied for a specific target, rather than a normal interactive logon under the account's own session:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4648; StartTime=(Get-Date).AddDays(-3)} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match '<AccountName>' } |
    Select-Object TimeCreated, @{N='TargetServer';E={$_.Properties[8].Value}}, @{N='ProcessName';E={$_.Properties[9].Value}}
```

Cloud/M365 sign-in evidence — where most BEC compromise actually plays out — requires the Microsoft Graph/Entra module stack, not native PowerShell; full query depth lives in [`Cloud/Microsoft/Entra ID/Sign-in Logs`](<../../Cloud/Microsoft/Entra%20ID/Sign-in%20Logs/Sign-in%20Logs%20for%20DFIR.md>), not repeated here.

## Step 4 — Detect Inbox-Rule Abuse (The Classic BEC Persistence Mechanism)

Once an M365 or Exchange account is confirmed compromised, the single highest-yield next check is **inbox-rule abuse** — an attacker-created rule that auto-forwards, auto-deletes, or auto-moves specific incoming mail, most commonly targeting replies to the fraudulent wire-transfer email the attacker is about to send (or has already sent) from the trusted account. This is the mechanism that lets a BEC operator keep operating from inside a legitimate mailbox for days or weeks without the account owner noticing anything is wrong — the victim keeps receiving and sending normal mail; the attacker's rule quietly siphons off or hides only the specific thread that would expose them.

[`15 - Email Forensics`](<../15 - Email Forensics.md#red-flags>) already flags mailbox-rule creation as a BEC persistence red flag; this step owns the full investigative sequence around it:

1. **Enumerate every rule on the compromised mailbox.** `Get-InboxRule -Mailbox <user>` (on-prem/hybrid Exchange) or the M365-equivalent cmdlet against Exchange Online — look for rules the account owner did not create. A rule with a **randomized or deliberately bland name** (or no name at all), created around the same timestamp as the Step 3 anomalous sign-in, is the strongest single finding in this step.
2. **Read what the rule actually does**, not just that it exists — the conditions (keyword match on sender, subject, or body — commonly targeting words like "invoice," "wire," "payment," "urgent," or the specific counterparty's domain) and the actions (forward to an external address, move to an obscure folder like RSS Feeds or Conversation History, mark as read, or delete outright). A rule that forwards matching mail to an external address **and** deletes/hides the original is the classic double-action BEC pattern — the account owner never sees the reply and the attacker gets it silently.
3. **Check `Get-MailboxAuditLog` / the Unified Audit Log for the rule's own creation event** (`New-InboxRule`/`Set-InboxRule` operations) — this ties the rule's creation to a specific sign-in session, closing the loop back to Step 3's compromise evidence rather than leaving the rule as an unexplained artifact.
4. **Check for a parallel `Add-MailboxPermission`/delegate-access or forwarding-SMTP-address change** on the mailbox — some BEC operators establish forwarding at the mailbox-settings level (a persistent SMTP forward) rather than, or in addition to, an inbox rule, since it doesn't show up in the rules list at all and is easy to miss if the investigation only checks rules.
5. **Prove the account was actually used to send fraudulent mail**, not just that a rule exists — pull the Sent Items folder (or its cloud-side equivalent via message trace / UAL `Send` operations) for messages sent during the compromise window that the account owner didn't author. A wire-fraud email sent *from* the trusted account to a real counterparty, sitting in Sent Items or provable via message trace even if the attacker deleted it from Sent Items afterward, is the evidence that turns "a rule existed" into "this account was actively used to defraud someone."
6. **Scope which recipients received attacker-controlled replies** — cross-reference the rule's forward-to address and the Sent Items/message-trace findings against the full distribution list of anyone who received a reply, follow-up, or new thread from the compromised account during the window. This recipient list is what Step 6 formalizes into a full impact scope.

Full cloud-side mechanics for this exact scenario — rule/forwarding hunting query syntax, `MailItemsAccessed`, message trace, and the decision tree for contain/eradicate/recover — are already built out in [`Cloud/Microsoft/M365/Exchange Online/Playbooks/Malicious Inbox Rules and Forwarding`](<../../Cloud/Microsoft/M365/Exchange%20Online/Playbooks/Malicious%20Inbox%20Rules%20and%20Forwarding.md>) and [`Cloud/Microsoft/M365/Exchange Online/Playbooks/Business Email Compromise`](<../../Cloud/Microsoft/M365/Exchange%20Online/Playbooks/Business%20Email%20Compromise.md>) — this step sequences the same investigation from the Windows/on-host-adjacent angle and points there for the platform-native query depth rather than re-deriving it.

## Step 5 — Detect MFA-Bypass / Adversary-in-the-Middle Session Theft

Adversary-in-the-middle (AiTM) phishing kits (Evilginx and similar reverse-proxy phishing frameworks) defeat MFA entirely, not by stealing a password to be guessed against later, but by transparently proxying the victim's real-time authentication session — the victim types their password and completes their actual MFA challenge against the real identity provider, believing they're on the legitimate site, while the kit sits in the middle and captures the resulting **session token/cookie** at the moment authentication succeeds. This is why this technique deserves its own step: **a simple password reset does not remediate it.** The attacker already holds a live, MFA-satisfied session token independent of the password — until that session is explicitly revoked, resetting the password changes nothing about the attacker's ongoing access.

**Detection sequence:**

1. **Sign-in log pattern in [`Cloud/Microsoft/Entra ID/Sign-in Logs`](<../../Cloud/Microsoft/Entra%20ID/Sign-in%20Logs/Sign-in%20Logs%20for%20DFIR.md>):** a successful sign-in showing MFA satisfied, immediately followed (often within seconds to minutes) by a second sign-in or token-refresh event **from a different IP/ASN/user-agent than the first**, for the same account, with no corresponding new MFA challenge on the second event. This "one real auth, two distinct sessions" pattern is the core AiTM tell — the victim authenticated once from their real location/device; the attacker's proxy replayed the resulting token from its own infrastructure moments later.
2. **Conditional Access evaluation results** for the suspicious sign-in — [`Cloud/Microsoft/Entra ID/Conditional Access & MFA for DFIR`](<../../Cloud/Microsoft/Entra%20ID/Conditional%20Access%20%26%20MFA/Conditional%20Access%20%26%20MFA%20for%20DFIR.md#the-how-did-they-beat-mfa-checklist>) carries a dedicated "How Did They Beat MFA?" checklist built exactly for this triage question — walk that checklist directly rather than re-deriving Conditional Access policy evaluation logic here.
3. **Token/session artifacts on the Windows endpoint, if the AiTM session was subsequently used from a corporate-managed device** — browser cookie stores for the identity-provider domain (note 14) may show a session cookie whose creation timestamp doesn't line up with any legitimate interactive sign-in the user performed on that device, corroborating that a token was injected/replayed rather than freshly issued through normal authentication on that machine.
4. **Continuous Access Evaluation (CAE) / token-revocation event check** — confirm whether the tenant's Conditional Access configuration supports and triggered token revocation on risk signals; if not, the stolen token may remain valid for its full lifetime regardless of password reset, which is the exact remediation gap this step exists to surface before handoff (Step 7).

🔴 **The single most important operational fact in this step:** if AiTM session theft is confirmed or even strongly suspected, remediation must include explicit **session/refresh-token revocation** (and, per current Microsoft guidance, potentially Continuous Access Evaluation configuration review) — not just a password reset. Flag this explicitly in the handoff to Step 7; a generic remediation checklist that only covers password reset will leave the attacker's session live.

## Step 6 — Scope Impact: Who Else Received Attacker Mail, What Was Accessed

Once compromise is confirmed (Step 3), and whichever mechanism sustained it is identified (Step 4's inbox rules and/or Step 5's session theft), scope the blast radius before moving to remediation:

- **Recipients of attacker-sent mail** — the Sent Items / message-trace reconstruction from Step 4.5 gives the direct recipient list; cross-reference against any known business relationships (vendors, customers, finance contacts) to prioritize outbound notification, since a lateral-phishing email sent from a trusted internal account to other employees or to external partners carries materially higher click-through risk than a cold phish from an unknown sender.
- **What the attacker actually read, not just what they sent** — Exchange Online's `MailItemsAccessed` operation (cross-ref [`15 - Email Forensics`](<../15 - Email Forensics.md#m365-ual--extractor-suite-deferred>) and the Cloud/ Exchange Online notes it defers to) is the evidence source for confirming which specific messages/attachments the attacker's session actually opened during the compromise window — materially different from "the mailbox was accessible," since a compromised account with a long dwell time may have only read a handful of specific threads relevant to the fraud.
- **Whether the compromise reached beyond mail** — a compromised M365 identity is frequently a single sign-on into SharePoint/OneDrive, Teams, and other Microsoft Graph-accessible services; confirm whether the same session/account was used to access anything beyond Exchange before declaring the scope "email only."
- **Whether Track A (malware) also occurred in parallel** — a sophisticated actor sometimes pairs a credential-harvesting phish with a payload-delivery phish against the same target list; don't assume the two tracks are mutually exclusive for a given campaign.

## Step 7 — Remediation Handoff

This playbook stops at scoping. Full remediation mechanics — password reset, session/token revocation, account disable-don't-delete sequencing, and post-remediation verification — are [`21 - Remediation and Containment`](<../21 - Remediation and Containment.md#account-and-credential-remediation>)'s job. Hand off with, at minimum:

- The confirmed compromise mechanism (credential reuse, AiTM session theft, or malware-driven foothold) — this determines whether a password reset alone is sufficient (credential reuse, no session theft) or whether explicit session/token revocation is mandatory (Step 5's AiTM finding).
- Every inbox rule, forwarding address, and delegate-access grant found in Step 4, documented (not yet deleted) — exported/documented first, disabled second, exactly as the disable-and-document principle the Ransomware Playbook's remediation section applies to persistence mechanisms generally.
- The full recipient/impact list from Step 6, for downstream notification and (where a Track A foothold was confirmed) escalation into the Ransomware Playbook if lateral movement or mass-deployment indicators are present.

## Investigative Sequence Summary

```
1. Detect delivery
   Attachment/link/QR-code technique identified (Step 1)
   → note 15 for header/attachment-chain depth
                    │
2. Confirm interaction
   Track A: execution evidence (note 06) → persistence (note 10)
   Track B: credential entered on fake login page (note 14)
                    │
3. Confirm account compromise
   On-host: Logon Type/4624/4625/4648 (note 05)
   Cloud: anomalous sign-in, MFA-already-satisfied (Cloud/Entra Sign-in Logs)
                    │
4. Inbox-rule / BEC persistence
   Get-InboxRule enumeration → rule creation tied to compromise sign-in
   → Sent Items/message-trace proof of fraudulent mail sent
   → recipient scoping begins here
   (Cloud/M365 Exchange Online BEC + Inbox Rules Playbooks)
                    │
5. MFA-bypass / AiTM detection
   One real auth, two sessions/IPs pattern → Conditional Access
   "How Did They Beat MFA?" checklist → session/token revocation flagged
   as mandatory, not optional
                    │
6. Scope impact
   Recipients of attacker mail · MailItemsAccessed · beyond-mail access
   · parallel Track A check
                    │
7. Remediation handoff
   Note 21 (account/credential + session revocation)
   · escalate to Ransomware Playbook if Track A + lateral movement found
```

## Pitfalls

| 🔴 Pitfall | Why it matters |
|---|---|
| Treating "user entered a password on a phishing page" as proof of compromise without checking Step 3 | A caught credential is not a used credential — MFA, a sinkholed kit, or simple attacker inattention can mean the credential was never successfully leveraged. Confirm actual sign-in/session use before calling it a compromise |
| Resetting the password and calling an AiTM case remediated | The stolen artifact in AiTM is a live session token, not the password itself — a password reset does nothing to a token that's already valid. Step 5's session/token revocation is mandatory in this scenario, not an optional extra |
| Checking only inbox rules and not mailbox-level forwarding/delegate settings | Some BEC operators establish persistence via a forwarding SMTP address or delegate grant instead of (or alongside) a rule — a rules-only sweep misses this entirely |
| Assuming QR-code phishing leaves the same endpoint evidence as a link in an email | The compromise-relevant browsing happens on the phone that scanned the code, largely invisible to the corporate endpoint's own telemetry — don't expect to find what isn't there; pivot to cloud-side sign-in evidence instead |
| Stopping at "found the malicious rule" without proving the account was actually used to send fraudulent mail | A rule alone shows intent/capability, not completed fraud — Sent Items and message-trace evidence is what actually proves financial/reputational impact and drives notification obligations |
| Assuming an ISO/LNK-smuggled payload will show the same Mark-of-the-Web trail as a directly-attached file | ISO mounting does not propagate Zone.Identifier to the files inside it — the outer container may show MOTW while the LNK/script inside shows none, and treating that absence as "this file wasn't from the internet" is exactly backward here |
| Scoping impact only to the mailbox | A compromised M365 identity is a single sign-on into SharePoint/OneDrive/Teams/Graph — confirm whether access extended beyond mail before declaring the incident email-only |

## Correlate With

| Note | Why |
|---|---|
| [`Windows Malware and Threat Landscape`](<Windows Malware and Threat Landscape.md>) | This folder's landing page — BEC/phishing sits under its own threat-category row, which this playbook now fills |
| [`05 - Users, Groups & Authentication`](<../05 - Users, Groups & Authentication.md>) | Logon-type/auth-event evidence for the on-host credential-harvesting → account-compromise pivot (Step 3) |
| [`06 - Evidence of Program Execution`](<../06 - Evidence of Program Execution>) | Execution evidence for Track A's payload once a malicious attachment/link is run (Step 2) |
| [`10 - Persistence Mechanisms`](<../10 - Persistence Mechanisms>) | What a Track A foothold sets up to survive reboot/account remediation |
| [`11 - Event Log Analysis`](<../11 - Event Log Analysis.md>) | Underlying Security-log mechanics behind the 4624/4625/4648 evidence cited in Step 3 |
| [`12 - Lateral Movement`](<../12 - Lateral Movement.md>) | Where a Track A foothold goes next if the phish escalates beyond a single endpoint |
| [`14 - Web Browser Forensics`](<../14 - Web Browser Forensics>) | Credential-entry evidence (Step 2), session-cookie artifacts for AiTM corroboration (Step 5) |
| [`15 - Email Forensics`](<../15 - Email Forensics.md>) | Header/attachment-chain depth for Step 1, mailbox-rule red flag this playbook's Step 4 owns the full sequence around |
| [`16 - Live Response and Volatile Data`](<../16 - Live Response and Volatile Data.md>) | Live triage sequencing if Track A execution is confirmed and the host may still be active |
| [`20 - Threat Hunting Methodology and Intelligence`](<../20 - Threat Hunting Methodology and Intelligence.md>) | Feedback loop for phishing-domain/kit indicators extracted from this investigation |
| [`21 - Remediation and Containment`](<../21 - Remediation and Containment.md#account-and-credential-remediation>) | Account/credential/session remediation once compromise is confirmed (Step 7) |
| Ransomware Playbook (this folder) | The likely next stage if a Track A foothold escalates into domain-wide lateral movement and mass deployment |
| [`Cloud/Microsoft/Entra ID/Sign-in Logs`](<../../Cloud/Microsoft/Entra%20ID/Sign-in%20Logs/Sign-in%20Logs%20for%20DFIR.md>) | Cloud-side sign-in evidence for Step 3's account-compromise confirmation and Step 5's AiTM pattern |
| [`Cloud/Microsoft/Entra ID/Conditional Access & MFA for DFIR`](<../../Cloud/Microsoft/Entra%20ID/Conditional%20Access%20%26%20MFA/Conditional%20Access%20%26%20MFA%20for%20DFIR.md#the-how-did-they-beat-mfa-checklist>) | The "How Did They Beat MFA?" checklist Step 5 walks directly |
| [`Cloud/Microsoft/M365/Exchange Online/Playbooks/Malicious Inbox Rules and Forwarding`](<../../Cloud/Microsoft/M365/Exchange%20Online/Playbooks/Malicious%20Inbox%20Rules%20and%20Forwarding.md>) | Platform-native query depth and contain/eradicate/recover sequencing behind Step 4 |
| [`Cloud/Microsoft/M365/Exchange Online/Playbooks/Business Email Compromise`](<../../Cloud/Microsoft/M365/Exchange%20Online/Playbooks/Business%20Email%20Compromise.md>) | Full cloud-side BEC investigation depth (fraud quantification, decision points) this playbook's Steps 4/6 point to rather than re-derive |

## Resources

- MITRE ATT&CK **T1566 (Phishing)** and its sub-techniques — T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link), T1566.003 (Spearphishing via Service) — the delivery techniques Step 1 detects.
- MITRE ATT&CK **T1204 (User Execution)** — the Step 2 Track A engagement, and **T1027.006 (HTML Smuggling)** for that specific delivery technique.
- MITRE ATT&CK **T1114 (Email Collection)** — already cited in [`15 - Email Forensics`](<../15 - Email Forensics.md>); the account-collection technique underlying inbox-rule/`MailItemsAccessed` abuse in Step 4/6.
- MITRE ATT&CK **T1098.002 (Account Manipulation: Additional Email Delegate Permissions)** and the related forwarding-rule technique — the classic BEC persistence mechanism Step 4 walks in full.
- MITRE ATT&CK **T1557 (Adversary-in-the-Middle)** and **T1539 (Steal Web Session Cookie)** — the AiTM/session-theft techniques Step 5 detects.
- SANS FOR508 poster/index — used as a coverage-checklist only during this playbook's construction; no content reproduced verbatim. No dedicated phishing/BEC playbook content was found there beyond what's already reflected in notes 05/14/15.
- Microsoft Learn — Adversary-in-the-middle (AiTM) phishing attack guidance and Continuous Access Evaluation documentation — consult current documentation for exact session-token protection/revocation mechanics referenced in Step 5.
