# Certify — Target Evidence

Certify has no single "target" the way a lateral-movement tool does — its evidentiary footprint spans **three separate systems**: the **CA server** (AD CS's own database and, if configured, its Security-log auditing), the **domain controller(s)** holding the LDAP-readable PKI objects, and — for the actual authentication step a minted certificate is used for — a **second domain controller acting as KDC**, whose PKINIT evidence is already documented in `Rubeus/04 - Target Evidence.md` and cross-linked rather than re-derived here.

## The CA's Own Request Database — Evidence That Doesn't Depend on Auditing

**The single most important fact in this file:** every Windows CA maintains its own persistent request/certificate database (the `Access`-based Jet/ESE store behind `%SystemRoot%\System32\CertLog\`), queryable via `certutil -view`, that records every request the CA ever processed — requester identity, template name, subject/SAN values, disposition (issued/denied/pending/revoked/failed), and timestamp — **independent of whether Windows Security auditing is configured at all**. This is baseline CA architecture, not an optional feature: the "Issued Certificates," "Pending Requests," and "Failed Requests" containers visible in the Certification Authority MMC snap-in are views into this same database. **A CA with zero Security-log auditing enabled still retains a full, queryable record of every Certify `request`/`request-agent`/`request-download`/`request-renew` call it ever serviced.**

```
certutil -view -restrict "Request.RequesterName=GHOSTPACK\svc-web" -out "RequesterName,CertificateTemplate,NotBefore,SubjectAltName2,Disposition"
```

This works on **any** CA regardless of the Security-log auditing state discussed below — treat it as the first, always-available query, not a fallback.

## CA-Side Security Event Log — Requires Non-Default Configuration

Windows Server's dedicated "Audit Certification Services" subcategory (verified against Microsoft Learn's own reference) generates **31 distinct event IDs** (4868–4898) covering the full AD CS operational surface. **This auditing is not enabled by default and requires two separate configuration steps, both non-default, before a single one of these events appears in the Security log:**

1. **CA-side**: `certutil -setreg CA\AuditFilter 127` (127 = all seven audit-flag bits) via an elevated prompt on the CA server, or the equivalent checkboxes under the Certification Authority MMC snap-in's **Audit** tab — followed by a `CertSvc` service restart to take effect.
2. **Windows-side**: the **Object Access → Audit Certification Services** advanced audit subcategory must be enabled (`auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable`, or via GPO under Advanced Audit Policy Configuration), and — because this is a subcategory-level setting — **"Audit: Force audit policy subcategory settings" must also be enabled**, or a legacy basic audit policy can silently override it back off.

If either half is missing, Certify's live activity against that CA generates **no Security-log event at all**, even though the CA database record from the section above still exists. Verify both are configured before building a hunt around these event IDs — and if you can't confirm they are, fall back to the `certutil -view` query above.

**Event IDs most relevant to Certify's own verbs** (full 4868–4898 catalog per Microsoft Learn's "Audit Certification Services" reference):

| Event ID | Meaning | Certify verb it corresponds to |
|---|---|---|
| 4886 | Certificate Services received a certificate request | `request`, `request-agent`, `request-renew` — the initial submission |
| 4887 | Certificate Services approved a request and issued a certificate | Any of the above, when the template auto-issues (no manager approval) — this is the **ESC1 exploitation event** |
| 4888 | Certificate Services denied a certificate request | Auto-denial at request time (e.g. policy-module rejection) |
| 4889 | Certificate Services set the status of a request to pending | A `PEND_ALL_REQUESTS` (manager-approval) template — precedes `request-download` |
| 4868 | The certificate manager denied a **pending** certificate request | `manage-ca --deny-id` — distinct from 4888's auto-denial; this is a human/administrative deny of an already-pending request |
| 4870 | Certificate Services revoked a certificate | `manage-ca --revoke-cert` |
| 4869 | Certificate Services received a resubmitted certificate request | A repeat `request-download`/renewal-style resubmission |
| 4873 / 4874 | A certificate request extension / attribute changed | `manage-ca --issuance-policy` / `--application-policy` |
| 4882 | Security permissions for Certificate Services changed | `manage-ca --enroll`/`--officer`/`--admin` role toggles |
| 4891 / 4892 | A configuration entry / property changed in Certificate Services | `manage-ca --esc6`/`--esc11`/`--esc16` flag toggles |
| 4880 / 4881 | Certificate Services started / stopped | The **mandatory `CertSvc` restart** every `manage-ca` flag toggle triggers (see `01`) — a 4881/4880 pair with no independent administrative cause is a strong secondary signal that a CA-wide flag was just changed |
| 4885 | The audit filter for Certificate Services changed | Fires if an operator (or defender) changes `CA\AuditFilter` itself — worth watching as a tamper indicator either direction |

## LDAP Enumeration Evidence — Same Gap as AdFind

Certify's `enum-cas`/`enum-templates`/`enum-pkiobjects` are plain, normal-looking authenticated LDAP reads against the five PKI containers documented in `01`. **Active Directory logs essentially nothing about a normal LDAP read by default** — the same finding already documented in depth in `AdFind/01 - Overview.md`: Event 1644 (expensive/inefficient LDAP query) requires non-default Field Engineering diagnostic logging, and there is no default AD equivalent of a file-access audit for object *reads*. Don't expect a DC-side event trail for the reconnaissance phase — the strongest signal for this phase lives on the **source** host (Sysmon 1/3 for the Certify process and its LDAP connection, per `03 - Source Evidence.md`), not the DC.

**One exception**: `enum-cas`'s remote-registry reads against the CA server (ESC6/ESC7/ESC11/ESC16) are Remote Registry Protocol operations, not LDAP — if the CA server has Object Access auditing enabled for its registry hive specifically (also non-default), Event **4657** (a registry value was modified — not applicable, reads aren't audited by that event) does not apply; **registry value reads have no dedicated default Windows audit event at all**, matching the LDAP-read gap above. Both enumeration paths are effectively silent by design absent non-default, deliberately configured auditing.

## PKINIT Authentication Evidence — Cross-Linked, Not Re-Derived

The actual redemption of a Certify-minted certificate — `Rubeus asktgt /certificate:` performing the RFC 4556 PKINIT exchange — generates DC-side Kerberos evidence that is **not Certify-specific** and is already fully documented in `Rubeus/04 - Target Evidence.md`'s PKINIT-related rows and `01 - Overview.md`'s Techniques table. Apply that page's Event 4768 analysis directly; the one Certify-specific detail worth adding here is that the certificate's issuing CA chain must be present in the DC's trust store (or `NTAuthCertificates`, per `01`) for the PKINIT pre-authentication to succeed at all — a forged (`forge` verb) certificate signed by a CA the DC doesn't trust fails at this step, which is itself a useful negative-evidence signal (a PKINIT attempt against a cert whose issuer isn't in `NTAuthCertificates` should fail cleanly, and DC-side Kerberos error codes reflect that specific failure mode rather than a generic auth failure).

## Filesystem / Registry on the CA or Domain Controller

Certify itself writes nothing to the CA's or DC's filesystem or registry directly — `manage-ca`'s flag toggles modify the CA's **own configuration registry** (`SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA-Name>\...`), which is a target-side artifact in its own right: a diff of `EditFlags`/`InterfaceFlags`/`DisableExtensionList` against a known-good baseline directly reveals ESC6/ESC11/ESC16 tampering, independent of whether the corresponding 4891/4892 events were logged. `manage-template`'s writes land in Active Directory itself (the template object's own attributes/ACL), covered below.

## Directory Service Changes — `manage-template`'s LDAP Writes

`manage-template`'s ACL/attribute/EKU/flag modifications are plain LDAP writes against the template's AD object. Per the same non-default-auditing pattern this repo has already found for `LOLBins/setspn/`'s SPN writes and `PowerSploit/PowerView/`'s ACL modifications: Event **5136** (A directory service object was modified) only fires if **"Audit Directory Service Changes"** is enabled **and** a SACL is configured on the specific template object (or its parent OU) — neither is default. Where enabled, 5136 captures the specific attribute changed (`msPKI-Certificate-Name-Flag`, `msPKI-Enrollment-Flag`, `nTSecurityDescriptor`, etc.) with old/new values, which is the most precise available record of exactly what an ESC4 self-escalation step changed.

## Endpoint-Security-Product Signature Behavior

- On the **CA server**, EDR/AV coverage is generally weaker than on a typical workstation — CA servers are frequently under-monitored relative to domain controllers, despite being an equivalently high-value target (this asymmetry is part of why AD CS misconfiguration abuse became a major post-2021 attack path in the first place).
- Because no official Certify binary exists (per `01`/`03`), static signature detection on any recovered `.pfx` or Certify binary is inherently weak — behavioral detection (the DCOM/RPC call pattern to `ICertRequest`/`ICertAdminD2`, the paired ESC8 HTTP(S) probe, the forged-certificate EKU fingerprint documented in `03`) is the more durable approach.
- A `CertSvc` service restart with no correlated Windows Update/patch/administrative-change window is a meaningful anomaly on its own — most legitimate CA configuration changes are planned, infrequent events, not something that happens ad hoc during normal operations.

## Building a Timeline

Chain source and target evidence together in this order for a realistic Certify incident reconstruction:

1. **Source-host enumeration activity** (`03`) — LDAP/registry reads establishing recon occurred, and against which templates/CAs.
2. **CA database record** (`certutil -view`, always available regardless of audit config) — the authoritative, always-present record of exactly which template was requested, by whom, with what SAN/subject, and when.
3. **[If CA auditing enabled] CA Security-log event** (4886/4887/4888/4889, or the `manage-ca`/`manage-template` administrative events) — corroborating timestamp and disposition, plus the loud 4880/4881 `CertSvc` restart pair if any `--esc*` flag was toggled.
4. **[If Directory Service Changes auditing enabled] Event 5136** — for `manage-template` ACL/attribute writes specifically, with old/new attribute values.
5. **Source-host local artifact** (`03`) — whether the resulting certificate/private key still exists on the operator's host (cert store, `.pfx`, `--out-file` target).
6. **DC-side PKINIT authentication evidence** — cross-reference `Rubeus/04 - Target Evidence.md`'s Event 4768 analysis for the actual redemption of the certificate into a usable TGT, and everything that TGT was subsequently used for.

Step 2 is the load-bearing one: unlike most tools in this repo, Certify's target-side evidence trail does **not** collapse to nothing when Windows-native auditing is off, because the CA's own database is a separate, always-on record — the caveat is knowing to query it directly (`certutil -view`) rather than assuming Security-log silence means no evidence exists.
