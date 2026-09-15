# Certipy — Detection and Hunting

## Hunting Priority

Certipy exposes real variation in evasion difficulty across its command surface — some artifacts are baked into the tool's own source and can't be flag-toggled away at all, others depend entirely on non-default auditing being configured, and one (the pre-built `Certipy.exe`) is trivially defeated by anyone willing to rebuild from the public source. Ranked by which signals survive the most operator choices:

| Rank | Signal | Survives a source rebuild/rename? | Requires non-default auditing? | Notes |
|---|---|---|---|---|
| 1 | `certutil.exe` child process with the literal string `certipy` (the hardcoded `-p certipy` backup password) under a `cmd.exe` parent under `services.exe`, on a CA server | ✅ Yes — the password is fixed in `ca.py`'s source, not an operator-supplied flag | No — Sysmon Event ID 1 process-creation, or even a default `services.exe` child-process baseline, catches this | The single highest-confidence signal in this table; only defeated by an operator patching and recompiling `ca.py` itself before running `-backup` |
| 2 | Microsoft Defender for Identity alert 2431 ("Suspected account takeover using shadow credentials") | ✅ Yes | **No** — MDI's detection doesn't depend on Directory Service Changes auditing | Fires regardless of AD audit-policy state, unlike every LDAP-write signal below it |
| 3 | A `Certipy`-named service (even briefly) via 7045/4697/7036 on a CA server | ✅ Yes on first occurrence per CA | 4697 needs "Audit Security System Extension"; 7045/7036 are unconditional | **Only the first `ca -backup` against a given CA is loud this way** — a repeat invocation reusing the existing service leaves no 4697/7045 at all (see `04`) — rank this signal high but not infallible |
| 4 | CA request-database record (`certutil -view`) naming a template/SAN mismatch (e.g. `Administrator` SAN requested by a low-privileged account) | ✅ Yes | **No** — the CA's own database is always-on regardless of Security-log auditing | Silent for `forge` (never touches the CA) — see `04`'s timeline caveat |
| 5 | Event 5136 on `userPrincipalName`/template-attribute/`msDS-KeyCredentialLink` changes | ✅ Yes | **Yes** — "Audit Directory Service Changes" + a SACL, neither default | Strong when present, structurally absent in most default-configured domains |
| 6 | CA Security-log 4886–4898 family | ✅ Yes | **Yes** — two independent non-default configuration steps (see `04`, cross-linked from `Certify/04`) | Same gap Certify's own page already documents in depth |
| 7 | PE metadata / hash of the official `Certipy.exe` release | ❌ **No** | No | Trivially defeated — the CI build pipeline is public, anyone can produce a byte-different, functionally identical binary; weakest signal in this table by construction, same conclusion `Rubeus/05` reaches for its own no-official-binary posture, but for the opposite reason (Certipy's binary exists but is freely reproducible) |
| 8 | Command-line credential/flag matching (`-p`, `-upn`, `-application-policies`, etc.) | ⚠️ Partial | No | Fully defeated by `-hashes`/`-k` (no password on the line) or by wrapping Certipy's own Python entry point programmatically rather than invoking the CLI |

## Hunting on Source

**The `Certipy`/`certipy-ad` install footprint (cheap first pass):**

```bash
# Linux/macOS attacking host or pivot box
pip show certipy-ad 2>/dev/null
find / -xdev -iname "*certipy*" -type f 2>/dev/null | grep -v proc
```

**Certipy's own predictable output-file naming (see `03`) — a filesystem sweep on a suspected pivot host:**

```bash
find / -xdev \( -name "*_Certipy.txt" -o -name "*_Certipy.json" -o -name "*_Templates_Certipy.csv" \
    -o -name "*_CAs_Certipy.csv" -o -name "*.pfx" -o -name "*.ccache" -o -name "*.kirbi" \) \
    -newermt "-7 days" 2>/dev/null
```

A cluster of `.pfx`/`.ccache` files with the *same* identity-derived basename (e.g. `administrator.pfx` + `administrator.ccache`) sitting alongside a `<timestamp>_Certipy.json` is close to unambiguous evidence of a completed `find` → `req` → `auth` chain on that host.

**`KRB5CCNAME` in a live process environment:**

```bash
for pid in $(pgrep -f certipy); do
    echo "PID $pid:"; tr '\0' '\n' < /proc/$pid/environ 2>/dev/null | grep -i KRB5CCNAME
done
```

**Command-line matching (rank 8 — cheap, know its blind spot):**

```powershell
# Sysmon Event ID 1 / Security 4688, if Certipy was run from a Windows-hosted
# shell (WSL, or the official Certipy.exe)
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]" |
    Where-Object { $_.Message -match '(certipy|-backupkey|application-policies|write-default-configuration)' }
```

## Hunting on Target

**Rank 1 — the CA-server process tree (highest-confidence signal in this page):**

```powershell
# Run on, or collect Sysmon Event ID 1 forwarded from, the CA server
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object {
        $_.Id -eq 1 -and
        $_.Message -match 'Image:.*certutil\.exe' -and
        $_.Message -match 'CommandLine:.*-p certipy'
    }
```

**Rank 2 — MDI Shadow Credentials alert:** surfaced directly in the Microsoft Defender portal / Defender for Identity alert queue as **"Suspected account takeover using shadow credentials"** (External ID **2431**) — no custom query needed if Defender for Identity is deployed; confirm sensor coverage on the relevant DCs if this alert class has never fired in an environment that should be generating it.

**Rank 3 — first-time `Certipy`-service creation on a CA server:**

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
    Where-Object { $_.Message -match 'ServiceName:\s+Certipy' }

Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4697} |
    Where-Object { $_.Message -match 'Service Name:\s+Certipy' }
```

Remember rank 3's caveat from the table above: **this misses every backup after the first** on a given CA, since Certipy reuses the existing service via `ChangeServiceConfigW` (no 4697/7045) rather than recreating it. Pair with a direct registry/service-list sweep for defense in depth:

```powershell
Invoke-Command -ComputerName $CAServers -ScriptBlock {
    Get-Service -Name Certipy -ErrorAction SilentlyContinue
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Certipy' -ErrorAction SilentlyContinue
}
```

**Rank 4 — CA request database, independent of audit configuration:**

```cmd
certutil -view -restrict "Disposition=20" -out "RequesterName,CertificateTemplate,NotBefore,SubjectAltName2" | findstr /i "Administrator Domain Admins Enterprise Admins"
```

Look specifically for a `RequesterName` that does **not** match the SAN/UPN identity named in the same row — that mismatch is the ESC1/ESC9/ESC17-class signature regardless of which client tool (Certify or Certipy) produced it.

**Rank 5 — Directory Service Changes, where enabled:**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5136} |
    Where-Object { $_.Message -match 'userPrincipalName|msDS-KeyCredentialLink|msPKI-Certificate-Name-Flag|msPKI-Enrollment-Flag' }
```

A `userPrincipalName` 5136 followed by a second 5136 reverting the **same** attribute on the **same** object within minutes is the UPN-manipulate-then-revert pattern `02`'s ESC9/ESC10 walkthroughs describe — flag this shape specifically, not just any single UPN change.

**Rank 6 — CA Security-log 4886–4898 family:** apply `GhostPack/Certify/05 - Detection and Hunting.md`'s existing hunting queries for this event range directly — mechanically identical regardless of which client submitted the request. Not re-derived here.

**Relay detection (ESC8/ESC11):** apply `Impacket/ntlmrelayx/05 - Detection and Hunting.md`'s coercion/relay hunting guidance directly — cross-linked, not re-derived, since Certipy's `relay` engine produces the same network-layer shape.

**PKINIT/Schannel redemption:** apply `Rubeus/05 - Detection and Hunting.md`'s Event 4768 PKINIT hunting guidance directly for `certipy auth`'s default path; for `-ldap-shell`'s Schannel path, hunt for LDAPS (636) client-certificate TLS sessions from unexpected source hosts rather than a Kerberos event, since none is generated.

## Fleet-Wide Sweep

```powershell
# CA-side: sweep every enterprise CA for the Certipy-service/certutil-child pattern
# and for CA-database requester/SAN mismatches, in one pass
$CAs = certutil -config - -ping 2>$null; # enumerate reachable CAs per environment convention
Invoke-Command -ComputerName $CAServers -ScriptBlock {
    Get-Service -Name Certipy -ErrorAction SilentlyContinue
    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 1 -and $_.Message -match 'certutil\.exe.*-p certipy' }
} -ErrorAction SilentlyContinue

# DC-side: sweep for the MDI Shadow Credentials alert plus 5136 UPN-manipulation
# bursts across all DCs with Directory Service Changes auditing enabled
$DCs = (Get-ADDomainController -Filter *).HostName
Invoke-Command -ComputerName $DCs -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5136; StartTime=(Get-Date).AddHours(-24)} |
        Where-Object { $_.Message -match 'userPrincipalName|msDS-KeyCredentialLink' }
} -ErrorAction SilentlyContinue

# Endpoint-side: sweep the fleet for the pip/pipx install footprint and Certipy's
# own predictable output-file naming on any host that shouldn't have it
Invoke-Command -ComputerName (Get-ADComputer -Filter *).Name -ScriptBlock {
    Get-ChildItem -Path C:\ -Recurse -Include "*_Certipy.txt","*_Certipy.json" -ErrorAction SilentlyContinue
} -ErrorAction SilentlyContinue
```

## Remediation

**Capture the CA request database record, any recovered `.pfx`/`.ccache` material, and the full event-log window before taking any of the following actions** — revoking certificates or resetting keys invalidates the very material an investigation may still need to characterize scope.

- **If a CA private key was confirmed stolen (`ca -backup`/rank 1 or rank 3 fired):** treat this as full CA compromise — rebuild the CA from a known-good state or, at minimum, revoke and reissue the CA's own certificate chain; every certificate that CA ever issued is now suspect, since a stolen key enables fully offline forgery (`forge`) with no further target-side evidence generated.
- **Revoke any certificate confirmed issued via an ESC1/ESC3/ESC6/ESC9/ESC13/ESC15/ESC16/ESC17 exploitation path** (`certutil -revoke`, or `certipy ca -deny-request`/an equivalent legitimate-admin action) and reset the impersonated account's password/Kerberos keys — a revoked cert alone doesn't invalidate a TGT already obtained from it before revocation, so also purge/force-logoff any session established from that TGT.
- **Remove any `msDS-KeyCredentialLink` entries not tied to a known, legitimate Windows Hello for Business/Azure AD device registration** — `certipy shadow list`/`info`'s own DeviceID output format is directly usable for identifying which entries to review; use `shadow remove -device-id <id>` (as a defender running Certipy itself for cleanup) or the equivalent `Set-ADObject`/`ldp.exe` removal.
- **Fix the underlying template/CA misconfiguration, not just the one exploited instance** — remove `ENROLLEE_SUPPLIES_SUBJECT` from templates that don't need it, restrict enrollment rights on any template flagged by `find -vulnerable`, clear `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6) and enforce `IF_ENFORCEENCRYPTICERTREQUEST` (ESC11) CA-wide, and set `StrongCertificateBindingEnforcement=2` on all DCs per KB5014754 once compatibility testing is complete.
- **Enable the auditing this page's hunts depend on**: "Audit Certification Services" on the CA (both the CA's own Audit tab and the Object Access subcategory, per `GhostPack/Certify/04`'s configuration steps), "Audit Security System Extension" (for 4697 service-install coverage), and "Audit Directory Service Changes" with SACLs on PKI-relevant OUs (for 5136 coverage on `account`/`template`/`shadow` writes) — none are default, and every one of them is a real detection gap in this page's hunting guidance until explicitly configured.
- **Confirm Microsoft Defender for Identity sensor coverage on every CA server, not just DCs** — MDI's shadow-credentials alert (2431) is DC-centric by nature of watching directory writes, but CA-server-specific attacks (`ca -backup`) benefit from the same sensor placement discipline any high-value server deserves.
