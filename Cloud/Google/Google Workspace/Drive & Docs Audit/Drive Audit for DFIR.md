# Drive Audit for DFIR

Drive cases are exfil cases: prove **what was downloaded or shared out, by whom, when** — and whether sensitive data actually left the org. The Drive audit log plus the Drive API's current-sharing view are your two pillars.

New to it? Read **What is the Drive Audit** first. This note is the *how*.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Did Data Actually Leave?](#did-data-actually-leave)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Retention | Best for |
|--------|--------------|-----------|----------|
| **Admin console → Audit → Drive** | Views/downloads/shares/deletes | ~6 months | First look |
| **Reports API** (`applicationName=drive`) | Same, scriptable | ~6 months | Bulk pulls |
| **BigQuery export** | Same, SQL | Your retention | Volume hunting |
| **Drive API** (`permissions.list`) | Current sharing state of a file | Live | Who can access it *now* |
| **Vault** | Hold + export Drive content | Hold | Preserve |

> ⚠️ Drive audit logging requires **Enterprise / Business Plus** editions. On lower tiers this evidence may not exist — confirm early.

## Collect It

**Console:** Admin console → **Reporting → Audit and investigation → Drive log events** → filter by user, event (`download`, `change_document_visibility`), date → **Export**.

**Current sharing of a suspect file/folder (Drive API / GAM):**

```bash
gam user victim@contoso.com show filelist query "..." fields id,name,permissions
# or Drive API: GET /drive/v3/files/{fileId}/permissions
```

**Preserve:** put affected users/shared drives on **Vault hold**.

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Confirm coverage | Drive logging on (edition)? Note retention + any BigQuery export |
| 2. Anchor the actor | Insider (departing employee) or compromised account (cross Login audit)? |
| 3. Bucket the activity | Downloads (exfil), visibility changes (exposure), deletes (destruction) |
| 4. Quantify | Count + list of files touched; flag by sensitivity/label |
| 5. Map external recipients | Every external share target / public link created |

## Did Data Actually Leave?

| If you see… | You can conclude |
|-------------|------------------|
| `download` events on the files | Content was pulled to a device 🎯 |
| `change_document_visibility` → public/link | The file was reachable by anyone with the URL |
| `change_user_access` → external address | Shared directly outside the org |
| `copy`/`print` at volume | Exfil via alternate path (evading download alerts) |
| Only `view` (no download) | Read, but no proven local copy — scope by sensitivity |

🔴 External share + subsequent access from an external identity = **confirmed** data left the org.

## Hunt at Scale

**BigQuery (Drive logs) — mass download by one user:**

```sql
SELECT actor.email, COUNT(*) AS downloads
FROM `contoso.workspace_logs.drive`
WHERE event.name = 'download'
  AND time_usec > UNIX_MICROS(TIMESTAMP '2026-07-01')
GROUP BY actor.email
HAVING downloads > 500
ORDER BY downloads DESC;
```

**Files made public / link-shared:**

```sql
SELECT time_usec, actor.email, doc.title, p.value AS visibility
FROM `contoso.workspace_logs.drive`, UNNEST(event.parameter) p
WHERE event.name = 'change_document_visibility'
  AND p.name = 'visibility' AND p.value IN ('public_on_the_web','people_with_link');
```

**External sharing:**

```sql
SELECT time_usec, actor.email, doc.title, target
FROM `contoso.workspace_logs.drive`
WHERE event.name = 'change_user_access' AND target NOT LIKE '%@contoso.com';
```

> **At the very end — SecOps UDM (optional):** land mass-download + external-share events to correlate the actor/IP and external recipients across the org. Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Stop exfil | Suspend the account (insider) or cut the session (compromised) |
| Revoke exposure | Remove public/link visibility; revoke external grants (Drive API / SIT bulk action) |
| Contain shared drives | Remove external members; audit membership |
| Preserve | Vault hold + export the Drive activity window |
| Recover | Rotate any secrets/keys that were in exposed docs |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Restrict external sharing** (allowlist domains / warn on external) | Limits data leaving |
| **Disable "anyone with the link" / public** for sensitive OUs | Kills leaky links |
| **DLP rules** on sensitive content (block external share/download) | Automated prevention |
| **Alert** on mass downloads + public-visibility changes | Early exfil detection |
| **Enable Drive logs → BigQuery** | Volume hunting + retention |
| **Trust rules** between shared drives | Contain cross-org sharing |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Hundreds of `download` events by one user in a short window | Bulk exfil |
| `change_document_visibility` → public/link on sensitive docs | Data exposure |
| External `change_user_access` grants | Data shared out of the org |
| Mass `copy`/`print` | Exfil evading download alerts |
| Downloads right before/after a resignation or a suspicious login | Insider or takeover exfil |
| Mass `trash`/`delete` | Destruction / cover tracks |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The Drive events + sharing model | **Drive & Docs Audit → What is** |
| The insider/compromised identity | **Workspace → Login & Auth Audit** · **Google → 01 Google Identities** |
| Mass-download exfil end to end | **Workspace → Playbooks → Mass Drive Exfiltration** |
| An OAuth app reading Drive | **Workspace → OAuth & Third-Party Apps** |

## Resources

- Drive audit log — https://support.google.com/a/answer/4579696
- Drive API permissions — https://developers.google.com/drive/api/reference/rest/v3/permissions
- Restrict external sharing — https://support.google.com/a/answer/60781
- DLP for Drive — https://support.google.com/a/answer/9646351
- MITRE ATT&CK: T1530 Data from Cloud Storage / T1567 Exfil Over Web Service — https://attack.mitre.org/techniques/T1530/
