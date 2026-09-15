# Macie for DFIR

A Macie finding answers the question every exposed-bucket incident eventually needs answered: **what was actually in it?** GuardDuty and Config tell you a bucket was public; Macie tells you whether that bucket held PII, credentials, or financial data — and how much.

New to the service? Read **What is Macie** first. This note is the *how*.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate — Confirming What Was Exposed](#investigate--confirming-what-was-exposed)
- [Reading a Finding](#reading-a-finding)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

Macie answers **"did sensitive data actually leave, and how much?"** — the question that separates a "we had a misconfiguration" writeup from a breach-notification obligation. It only sees what it's been pointed at (automated discovery is a sample; a classification job is a deep scan of what you choose), and like every detection service it can be disabled or its findings suppressed.

The core IR use case: an **Exposed S3 Bucket** incident (→ **S3 → Playbooks → Exposed S3 Bucket**) tells you a bucket was public and *may* tell you objects were read. Macie is how you turn "may have been read" into "here is exactly what kind of data was in the objects that were readable" — the input regulators, legal, and comms need.

## Evidence It Produces

| Evidence | What it gives you | Where |
|----------|-------------------|-------|
| **Sensitive data findings** | Data category (PII/credentials/financial/custom), occurrence counts, affected object | Macie console / API / EventBridge |
| **Policy findings** | Bucket-level exposure state (public, shared externally, unencrypted) | Same |
| Finding detail JSON | Sample locations (not raw values), classification confidence | `get-findings` |
| Classification job results | Per-bucket sensitivity score, scan coverage/completion | `describe-classification-job`, job result S3 export |
| **CloudTrail `macie2.*`** | Who changed Macie config (🔴 disable/suppress) | CloudTrail |

**In SecOps:** if forwarded through Security Hub, Macie findings land as Security Hub ASFF findings (log type `AWS_SECURITY_HUB`); a native `AWS_MACIE` mapping may also exist depending on ingestion setup. Confirm against a sample event — parsers vary.

## Collect It

**Step 1 — Confirm Macie was even on, and what it was watching.**

```bash
# Is Macie enabled in this account/region, and since when?
aws macie2 get-macie-session --query '{Status:status,CreatedAt:createdAt}'

# What buckets is automated discovery covering, and what's their sensitivity score?
aws macie2 describe-buckets --query 'buckets[].{Bucket:bucketName,Sensitivity:sensitivityScore,Public:publicAccess}'
```

> **Console:** Macie → **Settings** → status. Macie → **S3 buckets** → sensitivity score per bucket.

**Step 2 — Pull findings for the bucket/window in question.**

```bash
# List findings scoped to a bucket, filtered by severity
aws macie2 list-findings \
  --finding-criteria '{"criterion":{"resourcesAffected.s3Bucket.name":{"eq":["<bucket>"]}}}'

# Pull full detail (data categories, counts, sample locations) for specific findings
aws macie2 get-findings --finding-ids <fid1> <fid2> > findings.json
```

> **Console:** Macie → **Findings** → filter by *bucket* / *type* / *severity* → open a finding for full detail.

**Step 3 — If nothing was scanned yet, run a targeted classification job now.**

```bash
aws macie2 create-classification-job \
  --job-type ONE_TIME \
  --name "ir-<bucket>-<date>" \
  --s3-job-definition '{"bucketDefinitions":[{"accountId":"<acct>","buckets":["<bucket>"]}]}'

# Check job progress / pull results
aws macie2 describe-classification-job --job-id <job-id>
```

> 🔴 A classification job on a large bucket takes time and costs money (per-GB pricing) — scope it to the prefix/date range that matters, not the whole bucket, if you can bound the exposure window first via CloudTrail/Config.

**Step 4 — Confirm nobody suppressed or disabled Macie during the window.**

```bash
aws macie2 list-findings-filters                       # suppression rules?
aws macie2 list-members --query 'members[].{Account:accountId,Status:relationshipStatus}'
```

## Investigate — Confirming What Was Exposed

The flow, tying Macie back into the broader exposed-bucket investigation:

| Step | Do this |
|------|---------|
| 1. Establish the exposure window | From Config/CloudTrail (→ **Exposed S3 Bucket** playbook) — when did the bucket go public, when was it fixed |
| 2. Check for existing findings | Did automated discovery or a prior job already classify this bucket? Pull findings first before running a new job |
| 3. Run a targeted job if needed | Scan the bucket/prefix that was exposed, scoped to the relevant window if the data changed over time |
| 4. Read the data categories | `SensitiveData:S3Object/Personal|Credentials|Financial` — what *kind* of data, and how many matches |
| 5. Cross the finding with access evidence | Was the flagged object among those actually `GetObject`'d during the exposure window? (→ S3 data events / CloudTrail) |
| 6. Scope the blast radius | Every object with a sensitive-data finding **and** confirmed external read = your breach-notification scope |

> Macie tells you what's *in* the object. It does **not** by itself tell you the object was *read* by the attacker — that's S3 data events. You need both to say "X sensitive records were exposed to the internet" vs. "X sensitive records existed in a bucket that was briefly misconfigured."

## Reading a Finding

```jsonc
{
  "type": "SensitiveData:S3Object/Personal",
  "severity": { "description": "High" },
  "resourcesAffected": {
    "s3Bucket": { "name": "customer-exports", "publicAccess": { "effectivePermission": "PUBLIC" } },
    "s3Object": { "key": "exports/2026-07-08/orders.csv" }
  },
  "classificationDetails": {
    "result": {
      "sensitiveData": [
        { "category": "PERSONAL_INFORMATION",
          "detections": [ { "type": "USA_SOCIAL_SECURITY_NUMBER", "count": 412 } ] }
      ]
    }
  },
  "createdAt": "2026-07-09T15:10:00Z"
}
```

Read it as: *`exports/2026-07-08/orders.csv` in the publicly-readable `customer-exports` bucket contains 412 SSN matches* → confirmed high-severity PII exposure. Pivot to S3 data events to check whether that specific key was `GetObject`'d during the public window, and to CloudTrail for who made the bucket public in the first place.

## Hunt at Scale

**In-platform — Macie findings, filtered:**

```bash
# All high-severity sensitive-data findings across the account/org right now
aws macie2 list-findings \
  --finding-criteria '{"criterion":{"severity.description":{"eq":["High"]},"type":{"eq":["SensitiveData:S3Object/Personal","SensitiveData:S3Object/Credentials","SensitiveData:S3Object/Financial"]}}}'
```

**In-platform — the config-tamper CloudTrail (Athena/Lake):**

```sql
SELECT eventtime, useridentity.arn, eventname, awsregion
FROM cloudtrail_logs
WHERE eventsource = 'macie2.amazonaws.com'
  AND eventname IN ('DisableMacie','CreateFindingsFilter','ArchiveFindings',
                    'DisassociateMember','DeleteMember','UpdateClassificationJob')
  AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):** if findings flow through Security Hub, they're queryable there for cross-account correlation; otherwise stay in-platform (Macie is lower-volume than CloudTrail/GuardDuty and rarely needs SIEM-scale hunting).

## Respond

| Goal | Action |
|------|--------|
| Confirm scope | Cross Macie's affected-object list with confirmed S3 reads (→ S3 for DFIR) to get the true exposed-record count |
| Re-privatize the data | → **Exposed S3 Bucket** playbook (`put-public-access-block`, remove public policy/ACL) |
| Preserve the finding + object evidence | Export `get-findings` JSON and snapshot the flagged object versions before any lifecycle rule expires them |
| Trigger breach process | Hand the confirmed data-category + record-count evidence to legal/compliance |
| Re-enable/un-suppress Macie | `EnableMacie`; delete rogue findings filters; re-run the classification job to catch anything archived during the incident |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enable Macie org-wide**, delegated admin, all regions in use | No blind account/region |
| Turn on **automated sensitive-data discovery** account-wide | Baseline risk visibility before an incident, not scrambling after |
| Schedule **recurring classification jobs** on crown-jewel buckets | Catch new sensitive data as it lands, not just at scan time |
| **SCP** denying `macie2:DisableMacie` / `CreateFindingsFilter` / `DisassociateMember` outside break-glass | Attacker can't blind or suppress Macie |
| Wire high-severity findings → **EventBridge** → auto-quarantine (remove public access / restrict object) | Contain faster than a human can |
| **Send findings to Security Hub + SecOps** | One pane; cross-account correlation |
| Pair with **Block Public Access** account-level + S3 data events (→ Exposed S3 Bucket "Fix the Misconfig") | Prevents the exposure Macie would otherwise just be reporting on |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `SensitiveData:S3Object/Personal|Credentials|Financial` on a **publicly accessible** bucket | Confirmed high-value exposure — prioritize |
| `Policy:IAMUser/S3BucketSharedExternally` on a bucket with sensitive-data findings | Cross-account exposure of regulated data |
| `DisableMacie` in the incident window | Detection turned off |
| New findings filter (suppression) created mid-incident | Attacker or insider silencing findings about their own access |
| Classification job cancelled mid-run during an active investigation | Someone stopping you from seeing what's in the bucket |
| Sensitive-data finding with **no** corresponding classification job — only automated discovery sampled it | Coverage gap; may be undercounting — run a targeted job |
| Macie never enabled in the breached account | Flying blind on data content — hardening finding |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What Macie is + finding types | **Macie → What is Macie** |
| The bucket/object evidence and access logs | **AWS → Storage → S3 → S3 for DFIR** |
| Working an exposed-bucket incident end to end | **AWS → Storage → S3 → Playbooks → Exposed S3 Bucket** |
| The API actions behind bucket/policy changes | **AWS → Logging & Monitoring → CloudTrail** |
| Aggregating across tools | **AWS → Security & Detection → Security Hub** |
| Correlated threat detection (public bucket, unusual access) | **AWS → Security & Detection → GuardDuty** |

## Resources

- Remediating Macie findings — https://docs.aws.amazon.com/macie/latest/user/findings-remediate.html
- Finding types (managed data identifiers) — https://docs.aws.amazon.com/macie/latest/user/findings-types.html
- Classification jobs — https://docs.aws.amazon.com/macie/latest/user/discovery-jobs.html
- MITRE ATT&CK Cloud (IaaS) — https://attack.mitre.org/matrices/enterprise/cloud/iaas/
