# What is Macie?

**Amazon Macie** is AWS's **managed sensitive-data discovery service.** It uses machine learning and pattern matching to scan **S3** buckets and objects for PII, credentials, financial data, and other sensitive content — then raises **findings** telling you what's exposed and where.

For an analyst, Macie answers a question GuardDuty and CloudTrail can't: not just *"was this bucket public"* or *"was this object read,"* but **"what was actually IN it."** That's the difference between "a bucket was exposed" and "500 customer SSNs were exposed."

## Contents

- [How It Works](#how-it-works)
- [The Two Finding Categories](#the-two-finding-categories)
- [Anatomy of a Finding](#anatomy-of-a-finding)
- [Finding Types Worth Knowing](#finding-types-worth-knowing)
- [How to Identify Macie in Evidence](#how-to-identify-macie-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
S3 buckets/objects  ── Macie enumerates + samples ──►
        │  ML classification (PII, credentials, financial, custom identifiers)
        │  + bucket-policy/ACL analysis
        ▼
     FINDING  ── type, severity, affected bucket/object, sample ──►  Console / EventBridge / Security Hub
```

- Macie doesn't run continuously by default the way GuardDuty does — you **enable it** and either run a **one-time classification job** or schedule **recurring jobs** against chosen buckets/prefixes.
- It's **regional** and **per-account**, aggregatable **org-wide** from a delegated Macie admin account.
- Two independent things happen: **automated sensitive-data discovery** (statistical sampling across *all* buckets, low cost, gives coverage/risk overview) and **targeted classification jobs** (deep scan of specific buckets/objects you choose, gives object-level findings).

## The Two Finding Categories

| Category | Answers | Example |
|----------|---------|---------|
| **Sensitive data findings** | *What* sensitive data is in an object | `SensitiveData:S3Object/Personal`, `.../Credentials`, `.../Financial` |
| **Policy findings** | *Is the bucket configured/exposed in a risky way* | `Policy:IAMUser/S3BucketPublic`, `.../S3BucketSharedExternally`, `.../S3BucketEncryptionDisabled` |

> Policy findings overlap conceptually with GuardDuty's `Policy:S3/BucketAnonymousAccessGranted` and Config's `s3-bucket-public-read-prohibited` — three services flagging the same misconfiguration from different angles. Sensitive data findings are Macie's **unique** contribution: nothing else in AWS tells you *what's in the object*.

## Anatomy of a Finding

| Part | Field | Answers |
|------|-------|---------|
| **What** | `type` | The finding pattern (e.g. `SensitiveData:S3Object/Personal`) |
| **How bad** | `severity` | Low / Medium / High |
| **Where** | `resourcesAffected.s3Bucket` / `.s3Object` | The bucket + object key |
| **What kind of data** | `classificationDetails.result.sensitiveData[].category` + `detections[]` | PII type, credential pattern, financial data — with counts, not raw values |
| **Who can reach it** | `classificationDetails.result.sensitiveData` alongside bucket public/shared state | Ties exposure to content |
| **When** | `createdAt` / `updatedAt` | First and latest observation |

🔴 Macie reports **occurrence counts and sample cell/line locations**, not the raw sensitive values themselves — findings tell you *that* 40 rows matched an SSN pattern, not the 40 SSNs. Pull the object from S3 (with proper authorization/legal handling) if you need the actual content.

## Finding Types Worth Knowing

| Finding type | Means |
|--------------|-------|
| `SensitiveData:S3Object/Personal` | PII detected (names, addresses, SSNs, etc.) |
| `SensitiveData:S3Object/Credentials` | 🔴 AWS keys, private keys, passwords found in an object |
| `SensitiveData:S3Object/Financial` | Credit card numbers, bank account/routing numbers |
| `SensitiveData:S3Object/CustomIdentifier` | Matched a custom identifier you configured (internal ID formats, etc.) |
| `SensitiveData:S3Object/Multiple` | More than one category matched |
| `Policy:IAMUser/S3BucketPublic` | 🔴 Bucket is publicly accessible |
| `Policy:IAMUser/S3BucketSharedExternally` | Bucket shared with an account outside your org |
| `Policy:IAMUser/S3BucketReplicatedExternally` | 🔴 Replication rule sends objects to an external account |
| `Policy:IAMUser/S3BucketEncryptionDisabled` | Bucket lacks default encryption |
| `Policy:IAMUser/S3BlockPublicAccessDisabled` | Account/bucket-level Block Public Access turned off |

## How to Identify Macie in Evidence

- **`eventSource`:** `macie2.amazonaws.com` (admin/config actions).
- **Finding IDs:** UUID; findings are scoped per-account, per-region.
- **ARNs:** classification jobs — `arn:aws:macie2:<region>:<acct>:classification-job/<job-id>`.
- Findings arrive via **EventBridge** (`source: aws.macie`, `detail-type: Macie Finding`) and can be forwarded to **Security Hub** — that's how they wire into automation and SecOps.

## Common Operations You Will See

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `EnableMacie` / `DisableMacie` | Turn Macie on/off for the account | 🔴 `DisableMacie` = blinding |
| `CreateClassificationJob` | Start a scan of chosen buckets/prefixes | Config |
| `UpdateClassificationJob` (pause/cancel) | Stop a running job | 🔴 mid-job cancellation |
| `CreateFindingsFilter` | Auto-archive matching findings | 🔴 attacker suppressing findings about their own access |
| `ArchiveFindings` / `UpdateFindingsFeedback` | Mark findings archived/useful | 🔴 mass-archiving |
| `DisassociateMember` / `DeleteMember` | Remove accounts from org Macie | 🔴 dropping coverage |
| `ListFindings` / `GetFindings` | Read findings | Normal analyst use |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| **Macie** | Microsoft Purview (Data Map / sensitivity labels) | Sensitive Data Protection (formerly Cloud DLP) |
| Sensitive data finding | Purview sensitivity label match | DLP inspection finding |
| Classification job | Purview scan | DLP job |

## Common Use Cases

Your "normal":

- **Data-risk visibility** — know which buckets actually hold PII/secrets before an incident, not after.
- **Compliance evidence** — demonstrate where regulated data lives (GDPR, PCI, HIPAA scoping).
- **Post-exposure confirmation** — after a bucket goes public, prove *what* was actually exposed, not just *that* it was.
- **Automated response** — high-severity finding → EventBridge → Lambda to quarantine the object or bucket.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Finding** | A raised detection — sensitive-data or policy |
| **Sensitive data finding** | An object matched a data category (PII/credentials/financial/custom) |
| **Policy finding** | A bucket-level misconfiguration (public, shared externally, unencrypted) |
| **Classification job** | A one-time or scheduled scan of specific buckets/prefixes |
| **Automated discovery** | Continuous, low-cost statistical sampling across all buckets for a risk overview |
| **Custom identifier** | A regex you define to match org-specific sensitive patterns |
| **Allow list** | Values excluded from matching (known-safe strings) |
| **Sensitivity score** | Per-bucket score summarizing findable risk |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating Macie findings in a case | **Macie → Macie for DFIR** |
| The bucket/object evidence Macie is scanning | **AWS → Storage → S3** |
| Working an exposed-bucket incident end to end | **AWS → Storage → S3 → Playbooks → Exposed S3 Bucket** |
| Aggregating findings across tools | **AWS → Security & Detection → Security Hub** |
| The API actions behind bucket changes | **AWS → Logging & Monitoring → CloudTrail** |

## Resources

- What is Macie — https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html
- Finding types — https://docs.aws.amazon.com/macie/latest/user/findings-types.html
- Finding format — https://docs.aws.amazon.com/macie/latest/user/findings-managed-data-identifiers.html
