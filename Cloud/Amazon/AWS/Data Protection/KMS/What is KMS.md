# What is KMS

**AWS Key Management Service (KMS)** is the vault that holds the **encryption keys** protecting almost everything else — S3 objects, EBS volumes, RDS databases, Secrets Manager secrets, Parameter Store `SecureString`s, and more. The keys never leave KMS in plaintext; services ask KMS to encrypt/decrypt on their behalf.

Why an analyst cares: **whoever controls the key controls the data.** Delete or disable a key and every byte encrypted under it becomes unrecoverable (ransomware / destruction). Add an outside account to a key policy and that account can now decrypt your data (theft). KMS is small, quiet, and catastrophic when abused.

## Contents

- [How It Works](#how-it-works)
- [Envelope Encryption in One Picture](#envelope-encryption-in-one-picture)
- [How Access Is Decided — Key Policy First](#how-access-is-decided--key-policy-first)
- [How to Identify It](#how-to-identify-it)
- [Common Operations](#common-operations)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

| Concept | What it is | Why the analyst cares |
|---------|-----------|-----------------------|
| **KMS key** | A logical key living inside KMS (symmetric AES-256 by default; also asymmetric RSA/ECC and HMAC). The raw material **never leaves KMS**. | You can't "steal the key file." Abuse is via *API calls* — `Decrypt`, policy changes, deletion — all logged. |
| **AWS-managed vs customer-managed** | `aws/<service>` keys AWS makes for you vs **customer-managed keys (CMKs)** you create and control | You can only change policy/rotation on **customer-managed** keys; those are where misconfig lives. |
| **Key policy** | A **resource policy** attached to the key — the *primary* access control | Unlike most services, IAM alone isn't enough: the **key policy must grant access**. This is the #1 KMS gotcha. |
| **Grant** | A separate, often temporary, delegation of key permissions | 🔴 A stealthy way to hand an attacker decrypt rights without editing the policy. |
| **Alias** | A friendly name (`alias/prod-db`) pointing at a key | Logs may show the alias or the key ID — map both. |
| **Encryption context** | Extra key–value data bound to an operation (AAD) | Appears in CloudTrail → tells you **which resource** used the key. A gift for forensics. |

Services use KMS through **envelope encryption**: KMS doesn't encrypt your gigabytes directly — it encrypts a small **data key**, which encrypts the data.

## Envelope Encryption in One Picture

```
KMS key (stays in KMS)
   │  GenerateDataKey
   ▼
Data key ──encrypts──► your data (S3 object / EBS volume / secret)
   │
   └─ stored ALONGSIDE the data, itself encrypted by the KMS key

To read the data:  service sends the encrypted data key to KMS → Decrypt → plaintext data key → decrypt data
```

> 🔴 **Consequence:** to read the data you must call KMS `Decrypt`/`GenerateDataKey`, and **that call is in CloudTrail**. If the KMS key is **disabled or deleted**, the encrypted data keys can never be unwrapped → the data is gone. That single fact is why key operations are a data-destruction weapon.

## How Access Is Decided — Key Policy First

This trips up even seniors, so make it explicit:

| Layer | Role |
|-------|------|
| **Key policy** (on the key) | The root of trust. It must either grant the principal directly **or** contain the statement that *lets IAM policies apply* (`"Principal": {"AWS": "arn:aws:iam::<acct>:root"}` + `kms:*`). |
| **IAM policy** (on the principal) | Only effective **if** the key policy delegates to IAM. |
| **Grants** | Temporary, fine-grained permissions layered on top — common for service integrations. |

> 🔴 **Two abuse paths follow directly:** (1) `PutKeyPolicy` adding an **external account** as a principal = cross-account decrypt (data theft); (2) `CreateGrant` to an attacker principal = quiet decrypt access that a policy review might miss.

## How to Identify It

| Thing | Shape / example |
|------|-----------------|
| **Key ID** | `1234abcd-12ab-34cd-56ef-1234567890ab` (a UUID) |
| **Key ARN** | `arn:aws:kms:us-east-1:123456789012:key/1234abcd-…` |
| **Alias** | `alias/prod-db-key` |
| **Alias ARN** | `arn:aws:kms:us-east-1:123456789012:alias/prod-db-key` |
| **Grant ID** | a long token returned by `CreateGrant` |
| **Encryption context** | e.g. `{"aws:s3:arn":"arn:aws:s3:::bucket/key"}` in a `Decrypt` request |
| **Key material origin** | `AWS_KMS` (default) · `EXTERNAL` (BYOK/imported) · `AWS_CLOUDHSM` · `EXTERNAL_KEY_STORE` (XKS) |

## Common Operations

🔴 = high-value on a case. **W** = write/mutating, **R/U** = read/use.

| Operation | R/W | What it does | Flag |
|-----------|-----|--------------|------|
| `ScheduleKeyDeletion` | W | Queues a key for deletion (7–30 day wait) | 🔴 **Data destruction** — everything under it becomes unrecoverable |
| `DisableKey` | W | Makes a key temporarily unusable | 🔴 Instant "ransomware" — data unreadable until re-enabled |
| `PutKeyPolicy` | W | Rewrites the key's resource policy | 🔴 Add external account → cross-account decrypt |
| `CreateGrant` | W | Delegates key use to a principal | 🔴 Stealthy decrypt access |
| `Decrypt` | U | Decrypts ciphertext / a data key | 🔴 Actual data access — check `encryptionContext` |
| `GenerateDataKey` | U | Mints a data key (bulk encrypt) | Normal for services; 🔴 in odd hands = encrypting your data |
| `ReEncrypt` | U | Re-wraps ciphertext under another key | 🔴 Re-encrypt-to-attacker-key (ransomware pattern) |
| `Encrypt` | U | Encrypts small plaintext | Context matters |
| `DisableKeyRotation` | W | Turns off annual rotation | Weakening |
| `ImportKeyMaterial` | W | Loads external key material (BYOK) | 🔴 Unusual origin |
| `CancelKeyDeletion` / `EnableKey` | W | Reverses destruction | Recovery — or attacker restoring access |
| `CreateKey` / `CreateAlias` | W | New key/alias | Attacker's own key for re-encryption |

> **Unusual and useful:** KMS logs its *use* operations (`Decrypt`, `GenerateDataKey`, `Encrypt`) to CloudTrail **by default** — you rarely get data-plane visibility this cheaply elsewhere. Every decrypt of your crown-jewel data is recorded.

## Cross-Provider Equivalent

| Concept | AWS | Azure | Google Cloud |
|---------|-----|-------|--------------|
| Managed key service | **KMS** | **Key Vault (keys)** / **Managed HSM** | **Cloud KMS** |
| The key object | **KMS key (CMK)** | **Key** | **CryptoKey** (in a keyring) |
| Access control on the key | **Key policy** (+ IAM + grants) | **Access policy / Azure RBAC** | **IAM on the key/keyring** |
| Destroy a key | **`ScheduleKeyDeletion`** | soft-delete + purge | `destroyCryptoKeyVersion` |
| Envelope data key | **`GenerateDataKey`** | wrap/unwrap key | `GenerateDataKey` equivalent |
| Secret store (not keys) | **Secrets Manager** / SSM Parameter Store | **Key Vault (secrets)** | **Secret Manager** |

## Common Use Cases

- **Encrypting storage** — S3 (SSE-KMS), EBS volumes, RDS/Aurora, DynamoDB, EFS all use KMS keys.
- **Protecting secrets** — Secrets Manager and SSM `SecureString` wrap their secrets with KMS.
- **Application-level crypto** — apps call `Encrypt`/`Decrypt`/`GenerateDataKey` for field-level protection.
- **Compliance/BYOK** — imported or CloudHSM-backed keys satisfy "we hold the key material" requirements.

> "Normal" is a small set of **service principals and app roles** calling `GenerateDataKey`/`Decrypt` against specific keys, with consistent `encryptionContext`. A human principal calling `ScheduleKeyDeletion`, `PutKeyPolicy`, or `Decrypt` on a key it never touches before is the anomaly.

## Key Terminology

| Term | Meaning |
|------|---------|
| **KMS key / CMK** | The managed key; customer-managed ones are the ones you control |
| **Data key** | A key KMS generates to encrypt data (envelope encryption) |
| **Key policy** | The resource policy on a key — primary access control |
| **Grant** | A delegated, often temporary, key permission |
| **Alias** | A friendly pointer to a key ID |
| **Encryption context** | Bound key–value AAD, visible in CloudTrail |
| **Envelope encryption** | KMS encrypts a data key; the data key encrypts the data |
| **Key material origin** | Where the raw key came from (AWS/external/HSM/XKS) |
| **Pending deletion** | A key scheduled for deletion during its waiting period |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Reading KMS events + the destruction/theft patterns | **KMS for DFIR** |
| The secrets KMS protects | **AWS → Data Protection → Secrets Manager** · **SSM Parameter Store** |
| Data made unrecoverable / ransom | **AWS → Playbooks → Ransomware and Data Destruction** |
| Encrypted storage that depends on KMS | **AWS → Storage → S3 / EBS** · **Databases → RDS** |
| The audit log recording every KMS call | **AWS → Logging & Monitoring → CloudTrail** |
| Who the calling principals are | **AWS → 01 IAM & Identities** |
| The same service in Azure/GCP | **Azure → Key Vault** · **Cloud → 06 Service Equivalents** |

## Resources

- What is AWS KMS — https://docs.aws.amazon.com/kms/latest/developerguide/overview.html
- Key policies — https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
- Grants in KMS — https://docs.aws.amazon.com/kms/latest/developerguide/grants.html
- Deleting KMS keys — https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html
- Encryption context — https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context
- Logging KMS API calls with CloudTrail — https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html
