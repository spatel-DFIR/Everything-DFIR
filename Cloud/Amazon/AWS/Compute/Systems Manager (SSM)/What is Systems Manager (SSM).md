# What is Systems Manager (SSM)

**AWS Systems Manager (SSM)** is AWS's built-in way to **run commands and open shells on your EC2 instances without SSH, RDP, or an open inbound port** — plus store config/secrets and automate fleet operations. If an attacker holds the right IAM permissions, it is also the cleanest way to get **root/SYSTEM code execution on every managed instance in the account** — straight through the AWS API, invisible to your network controls.

You will meet SSM on a case when: a host is compromised but there's *no* SSH login to explain it; a cost/CPU spike traces back to a command that "came from nowhere"; or an EC2 role turns out to have `ssm:SendCommand`.

## Contents

- [How It Works](#how-it-works)
- [The Capabilities That Matter to IR](#the-capabilities-that-matter-to-ir)
- [Why SSM Is a First-Class Attacker Tool](#why-ssm-is-a-first-class-attacker-tool)
- [How to Identify It](#how-to-identify-it)
- [Common Operations](#common-operations)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

Three pieces make SSM work — and each one is an investigative fact:

| Piece | What it is | Why the analyst cares |
|-------|-----------|-----------------------|
| **SSM Agent** | A daemon (`amazon-ssm-agent`) pre-installed on Amazon Linux, Ubuntu, and Windows AMIs. Runs as **root / SYSTEM**. | Anything SSM runs, runs with the **agent's** privilege — i.e. full admin on the box. It polls AWS *outbound*; no inbound port is opened. |
| **Instance IAM role** | The instance profile must carry `AmazonSSMManagedInstanceCore` (or equivalent). | Only instances with this role show up as **"Managed."** An instance's *own* role is what SSM authenticates as — see IMDS. |
| **SSM documents (SSM docs)** | JSON/YAML playbooks describing *what* to run (`AWS-RunShellScript`, `AWS-RunPowerShellScript`, custom docs, Automation runbooks). | The document + its parameters **are the payload.** Reading them tells you exactly what executed. |

The flow: a caller invokes an **SSM API** (`SendCommand`, `StartSession`, …) → the SSM service tells the target's agent → the **agent executes locally as root/SYSTEM** → results return through AWS. The instance never accepts an inbound connection; the traffic is the agent's normal outbound HTTPS to `ssm.<region>.amazonaws.com`.

> 🔴 **The security consequence in one line:** on a managed instance, `ssm:SendCommand` ≈ *unauthenticated root shell for anyone who can call the API* — and it leaves **no SSH log, no new open port, no VPC ingress**. Network-based controls (security groups, NACLs, bastions) do not see it.

## The Capabilities That Matter to IR

| Capability | What it does | API you'll see | DFIR angle |
|-----------|-------------|----------------|-----------|
| **Run Command** | Fire a command/script at one or many instances | `SendCommand`, `GetCommandInvocation` | 🔴 Mass RCE as root. Command text is in `SendCommand` request params. |
| **Session Manager** | Interactive browser/CLI shell to an instance | `StartSession`, `TerminateSession`, `ResumeSession` | 🔴 SSH-less shell. Keystrokes **not** logged unless session logging is on. |
| **Parameter Store** | Config + secrets store (`SecureString` = KMS-encrypted) | `GetParameter(s)`, `GetParametersByPath`, `PutParameter` | 🔴 Secrets live here. `GetParametersByPath --with-decryption` = bulk secret theft. |
| **Automation** | Multi-step runbooks across services (an SSM doc of type `Automation`) | `StartAutomationExecution` | 🔴 Can chain privileged actions; runs under a passed role → privesc/lateral. |
| **State Manager** | Applies a document to instances **on a schedule** | `CreateAssociation`, `UpdateAssociation` | 🔴 **Persistence** — a scheduled association re-runs attacker code even after cleanup. |
| **Patch Manager / Inventory / Fleet Manager** | Patch, inventory, and file/registry browse instances | `DescribeInstanceInformation`, Fleet Manager APIs | Recon — `DescribeInstanceInformation` enumerates every reachable box. |

## Why SSM Is a First-Class Attacker Tool

Put the pieces together and you see why SSM shows up in real intrusions:

1. **It bypasses the network story.** No inbound port, no security-group change, no bastion hop. Your VPC Flow Logs and SSH logs stay clean while an attacker owns the fleet.
2. **It runs as root/SYSTEM.** The agent is privileged, so Run Command and Session Manager don't need a local exploit.
3. **It scales in one call.** `SendCommand --targets Key=tag:Env,Values=prod` hits *every* prod instance at once — one API call, whole-fleet RCE.
4. **The credential is often already there.** Any principal with `ssm:SendCommand` + `ssm:StartSession` can use it; and an attacker who compromised one instance can read that instance's role from **IMDS** and, if it has SSM rights, pivot to others.
5. **It doubles as persistence.** A **State Manager association** or a malicious **SSM document** re-executes on a schedule.

> This is exactly the AWS-native equivalent of Azure **Run Command / Custom Script Extension** abuse — see the cross-provider table and the SSM playbook.

## How to Identify It

Recognize SSM objects in logs and console:

| Thing | Shape / example |
|------|-----------------|
| **Managed instance ID** | `i-0abc123…` (EC2) or `mi-0abc123…` (hybrid/on-prem activation) |
| **SSM document ARN** | `arn:aws:ssm:us-east-1:123456789012:document/My-Doc` |
| **Built-in command docs** | `AWS-RunShellScript`, `AWS-RunPowerShellScript`, `AWS-RunAnsiblePlaybook` |
| **Session document** | `SSM-SessionManagerRunShell` (default interactive shell) |
| **Parameter name** | `/app/prod/db-password` (a path); `SecureString` type = KMS-encrypted |
| **Command invocation ID** | a GUID tying a `SendCommand` to its per-instance results |
| **Agent process on host** | `amazon-ssm-agent` (Linux) / `AmazonSSMAgent` service (Windows), running as root/SYSTEM |

## Common Operations

🔴 = high-value on a case. **W** = write/mutating, **R** = read.

| Operation | R/W | What it does | Flag |
|-----------|-----|--------------|------|
| `SendCommand` | W | Run a command/script on target instances | 🔴 root RCE; read the `parameters.commands` |
| `StartSession` | W | Open an interactive shell to an instance | 🔴 SSH-less shell; who/when/which instance |
| `GetParameter` / `GetParameters` | R | Read a Parameter Store value | 🔴 with `--with-decryption` on a `SecureString` |
| `GetParametersByPath` | R | Read *every* parameter under a path | 🔴 bulk secret harvest |
| `PutParameter` | W | Create/overwrite a parameter | Tampering / planting |
| `StartAutomationExecution` | W | Run an Automation runbook | 🔴 privesc/lateral via passed role |
| `CreateAssociation` / `UpdateAssociation` | W | Schedule a doc to run on instances | 🔴 persistence |
| `CreateDocument` / `UpdateDocument` | W | Define/modify an SSM document | 🔴 malicious payload doc |
| `ModifyDocumentPermission` | W | Share a document with another account / public | 🔴 exfil of a doc, or cross-account abuse |
| `DescribeInstanceInformation` | R | List all managed instances | Recon / target enumeration |
| `GetCommandInvocation` | R | Read a command's result | Attacker checking output |
| `TerminateSession` | W | Close a session | Anti-forensics / normal cleanup |

## Cross-Provider Equivalent

| Capability | AWS | Azure | Google Cloud |
|-----------|-----|-------|--------------|
| Run a command on a VM | **SSM Run Command** (`SendCommand`) | **Run Command** / **Custom Script Extension** | `gcloud compute ssh` + **startup/metadata scripts**, **OS patch** |
| SSH-less interactive shell | **SSM Session Manager** (`StartSession`) | **Bastion** / **Serial Console** | **IAP TCP forwarding** |
| Agent on the box | **SSM Agent** (root/SYSTEM) | **Azure VM Guest Agent** (WAAgent) | **Guest Agent / OS Config agent** |
| Config & secret store | **Parameter Store** | **App Configuration** / **Key Vault** | **Secret Manager** / runtime config |
| Multi-step automation | **SSM Automation** | **Azure Automation** runbooks | **Workflows** / Cloud Functions |
| Scheduled config enforcement | **State Manager** | **Guest Configuration** / DSC | **OS Config** |

> The Azure twin is the closest: SSM **Run Command** abuse reads almost identically to Azure **Run Command Abuse** — API-driven, root-level, network-invisible code execution on a VM. See the Azure note of the same name.

## Common Use Cases

Knowing *normal* is how you spot *abnormal*:

- **Patching & config at scale** — Patch Manager and State Manager keep fleets compliant (frequent, scheduled, from AWS service principals or a known automation role).
- **Break-glass / SSH-less admin** — Session Manager is the modern replacement for bastions and key-based SSH; many orgs disable SSH entirely and route all shell access through it (so *legitimate* interactive access is `StartSession`, not port 22).
- **Secrets/config for apps** — Parameter Store holds DB strings, feature flags, and `SecureString` secrets that apps fetch at boot.
- **Runbooks / remediation** — Automation documents standardize actions (create AMI, restart service, isolate host).

> Because legit admin *also* uses Session Manager and Run Command, the question is never "did SSM run?" but **"which identity ran it, against which instances, with what command, from where — and does that match a known change?"**

## Key Terminology

| Term | Meaning |
|------|---------|
| **SSM Agent** | The on-instance daemon that executes SSM work as root/SYSTEM |
| **Managed instance** | An instance (or hybrid `mi-` node) reachable by SSM via its IAM role |
| **SSM document (doc)** | JSON/YAML defining what to run: `Command`, `Session`, or `Automation` type |
| **Run Command** | One-shot command execution against targets (`SendCommand`) |
| **Session Manager** | Interactive shell over the SSM channel (`StartSession`) |
| **Parameter Store** | Hierarchical config/secret store; `SecureString` = KMS-encrypted |
| **Automation** | Runbook-style multi-step orchestration |
| **State Manager association** | A doc bound to instances that runs on a schedule (persistence-capable) |
| **Instance profile** | The IAM role attached to the instance; SSM authenticates as it |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The instances SSM runs on, and IMDS/role theft | **AWS → Compute → EC2** · **Playbooks → IMDS SSRF to Role Theft** |
| The IAM role SSM authenticates as, and `ssm:*` permissions | **AWS → Identity & Access → IAM** |
| Reading `SendCommand`/`StartSession` events + the abuse chain | **Systems Manager (SSM) for DFIR** · **Playbooks → SSM Run Command and Session Abuse** |
| Where SSM secrets are (SecureString → KMS) | **AWS → Data Protection → KMS** · **Secrets Manager** |
| The audit log that records every SSM API call | **AWS → Logging & Monitoring → CloudTrail** |
| The same technique in Azure | **Azure → Virtual Machines → Run Command Abuse** |

## Resources

- What is AWS Systems Manager — https://docs.aws.amazon.com/systems-manager/latest/userguide/what-is-systems-manager.html
- Run Command — https://docs.aws.amazon.com/systems-manager/latest/userguide/run-command.html
- Session Manager — https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html
- Parameter Store — https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html
- SSM documents — https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-ssm-docs.html
- Logging Session Manager activity — https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-logging.html
