# FedCred Guardian

**A read-only audit of secret-free CI/CD access.** FedCred Guardian finds every place where Microsoft Entra ID, Azure managed identities and AWS IAM trust GitHub Actions. It flags the trusts that can be hijacked, then writes the migration runbook to GitHub's new immutable subject format.

[**View the sample report**](https://aayyagar.github.io/fedcred-guardian/sample-report/) · PowerShell 7 · MIT license · v1.0.0

```text
PS> .\Invoke-FedCredGuardian.ps1 -Demo

  Found 16 GitHub-trusting credentials. Evaluating...

  Score: 66/100  (Grade D)   Ready: 3/16
  Critical 4  High 4  Medium 13  Low 7
  Migrate 7  Restrict 4  Delete 2
```

---

## Why this exists

GitHub Actions can sign in to Azure and AWS without stored secrets. The workflow presents a short-lived OIDC token, and the cloud checks its `sub` claim against a federated credential or an IAM trust policy. That removes long-lived secrets, but the trust is only as good as the subject it matches.

Most subjects identify the repository **by name**:

```text
repo:contoso/payments-api:ref:refs/heads/main
```

Names can be reused. When a repository is renamed, transferred or deleted, or its owner account disappears, someone else can create a repository with the old name. Its tokens then match your credential. This is called **subject recycling**.

In 2026 GitHub introduced **immutable subjects**, which embed the numeric owner and repository IDs:

```text
repo:contoso@5544123/payments-api@821093847:ref:refs/heads/main
```

- Since **July 15, 2026**, GitHub uses the new format automatically for repositories that are created, renamed or transferred. Existing repositories keep the old format until someone opts in.
- Microsoft asks admins to migrate GitHub Actions federated credentials to immutable subjects ([Microsoft Learn](https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-github-immutable-subjects), message center MC1447671).
- The first version of the format used `-` as the delimiter. Hyphens are legal in names, so an attacker could register an owner called `contoso-5544123` and produce an identical subject ([Boost Security, "Sleeper Squats"](https://labs.boostsecurity.io/articles/sleeper-squats-github-oidc-immutable-subject-claim)). GitHub switched to `@`. Any trust policy copied during that window is still exploitable.

Doing this by hand means opening every app registration, every managed identity in every subscription and every IAM role in every account. FedCred Guardian does the inventory, the risk analysis and the runbook in one pass.

## What it checks

| ID | Severity | Check |
|---|---|---|
| FCG-01 | Critical | AWS role trusts GitHub OIDC with **no subject condition**: any repository on GitHub can assume it |
| FCG-02 | Critical | Subject wildcard matches **any GitHub owner** (`repo:*`, `repo:*/*`) |
| FCG-03 | Critical | **Withdrawn hyphen-delimited** immutable subject (`owner-123/repo-456`), confirmed against the real owner ID |
| FCG-04 | Critical | Trusted **owner account no longer exists**, so anyone can register the name |
| FCG-05 | High | Wildcard trusts **every repository of an owner** (`repo:contoso/*`) |
| FCG-06 | High | Repository was **renamed or transferred**, and the subject still names the old repo |
| FCG-07 | High | Repository in the subject **was not found** |
| FCG-08 | Medium | **Name-based (mutable)** subject, which needs migrating |
| FCG-09 | Medium | Wildcard trusts **every branch, tag or environment** |
| FCG-10 | Medium | AWS **audience** condition missing or not `sts.amazonaws.com` |
| FCG-11 | Medium | Flexible credential does not check **`repository_id`** |
| FCG-12 | Low | Bound to a branch or tag instead of a **protected environment** |
| FCG-13 | Low | Trusts **`pull_request`** workflows |
| FCG-14 | Low | Immutable credential is **orphaned** (repository ID no longer exists) |
| FCG-15 | Low | Non-standard Entra **audience** |
| FCG-16 | Info | **Custom subject template**, flagged for manual review |

Every credential gets a 0–100 score, and the report shows the average. Each credential also gets one action:

- **Ready:** already immutable and safe.
- **Migrate:** move it to an immutable subject. You get the new subject string and copy-ready commands: create the new credential alongside the old one, opt the repository in, validate, then remove the old one.
- **Restrict:** replace a wildcard or missing condition with exact repositories.
- **Delete:** the trusted repository or owner is gone, so the credential only creates risk.

## Quick start

```powershell
git clone https://github.com/aayyagar/fedcred-guardian.git
cd fedcred-guardian
.\Invoke-FedCredGuardian.ps1 -Demo
```

Demo mode uses a fictional Contoso tenant and AWS account (`demo/sample-environment.json`). It needs no modules and makes no connections. Open `FedCredGuardian_<timestamp>/index.html` to see the report.

## Scanning your environment

```powershell
# Entra ID app registrations
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Connect-MgGraph -Scopes Application.Read.All

# Azure user-assigned managed identities
Install-Module Az.Accounts -Scope CurrentUser
Connect-AzAccount

# AWS: uses the AWS CLI v2 and your current credentials or -AwsProfile

$env:GITHUB_TOKEN = '<read-only token>'   # optional, see below
.\Invoke-FedCredGuardian.ps1 -Source Entra,ManagedIdentity,AWS
```

| Platform | Minimum access |
|---|---|
| Entra ID | `Application.Read.All` (delegated). Global Reader works. |
| Azure | `Reader` on the subscriptions to scan |
| AWS | `iam:ListRoles`, `sts:GetCallerIdentity` (for example `SecurityAudit`) |
| GitHub | Optional token. A fine-grained token with no permissions is enough for public repositories; add read-only `Metadata` access for private ones. Without a token the tool uses the public API (60 requests per hour) and can't see private repositories. |

GitHub lookups resolve the real owner and repository IDs for the migration commands. They also detect renamed, deleted and missing repositories. Use `-SkipGitHubLookup` to work fully offline; commands will then contain `<OWNER_ID>` and `<REPO_ID>` placeholders.

### Options

| Parameter | Purpose |
|---|---|
| `-Demo` | Run against the bundled sample environment |
| `-Source` | `Entra`, `ManagedIdentity`, `AWS` (default: all) |
| `-SubscriptionId` | Limit the managed identity scan to specific subscriptions |
| `-AwsProfile` | AWS CLI profile |
| `-GitHubToken` | Token for GitHub lookups (default `$env:GITHUB_TOKEN`) |
| `-SkipGitHubLookup` | No GitHub API calls |
| `-InputPath` | Analyse an offline snapshot in the demo file's format |
| `-OutputPath` | Report folder (default `.\FedCredGuardian_<timestamp>`) |
| `-Format` | `Html`, `Json`, `Csv`, `Markdown` (default: all) |
| `-FailOn` | Exit code 1 if a finding at or above `Critical`/`High`/`Medium`/`Low` exists |

## Output

| File | Contents |
|---|---|
| `index.html` | Interactive report: score, severity filters, search, and a runbook per credential with copy buttons. Works offline and in light or dark mode. |
| `migration-plan.md` | The full runbook as Markdown, ready to paste into a change request |
| `fedcred-report.json` | Everything, for automation |
| `fedcred-findings.csv` | One row per finding, for tickets and spreadsheets |

## Run it on a schedule

```yaml
# .github/workflows/fedcred-audit.yml (excerpt)
- name: Audit federated credentials
  shell: pwsh
  run: ./Invoke-FedCredGuardian.ps1 -Source AWS -FailOn High
```

The non-zero exit code fails the job when a high or critical trust appears, so a new wildcard role is caught the day it is created.

## Safe by design

- **Read-only.** Microsoft Graph and Azure Resource Manager calls are all `GET`. AWS calls are `iam:ListRoles` and `sts:GetCallerIdentity`. GitHub calls read public metadata.
- **Nothing is changed for you.** The migration commands are printed for you to review and run through your normal change process.
- **Old and new side by side.** Every migration creates the immutable credential first and removes the old one only after you validate, so pipelines keep working throughout.
- **No secrets are stored.** Tokens come from your existing sign-in sessions and are never written to the report.

## Project layout

```text
Invoke-FedCredGuardian.ps1     the tool (single file, dot-sourceable)
report/template.html           report template
demo/sample-environment.json   fictional Contoso environment
tests/                         Pester 5 tests
sample-report/                 the published sample report
```

Run the tests with `Invoke-Pester ./tests`.

## Roadmap

- GitHub Enterprise Cloud with data residency (`*.ghe.com` issuers)
- Google Cloud workload identity pool providers
- An optional `-Apply` mode that runs the migration with `-WhatIf` confirmation

## References

- Microsoft Learn: [Migrate GitHub Actions federated credentials to immutable subjects](https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-github-immutable-subjects)
- GitHub Changelog: [Immutable subject claims for GitHub Actions OIDC tokens](https://github.blog/changelog/2026-04-23-immutable-subject-claims-for-github-actions-oidc-tokens)
- Boost Security Labs: [Sleeper Squats: How a Hyphen (Almost) Unraveled GitHub's Immutable OIDC Subject Claim](https://labs.boostsecurity.io/articles/sleeper-squats-github-oidc-immutable-subject-claim)

## License

MIT © 2026 Akhilesh Ayyagari
