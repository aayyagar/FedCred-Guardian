# Changelog

## 1.0.0 - 2026-10-28

- First release.
- Scans Entra ID app registrations, Azure user-assigned managed identities and AWS IAM role trust policies for GitHub Actions OIDC trust.
- 16 checks, including detection of the withdrawn hyphen-delimited immutable subject format.
- GitHub lookups to resolve owner and repository IDs and detect renamed, deleted and missing repositories.
- Migration runbooks with copy-ready Azure CLI and AWS CLI commands.
- HTML, JSON, CSV and Markdown output; `-FailOn` exit codes for CI.
