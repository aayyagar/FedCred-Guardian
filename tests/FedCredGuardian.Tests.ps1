#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
# Run: Invoke-Pester ./tests

BeforeAll {
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-FedCredGuardian.ps1')

    function New-TestCred {
        param([string]$Subject, [string]$Platform = 'Entra app', [string]$Operator = 'equals', $Audiences = @('api://AzureADTokenExchange'), [string]$Expr)
        New-FcgCredential -Platform $Platform -ResourceName 'test' -ResourceId '/subscriptions/s/resourceGroups/rg/providers/x/y/test' `
            -Location 'test' -CredentialName 'cred' -CredentialId 'id1' -Issuer 'https://token.actions.githubusercontent.com' `
            -Subject $Subject -Operator $Operator -Audiences $Audiences -ClaimsExpression $Expr
    }
    function Get-Ids { param($Result) @($Result.Findings | ForEach-Object CheckId) }
}

Describe 'ConvertFrom-GitHubSubject' {
    It 'parses a name-based branch subject' {
        $p = ConvertFrom-GitHubSubject 'repo:contoso/payments-api:ref:refs/heads/main'
        $p.Format | Should -Be 'Name'
        $p.Owner | Should -Be 'contoso'
        $p.Repo | Should -Be 'payments-api'
        $p.Context | Should -Be 'branch'
        $p.ContextValue | Should -Be 'main'
    }
    It 'parses an immutable environment subject' {
        $p = ConvertFrom-GitHubSubject 'repo:contoso@5544123/payments-api@821093847:environment:prod'
        $p.Format | Should -Be 'Immutable'
        $p.OwnerId | Should -Be '5544123'
        $p.RepoId | Should -Be '821093847'
        $p.Context | Should -Be 'environment'
    }
    It 'recognises the withdrawn hyphen format' {
        $p = ConvertFrom-GitHubSubject 'repo:contoso-5544123/payments-api-821093847:ref:refs/heads/main'
        $p.Format | Should -Be 'ImmutableHyphen'
        $p.Owner | Should -Be 'contoso'
        $p.RepoId | Should -Be '821093847'
    }
    It 'does not mistake short numeric suffixes for the hyphen format' {
        (ConvertFrom-GitHubSubject 'repo:team-2/app-1:ref:refs/heads/main').Format | Should -Be 'Name'
    }
    It 'treats * literally when wildcards are not allowed (Entra exact match, AWS StringEquals)' {
        (ConvertFrom-GitHubSubject 'repo:contoso/*').WildcardScope | Should -Be 'None'
    }
    It 'classifies wildcard scopes' {
        (ConvertFrom-GitHubSubject 'repo:*/*' -AllowWildcards).WildcardScope | Should -Be 'AnyOwner'
        (ConvertFrom-GitHubSubject 'repo:*' -AllowWildcards).WildcardScope | Should -Be 'AnyOwner'
        (ConvertFrom-GitHubSubject 'repo:contoso/*' -AllowWildcards).WildcardScope | Should -Be 'AnyRepo'
        (ConvertFrom-GitHubSubject 'repo:contoso/app:*' -AllowWildcards).WildcardScope | Should -Be 'AnyContext'
        (ConvertFrom-GitHubSubject 'repo:contoso/app:ref:refs/heads/main' -AllowWildcards).WildcardScope | Should -Be 'None'
    }
    It 'flags custom subject templates' {
        (ConvertFrom-GitHubSubject 'job_workflow_ref:contoso/wf/.github/workflows/d.yml@refs/heads/main').Kind | Should -Be 'Custom'
    }
    It 'handles a missing subject' {
        (ConvertFrom-GitHubSubject $null).Kind | Should -Be 'Missing'
    }
}

Describe 'Get-SubFromClaimsExpression' {
    It 'extracts the sub pattern and repository_id check' {
        $x = Get-SubFromClaimsExpression "claims['sub'] matches 'repo:octo-org@123456/octo-repo@456789:*' and claims['repository_id'] eq '456789'"
        $x.Subject | Should -Be 'repo:octo-org@123456/octo-repo@456789:*'
        $x.Operator | Should -Be 'matches'
        $x.HasRepositoryId | Should -BeTrue
    }
    It 'notices a missing repository_id check' {
        (Get-SubFromClaimsExpression "claims['sub'] matches 'repo:contoso/*'").HasRepositoryId | Should -BeFalse
    }
}

Describe 'Test-FcgCredential' {
    It 'passes a clean immutable environment credential' {
        $r = Test-FcgCredential -Credential (New-TestCred 'repo:contoso@1/app@2:environment:prod')
        Get-Ids $r | Should -BeNullOrEmpty
    }
    It 'flags name-based subjects (FCG-08) and branch binding (FCG-12)' {
        $ids = Get-Ids (Test-FcgCredential -Credential (New-TestCred 'repo:contoso/app:ref:refs/heads/main'))
        $ids | Should -Contain 'FCG-08'
        $ids | Should -Contain 'FCG-12'
    }
    It 'flags an AWS role with no sub condition as critical (FCG-01)' {
        $r = Test-FcgCredential -Credential (New-TestCred $null -Platform 'AWS IAM role' -Audiences @('sts.amazonaws.com'))
        Get-Ids $r | Should -Contain 'FCG-01'
    }
    It 'flags any-owner wildcards (FCG-02)' {
        $ids = Get-Ids (Test-FcgCredential -Credential (New-TestCred 'repo:*/*' -Platform 'AWS IAM role' -Operator 'like' -Audiences @('sts.amazonaws.com')))
        $ids | Should -Contain 'FCG-02'
        $ids | Should -Not -Contain 'FCG-08'
    }
    It 'flags org-wide wildcards (FCG-05)' {
        Get-Ids (Test-FcgCredential -Credential (New-TestCred 'repo:contoso/*' -Platform 'AWS IAM role' -Operator 'like' -Audiences @('sts.amazonaws.com'))) | Should -Contain 'FCG-05'
    }
    It 'flags the hyphen format (FCG-03) and confirms it with the owner ID' {
        $r = Test-FcgCredential -Credential (New-TestCred 'repo:contoso-5544123/app-821093847:environment:prod') -HyphenOwnerId '5544123'
        Get-Ids $r | Should -Contain 'FCG-03'
        ($r.Findings | Where-Object CheckId -eq 'FCG-03').Detail | Should -Match 'Confirmed'
    }
    It 'uses GitHub lookups for renamed, deleted and orphaned repositories' {
        Get-Ids (Test-FcgCredential -Credential (New-TestCred 'repo:contoso/old:environment:p') -GitHub ([pscustomobject]@{ Status = 'Renamed'; FullName = 'contoso/new' })) | Should -Contain 'FCG-06'
        Get-Ids (Test-FcgCredential -Credential (New-TestCred 'repo:gone/app:environment:p') -GitHub ([pscustomobject]@{ Status = 'OwnerMissing' })) | Should -Contain 'FCG-04'
        Get-Ids (Test-FcgCredential -Credential (New-TestCred 'repo:contoso/app:environment:p') -GitHub ([pscustomobject]@{ Status = 'RepoMissing'; Note = 'Repository not found' })) | Should -Contain 'FCG-07'
        Get-Ids (Test-FcgCredential -Credential (New-TestCred 'repo:contoso@1/app@2:environment:p') -GitHub ([pscustomobject]@{ Status = 'RepoMissing' })) | Should -Contain 'FCG-14'
    }
    It 'checks the AWS audience (FCG-10)' {
        Get-Ids (Test-FcgCredential -Credential (New-TestCred 'repo:contoso@1/app@2:environment:p' -Platform 'AWS IAM role' -Audiences @())) | Should -Contain 'FCG-10'
    }
    It 'requires repository_id in flexible credentials (FCG-11)' {
        Get-Ids (Test-FcgCredential -Credential (New-TestCred $null -Expr "claims['sub'] matches 'repo:contoso@1/app@2:*'")) | Should -Contain 'FCG-11'
    }
}

Describe 'AWS trust policy parsing' {
    It 'creates one credential per sub value and keeps the operator' {
        $role = [pscustomobject]@{
            RoleName = 'r'; Arn = 'arn:aws:iam::1:role/r'
            AssumeRolePolicyDocument = ('{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRoleWithWebIdentity","Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},"Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},"StringLike":{"token.actions.githubusercontent.com:sub":["repo:a/b:*","repo:a/c:*"]}}}]}' | ConvertFrom-Json)
        }
        $c = @(ConvertFrom-AwsTrustPolicy -Role $role -AccountId '1')
        $c.Count | Should -Be 2
        $c[0].Operator | Should -Be 'like'
        $c[0].Audiences | Should -Contain 'sts.amazonaws.com'
    }
    It 'ignores roles that do not trust GitHub' {
        $role = [pscustomobject]@{ RoleName = 'ec2'; Arn = 'a'; AssumeRolePolicyDocument = ('{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":"ec2.amazonaws.com"}}]}' | ConvertFrom-Json) }
        @(ConvertFrom-AwsTrustPolicy -Role $role -AccountId '1').Count | Should -Be 0
    }
    It 'reads URL-encoded policy documents' {
        $doc = [uri]::EscapeDataString('{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRoleWithWebIdentity","Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"}}]}')
        $c = @(ConvertFrom-AwsTrustPolicy -Role ([pscustomobject]@{ RoleName = 'r'; Arn = 'a'; AssumeRolePolicyDocument = $doc }) -AccountId '1')
        $c.Count | Should -Be 1
        $c[0].Subject | Should -BeNullOrEmpty
    }
}

Describe 'Migration plan' {
    It 'rewrites a name-based subject to the immutable format, keeping the context' {
        $p = ConvertFrom-GitHubSubject 'repo:contoso/app:environment:prod'
        ConvertTo-ImmutableSubject -Parsed $p -OwnerId '1' -RepoId '2' | Should -Be 'repo:contoso@1/app@2:environment:prod'
    }
    It 'uses placeholders when IDs are unknown' {
        $p = ConvertFrom-GitHubSubject 'repo:contoso/app:ref:refs/heads/main'
        ConvertTo-ImmutableSubject -Parsed $p | Should -Be 'repo:contoso@<OWNER_ID>/app@<REPO_ID>:ref:refs/heads/main'
    }
    It 'fixes the hyphen delimiter to @' {
        $c = New-TestCred 'repo:contoso-5544123/app-821093847:environment:prod'
        $t = Test-FcgCredential -Credential $c -HyphenOwnerId '5544123'
        $plan = New-FcgMigrationPlan -Credential $c -Parsed $t.Parsed -GitHub $null -Findings $t.Findings
        $plan.NewSubject | Should -Be 'repo:contoso@5544123/app@821093847:environment:prod'
    }
    It 'plans deletion when the owner no longer exists' {
        $c = New-TestCred 'repo:gone/app:environment:p'
        $gh = [pscustomobject]@{ Status = 'OwnerMissing' }
        $t = Test-FcgCredential -Credential $c -GitHub $gh
        (New-FcgMigrationPlan -Credential $c -Parsed $t.Parsed -GitHub $gh -Findings $t.Findings).Action | Should -Be 'Delete'
    }
    It 'migrates to the new name when a repository was renamed' {
        $c = New-TestCred 'repo:contoso/old:environment:p'
        $gh = [pscustomobject]@{ Status = 'Renamed'; FullName = 'contoso/new'; RepoId = '9'; OwnerId = '1' }
        $t = Test-FcgCredential -Credential $c -GitHub $gh
        (New-FcgMigrationPlan -Credential $c -Parsed $t.Parsed -GitHub $gh -Findings $t.Findings).NewSubject | Should -Be 'repo:contoso@1/new@9:environment:p'
    }
}

Describe 'Demo run' {
    It 'produces every output and the expected headline numbers' {
        $out = Join-Path ([IO.Path]::GetTempPath()) ("fcg-test-" + [guid]::NewGuid())
        $run = Invoke-FedCredGuardian -Demo $true -Source @('Entra') -Format @('Html', 'Json', 'Csv', 'Markdown') -OutputPath $out -FailOn 'Critical'
        $run.Report.Summary.Credentials | Should -Be 16
        $run.Report.Summary.Severity.Critical | Should -Be 4
        $run.ExitCode | Should -Be 1
        foreach ($f in 'index.html', 'fedcred-report.json', 'fedcred-findings.csv', 'migration-plan.md') { Join-Path $out $f | Should -Exist }
        Remove-Item $out -Recurse -Force
    }
}
