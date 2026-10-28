<#
.SYNOPSIS
    FedCred Guardian - audits secret-free CI/CD access (GitHub Actions OIDC federation)
    across Microsoft Entra ID apps, Azure managed identities and AWS IAM roles.

.DESCRIPTION
    GitHub Actions can sign in to Azure and AWS without stored secrets by presenting an
    OIDC token whose "sub" claim the cloud trusts. Name-based subjects such as
    "repo:contoso/payments-api:ref:refs/heads/main" can be matched again when a repository
    is renamed, transferred, deleted or re-created ("subject recycling"). GitHub's
    immutable format embeds the owner and repository IDs instead:
    "repo:contoso@5544123/payments-api@821093847:ref:refs/heads/main".

    FedCred Guardian is READ-ONLY. It:
      * inventories every GitHub-trusting federated credential in Entra ID apps,
        user-assigned managed identities and AWS IAM role trust policies,
      * flags name-based subjects, wildcards, missing subject conditions, renamed or
        deleted repositories, and the withdrawn hyphen-delimited immutable format,
      * generates a step-by-step migration plan with ready-to-run commands.

    It never creates, changes or deletes anything. The generated commands are for you to
    review and run.

.PARAMETER Demo
    Run against the bundled sample environment. Needs no connections or modules.

.PARAMETER Source
    Which platforms to scan: Entra, ManagedIdentity, AWS. Default: all three.

.PARAMETER SubscriptionId
    Azure subscription IDs to scan for managed identities. Default: all you can read.

.PARAMETER AwsProfile
    AWS CLI profile to use. Default: the CLI's default credentials.

.PARAMETER GitHubToken
    Optional GitHub token (read-only, no scopes needed for public repos) used to resolve
    repository and owner IDs. Defaults to $env:GITHUB_TOKEN. Without it, lookups use the
    unauthenticated API (60 requests/hour) and private repositories show as unverified.

.PARAMETER SkipGitHubLookup
    Do not call the GitHub API. Migration commands will contain <OWNER_ID>/<REPO_ID>
    placeholders.

.PARAMETER InputPath
    Analyse an offline snapshot (same schema as demo/sample-environment.json) instead of
    connecting to the clouds.

.PARAMETER OutputPath
    Folder for the report. Default: .\FedCredGuardian_<timestamp>

.PARAMETER Format
    Output formats: Html, Json, Csv, Markdown. Default: all.

.PARAMETER FailOn
    Exit with code 1 when a finding at or above this severity exists (for CI).
    Critical, High, Medium, Low or None. Default: None.

.EXAMPLE
    .\Invoke-FedCredGuardian.ps1 -Demo

.EXAMPLE
    Connect-MgGraph -Scopes Application.Read.All; Connect-AzAccount
    .\Invoke-FedCredGuardian.ps1 -Source Entra,ManagedIdentity,AWS -FailOn High

.NOTES
    Version : 1.0.0
    Requires: PowerShell 7+
    License : MIT
    Author  : Akhilesh Ayyagari
#>
#Requires -Version 7.0
[CmdletBinding()]
param(
    [switch]$Demo,
    [ValidateSet('Entra', 'ManagedIdentity', 'AWS')]
    [string[]]$Source = @('Entra', 'ManagedIdentity', 'AWS'),
    [string[]]$SubscriptionId,
    [string]$AwsProfile,
    [string]$GitHubToken = $env:GITHUB_TOKEN,
    [switch]$SkipGitHubLookup,
    [string]$InputPath,
    [string]$OutputPath,
    [ValidateSet('Html', 'Json', 'Csv', 'Markdown')]
    [string[]]$Format = @('Html', 'Json', 'Csv', 'Markdown'),
    [ValidateSet('Critical', 'High', 'Medium', 'Low', 'None')]
    [string]$FailOn = 'None'
)

Set-StrictMode -Version Latest
$script:FcgVersion = '1.0.0'
$script:GitHubIssuer = 'https://token.actions.githubusercontent.com'
$script:EntraAudience = 'api://AzureADTokenExchange'
$script:AwsAudience = 'sts.amazonaws.com'
$script:SeverityRank = @{ Critical = 4; High = 3; Medium = 2; Low = 1; Info = 0 }
$script:SeverityWeight = @{ Critical = 60; High = 30; Medium = 12; Low = 4; Info = 0 }

# ---------------------------------------------------------------------------------------
# Check catalogue
# ---------------------------------------------------------------------------------------
$script:Checks = [ordered]@{
    'FCG-01' = @{ Severity = 'Critical'; Title = 'AWS role trusts GitHub OIDC with no subject condition'
        Why = 'Without a token.actions.githubusercontent.com:sub condition, a workflow in ANY repository on GitHub can assume this role.' }
    'FCG-02' = @{ Severity = 'Critical'; Title = 'Subject wildcard matches any GitHub owner'
        Why = 'The pattern matches repositories owned by anyone, so any GitHub user can mint a matching token.' }
    'FCG-03' = @{ Severity = 'Critical'; Title = 'Withdrawn hyphen-delimited immutable subject'
        Why = 'The first immutable format (April 2026) used "-" between name and ID. Hyphens are legal in names, so an attacker can register an owner such as "contoso-5544123" whose legacy subject is identical. GitHub replaced the delimiter with "@".' }
    'FCG-04' = @{ Severity = 'Critical'; Title = 'Trusted owner account no longer exists'
        Why = 'The GitHub user or organization in the subject was deleted. Anyone can register that name and create a repository whose tokens match this credential.' }
    'FCG-05' = @{ Severity = 'High'; Title = 'Subject wildcard trusts every repository of an owner'
        Why = 'Any repository in the organization, including new or forked-in ones, can use this identity. One compromised repo exposes the cloud role.' }
    'FCG-06' = @{ Severity = 'High'; Title = 'Repository was renamed or transferred'
        Why = 'The subject still names the old repository. That name is free to be re-created, and the new repository would receive this access.' }
    'FCG-07' = @{ Severity = 'High'; Title = 'Repository in the subject was not found'
        Why = 'The repository was deleted (or is private and could not be verified). If it is re-created under the same name it inherits this access.' }
    'FCG-08' = @{ Severity = 'Medium'; Title = 'Name-based (mutable) subject'
        Why = 'Name-based subjects are exposed to subject recycling. Microsoft and GitHub recommend migrating to the immutable owner@id/repo@id format.' }
    'FCG-09' = @{ Severity = 'Medium'; Title = 'Wildcard trusts every branch, tag or environment'
        Why = 'Any branch, including an unreviewed feature branch, can deploy with this identity.' }
    'FCG-10' = @{ Severity = 'Medium'; Title = 'AWS audience condition missing or unexpected'
        Why = 'Trust policies should require token.actions.githubusercontent.com:aud = sts.amazonaws.com.' }
    'FCG-11' = @{ Severity = 'Medium'; Title = 'Flexible credential does not check repository_id'
        Why = 'For flexible federated credentials GitHub requires the numeric repository_id claim in addition to sub.' }
    'FCG-12' = @{ Severity = 'Low'; Title = 'Credential is not bound to a protected environment'
        Why = 'Binding production identities to a GitHub environment lets you require reviewers before a workflow can use them.' }
    'FCG-13' = @{ Severity = 'Low'; Title = 'Credential trusts pull_request workflows'
        Why = 'Pull-request workflows run code that has not been merged. Keep this identity read-only.' }
    'FCG-14' = @{ Severity = 'Low'; Title = 'Immutable credential is orphaned'
        Why = 'The repository ID in the subject no longer exists. The credential can never be used again and should be deleted.' }
    'FCG-15' = @{ Severity = 'Low'; Title = 'Non-standard Entra audience'
        Why = 'GitHub Actions credentials normally use the audience api://AzureADTokenExchange.' }
    'FCG-16' = @{ Severity = 'Info'; Title = 'Custom subject template'
        Why = 'This subject does not start with "repo:", so the repository uses a customised OIDC subject template. Review it manually.' }
}

# ---------------------------------------------------------------------------------------
# Subject parsing
# ---------------------------------------------------------------------------------------
function ConvertFrom-GitHubSubject {
    <# Parses a GitHub Actions OIDC "sub" value into its parts. #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$Subject,
        [switch]$AllowWildcards
    )
    $r = [ordered]@{
        Raw = $Subject; Kind = 'Missing'; Format = $null
        Owner = $null; OwnerId = $null; Repo = $null; RepoId = $null
        Context = $null; ContextValue = $null; WildcardScope = 'None'
    }
    if ([string]::IsNullOrWhiteSpace($Subject)) { return [pscustomobject]$r }

    $m = [regex]::Match($Subject, '^repo:(?<owner>[^/:]+)/(?<repo>[^:]+)(?::(?<rest>.*))?$')
    if (-not $m.Success) {
        $r.Kind = 'Custom'
        if ($AllowWildcards -and $Subject -match '^\s*(\*|repo:\*)') { $r.Kind = 'Repo'; $r.WildcardScope = 'AnyOwner' }
        return [pscustomobject]$r
    }
    $r.Kind = 'Repo'
    $ownerPart = $m.Groups['owner'].Value
    $repoPart = $m.Groups['repo'].Value
    $rest = if ($m.Groups['rest'].Success) { $m.Groups['rest'].Value } else { '' }

    $oi = [regex]::Match($ownerPart, '^(?<n>.+)@(?<id>\d+)$')
    $ri = [regex]::Match($repoPart, '^(?<n>.+)@(?<id>\d+)$')
    $oh = [regex]::Match($ownerPart, '^(?<n>.+)-(?<id>\d{3,})$')
    $rh = [regex]::Match($repoPart, '^(?<n>.+)-(?<id>\d{5,})$')
    if ($oi.Success -and $ri.Success) {
        $r.Format = 'Immutable'
        $r.Owner = $oi.Groups['n'].Value; $r.OwnerId = $oi.Groups['id'].Value
        $r.Repo = $ri.Groups['n'].Value; $r.RepoId = $ri.Groups['id'].Value
    }
    elseif ($oh.Success -and $rh.Success) {
        # Looks like the withdrawn "name-id" delimiter. Confirmed later against GitHub IDs.
        $r.Format = 'ImmutableHyphen'
        $r.Owner = $oh.Groups['n'].Value; $r.OwnerId = $oh.Groups['id'].Value
        $r.Repo = $rh.Groups['n'].Value; $r.RepoId = $rh.Groups['id'].Value
    }
    else {
        $r.Format = 'Name'
        $r.Owner = $ownerPart; $r.Repo = $repoPart
    }

    switch -Regex ($rest) {
        '^ref:refs/heads/(?<v>.+)$' { $r.Context = 'branch'; $r.ContextValue = $Matches['v']; break }
        '^ref:refs/tags/(?<v>.+)$' { $r.Context = 'tag'; $r.ContextValue = $Matches['v']; break }
        '^environment:(?<v>.+)$' { $r.Context = 'environment'; $r.ContextValue = $Matches['v']; break }
        '^pull_request$' { $r.Context = 'pull_request'; break }
        '^$' { $r.Context = 'none'; break }
        default { $r.Context = 'other'; $r.ContextValue = $rest }
    }

    if ($AllowWildcards) {
        if ($ownerPart -match '[*?]') { $r.WildcardScope = 'AnyOwner' }
        elseif ($repoPart -match '[*?]') { $r.WildcardScope = 'AnyRepo' }
        elseif ($rest -match '[*?]' -or $r.Context -eq 'none') { $r.WildcardScope = 'AnyContext' }
    }
    [pscustomobject]$r
}

function Get-SubFromClaimsExpression {
    <# Extracts the sub pattern and repository_id check from a flexible FIC expression. #>
    param([string]$Expression)
    $out = [ordered]@{ Subject = $null; Operator = $null; HasRepositoryId = $false }
    if (-not $Expression) { return [pscustomobject]$out }
    $m = [regex]::Match($Expression, "claims\[\s*'sub'\s*\]\s+(?<op>matches|eq)\s+'(?<v>[^']*)'", 'IgnoreCase')
    if ($m.Success) { $out.Subject = $m.Groups['v'].Value; $out.Operator = $m.Groups['op'].Value.ToLower() }
    $out.HasRepositoryId = $Expression -match "claims\[\s*'repository_id'\s*\]"
    [pscustomobject]$out
}

# ---------------------------------------------------------------------------------------
# Collectors (all read-only)
# ---------------------------------------------------------------------------------------
function New-FcgCredential {
    param($Platform, $ResourceName, $ResourceId, $Location, $CredentialName, $CredentialId,
        $Issuer, $Subject, [string]$Operator = 'equals', $Audiences, $ClaimsExpression, $Raw)
    [pscustomobject][ordered]@{
        Platform = $Platform; ResourceName = $ResourceName; ResourceId = $ResourceId
        Location = $Location; CredentialName = $CredentialName; CredentialId = $CredentialId
        Issuer = $Issuer; Subject = $Subject; Operator = $Operator
        Audiences = @($Audiences | Where-Object { $_ }); ClaimsExpression = $ClaimsExpression; Raw = $Raw
    }
}

function Get-FcgEntraCredentials {
    if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        throw 'Microsoft.Graph.Authentication is not installed. Run: Install-Module Microsoft.Graph.Authentication; Connect-MgGraph -Scopes Application.Read.All'
    }
    $creds = New-Object System.Collections.Generic.List[object]
    $uri = 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName&$top=999'
    while ($uri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
        foreach ($app in $page.value) {
            # beta exposes claimsMatchingExpression for flexible credentials
            $fics = $null
            try { $fics = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/applications/$($app.id)/federatedIdentityCredentials" -OutputType PSObject).value }
            catch { $fics = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)/federatedIdentityCredentials" -OutputType PSObject).value }
            foreach ($f in @($fics)) {
                if (-not $f -or -not $f.issuer -or -not $f.issuer.StartsWith($script:GitHubIssuer)) { continue }
                $expr = $null
                if ($f.PSObject.Properties['claimsMatchingExpression'] -and $f.claimsMatchingExpression) { $expr = $f.claimsMatchingExpression.value }
                $creds.Add((New-FcgCredential -Platform 'Entra app' -ResourceName $app.displayName -ResourceId $app.id `
                            -Location "appId $($app.appId)" -CredentialName $f.name -CredentialId $f.id -Issuer $f.issuer `
                            -Subject $f.subject -Audiences $f.audiences -ClaimsExpression $expr -Raw $f))
            }
        }
        $uri = if ($page.PSObject.Properties['@odata.nextLink']) { $page.'@odata.nextLink' } else { $null }
    }
    $creds
}

function Get-FcgManagedIdentityCredentials {
    param([string[]]$SubscriptionId)
    if (-not (Get-Command Invoke-AzRestMethod -ErrorAction SilentlyContinue)) {
        throw 'Az.Accounts is not installed. Run: Install-Module Az.Accounts; Connect-AzAccount'
    }
    $subs = if ($SubscriptionId) { $SubscriptionId } else { (Get-AzSubscription -ErrorAction Stop).Id }
    $creds = New-Object System.Collections.Generic.List[object]
    foreach ($s in $subs) {
        $path = "/subscriptions/$s/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31"
        while ($path) {
            $resp = Invoke-AzRestMethod -Method GET -Path $path
            if ($resp.StatusCode -ne 200) { Write-Warning "Subscription ${s}: HTTP $($resp.StatusCode) listing identities"; break }
            $body = $resp.Content | ConvertFrom-Json
            foreach ($id in @($body.value)) {
                $rg = ($id.id -split '/')[4]
                $fr = Invoke-AzRestMethod -Method GET -Path "$($id.id)/federatedIdentityCredentials?api-version=2023-01-31"
                if ($fr.StatusCode -ne 200) { continue }
                foreach ($f in @(($fr.Content | ConvertFrom-Json).value)) {
                    if (-not $f -or -not $f.properties.issuer.StartsWith($script:GitHubIssuer)) { continue }
                    $creds.Add((New-FcgCredential -Platform 'Managed identity' -ResourceName $id.name -ResourceId $id.id `
                                -Location "rg $rg / sub $s" -CredentialName $f.name -CredentialId $f.id -Issuer $f.properties.issuer `
                                -Subject $f.properties.subject -Audiences $f.properties.audiences -Raw $f))
                }
            }
            $path = $null
            if ($body.PSObject.Properties['nextLink'] -and $body.nextLink) { $path = ([uri]$body.nextLink).PathAndQuery }
        }
    }
    $creds
}

function ConvertFrom-AwsTrustPolicy {
    <# Turns one IAM role into normalised credentials (one per trusted sub value). #>
    param([Parameter(Mandatory)]$Role, [string]$AccountId)
    $doc = $Role.AssumeRolePolicyDocument
    if ($doc -is [string]) { $doc = [uri]::UnescapeDataString($doc) | ConvertFrom-Json }
    $out = New-Object System.Collections.Generic.List[object]
    $si = 0
    foreach ($st in @($doc.Statement)) {
        $si++
        if ($st.Effect -ne 'Allow') { continue }
        $actions = @($st.Action)
        if (-not ($actions | Where-Object { $_ -in @('sts:AssumeRoleWithWebIdentity', 'sts:*', '*') })) { continue }
        if (-not $st.PSObject.Properties['Principal'] -or -not $st.Principal.PSObject.Properties['Federated']) { continue }
        $fed = @($st.Principal.Federated) | Where-Object { $_ -like '*oidc-provider/token.actions.githubusercontent.com*' }
        if (-not $fed) { continue }

        $subs = @(); $auds = @(); $op = 'equals'
        if ($st.PSObject.Properties['Condition'] -and $st.Condition) {
            foreach ($opProp in $st.Condition.PSObject.Properties) {
                foreach ($k in $opProp.Value.PSObject.Properties) {
                    if ($k.Name -eq 'token.actions.githubusercontent.com:sub') {
                        foreach ($v in @($k.Value)) { $subs += [pscustomobject]@{ Value = $v; Op = $(if ($opProp.Name -match 'Like') { 'like' } else { 'equals' }) } }
                    }
                    elseif ($k.Name -eq 'token.actions.githubusercontent.com:aud') { $auds += @($k.Value) }
                }
            }
        }
        $loc = "account $AccountId"
        if (-not $subs) {
            $out.Add((New-FcgCredential -Platform 'AWS IAM role' -ResourceName $Role.RoleName -ResourceId $Role.Arn -Location $loc `
                        -CredentialName "Statement $si" -CredentialId "$($Role.Arn)#$si" -Issuer $script:GitHubIssuer -Subject $null `
                        -Operator $op -Audiences $auds -Raw $st))
        }
        $n = 0
        foreach ($s in $subs) {
            $n++
            $out.Add((New-FcgCredential -Platform 'AWS IAM role' -ResourceName $Role.RoleName -ResourceId $Role.Arn -Location $loc `
                        -CredentialName "Statement $si, sub $n" -CredentialId "$($Role.Arn)#$si.$n" -Issuer $script:GitHubIssuer `
                        -Subject $s.Value -Operator $s.Op -Audiences $auds -Raw $st))
        }
    }
    $out
}

function Get-FcgAwsCredentials {
    param([string]$AwsProfile)
    if (-not (Get-Command aws -ErrorAction SilentlyContinue)) { throw 'AWS CLI v2 is not installed or not on PATH.' }
    $p = @(); if ($AwsProfile) { $p = @('--profile', $AwsProfile) }
    $acct = (& aws sts get-caller-identity --output json @p | ConvertFrom-Json).Account
    $roles = (& aws iam list-roles --output json @p | ConvertFrom-Json).Roles
    $creds = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($roles)) { foreach ($c in (ConvertFrom-AwsTrustPolicy -Role $r -AccountId $acct)) { $creds.Add($c) } }
    $creds
}

# ---------------------------------------------------------------------------------------
# GitHub lookups (read-only, cached)
# ---------------------------------------------------------------------------------------
$script:GitHubCache = @{}
function Invoke-FcgGitHubGet {
    param([string]$Path, [string]$Token)
    $h = @{ Accept = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28'; 'User-Agent' = 'FedCred-Guardian' }
    if ($Token) { $h.Authorization = "Bearer $Token" }
    try { return @{ Status = 200; Body = (Invoke-RestMethod -Uri "https://api.github.com/$Path" -Headers $h -ErrorAction Stop) } }
    catch {
        $code = 0
        if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        return @{ Status = $code; Body = $null }
    }
}

function Resolve-FcgGitHubRepo {
    <# Returns Found | Renamed | RepoMissing | OwnerMissing | Unknown plus current IDs. #>
    param([string]$Owner, [string]$Repo, [string]$RepoId, [string]$Token, [hashtable]$Offline)
    $key = if ($RepoId) { "id:$RepoId" } else { "$Owner/$Repo".ToLower() }
    if ($Offline) {
        if ($Offline.ContainsKey($key)) { return $Offline[$key] }
        return [pscustomobject]@{ Status = 'Unknown'; FullName = $null; RepoId = $null; OwnerId = $null; Note = 'Not in snapshot' }
    }
    if ($script:GitHubCache.ContainsKey($key)) { return $script:GitHubCache[$key] }

    $res = $null
    if ($RepoId) {
        $g = Invoke-FcgGitHubGet -Path "repositories/$RepoId" -Token $Token
        if ($g.Status -eq 200) { $res = [pscustomobject]@{ Status = 'Found'; FullName = $g.Body.full_name; RepoId = "$($g.Body.id)"; OwnerId = "$($g.Body.owner.id)"; Note = $null } }
        elseif ($g.Status -eq 404) { $res = [pscustomobject]@{ Status = 'RepoMissing'; FullName = $null; RepoId = $RepoId; OwnerId = $null; Note = 'Repository ID not found' } }
    }
    else {
        $g = Invoke-FcgGitHubGet -Path "repos/$Owner/$Repo" -Token $Token
        if ($g.Status -eq 200) {
            $st = if ($g.Body.full_name -ieq "$Owner/$Repo") { 'Found' } else { 'Renamed' }
            $res = [pscustomobject]@{ Status = $st; FullName = $g.Body.full_name; RepoId = "$($g.Body.id)"; OwnerId = "$($g.Body.owner.id)"; Note = $null }
        }
        elseif ($g.Status -eq 404) {
            $u = Invoke-FcgGitHubGet -Path "users/$Owner" -Token $Token
            if ($u.Status -eq 404) { $res = [pscustomobject]@{ Status = 'OwnerMissing'; FullName = $null; RepoId = $null; OwnerId = $null; Note = 'Owner account not found' } }
            elseif ($u.Status -eq 200) {
                $note = if ($Token) { 'Repository not found' } else { 'Repository not found (private repositories need -GitHubToken)' }
                $res = [pscustomobject]@{ Status = 'RepoMissing'; FullName = $null; RepoId = $null; OwnerId = "$($u.Body.id)"; Note = $note }
            }
        }
    }
    if (-not $res) { $res = [pscustomobject]@{ Status = 'Unknown'; FullName = $null; RepoId = $null; OwnerId = $null; Note = 'GitHub API unavailable or rate-limited' } }
    $script:GitHubCache[$key] = $res
    $res
}

function Resolve-FcgGitHubOwnerId {
    param([string]$Owner, [string]$Token, [hashtable]$Offline)
    $key = "owner:$($Owner.ToLower())"
    if ($Offline) { if ($Offline.ContainsKey($key)) { return $Offline[$key] } else { return $null } }
    if ($script:GitHubCache.ContainsKey($key)) { return $script:GitHubCache[$key] }
    $u = Invoke-FcgGitHubGet -Path "users/$Owner" -Token $Token
    $id = if ($u.Status -eq 200) { "$($u.Body.id)" } else { $null }
    $script:GitHubCache[$key] = $id
    $id
}

# ---------------------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------------------
function New-FcgFinding {
    param([string]$CheckId, [string]$Detail)
    $c = $script:Checks[$CheckId]
    [pscustomobject][ordered]@{ CheckId = $CheckId; Severity = $c.Severity; Title = $c.Title; Why = $c.Why; Detail = $Detail }
}

function Test-FcgCredential {
    <# Evaluates one normalised credential. Returns the parsed subject, GitHub status and findings. #>
    param([Parameter(Mandatory)]$Credential, $GitHub, $HyphenOwnerId)
    $f = New-Object System.Collections.Generic.List[object]
    $subj = $Credential.Subject
    $op = $Credential.Operator
    $flex = $null
    if ($Credential.ClaimsExpression) {
        $flex = Get-SubFromClaimsExpression -Expression $Credential.ClaimsExpression
        $subj = $flex.Subject; $op = $flex.Operator
    }
    $wild = $op -in @('like', 'matches')
    $p = ConvertFrom-GitHubSubject -Subject $subj -AllowWildcards:$wild

    if ($p.Kind -eq 'Missing') {
        if ($Credential.Platform -eq 'AWS IAM role') { $f.Add((New-FcgFinding 'FCG-01' 'No token.actions.githubusercontent.com:sub condition in the trust policy.')) }
        return [pscustomobject]@{ Parsed = $p; Findings = $f }
    }
    if ($p.Kind -eq 'Custom') {
        $f.Add((New-FcgFinding 'FCG-16' "Subject: $subj"))
        return [pscustomobject]@{ Parsed = $p; Findings = $f }
    }

    switch ($p.WildcardScope) {
        'AnyOwner' { $f.Add((New-FcgFinding 'FCG-02' "Pattern '$subj' matches repositories of any owner.")) }
        'AnyRepo' { $f.Add((New-FcgFinding 'FCG-05' "Pattern '$subj' matches many repositories owned by '$($p.Owner)', including ones created later.")) }
        'AnyContext' { $f.Add((New-FcgFinding 'FCG-09' "Pattern '$subj' matches any branch, tag, environment or pull request.")) }
    }

    if ($p.Format -eq 'ImmutableHyphen') {
        $confirmed = $HyphenOwnerId -and ($HyphenOwnerId -eq $p.OwnerId)
        $d = "Subject uses '$($p.Owner)-$($p.OwnerId)/$($p.Repo)-$($p.RepoId)'. Replace '-' with '@'."
        if ($confirmed) { $d += " Confirmed: $($p.Owner) has owner ID $($p.OwnerId)." } else { $d += ' Not confirmed against GitHub; verify the owner ID.' }
        $f.Add((New-FcgFinding 'FCG-03' $d))
    }
    elseif ($p.Format -eq 'Name' -and $p.WildcardScope -ne 'AnyOwner') {
        $f.Add((New-FcgFinding 'FCG-08' "Subject '$subj' identifies the repository by name only."))
    }

    if ($GitHub) {
        switch ($GitHub.Status) {
            'OwnerMissing' { $f.Add((New-FcgFinding 'FCG-04' "GitHub owner '$($p.Owner)' does not exist. Delete this credential.")) }
            'Renamed' { $f.Add((New-FcgFinding 'FCG-06' "'$($p.Owner)/$($p.Repo)' now redirects to '$($GitHub.FullName)'.")) }
            'RepoMissing' {
                if ($p.Format -eq 'Immutable') { $f.Add((New-FcgFinding 'FCG-14' "Repository ID $($p.RepoId) no longer exists.")) }
                else { $f.Add((New-FcgFinding 'FCG-07' "$($GitHub.Note): '$($p.Owner)/$($p.Repo)'.")) }
            }
        }
    }

    if ($p.Context -eq 'pull_request') { $f.Add((New-FcgFinding 'FCG-13' 'Subject trusts the pull_request context.')) }
    if ($p.Context -in @('branch', 'tag') -and $p.WildcardScope -eq 'None') {
        $f.Add((New-FcgFinding 'FCG-12' "Bound to $($p.Context) '$($p.ContextValue)' rather than an environment with required reviewers."))
    }

    if ($Credential.Platform -eq 'AWS IAM role') {
        $auds = @($Credential.Audiences)
        if (-not $auds) { $f.Add((New-FcgFinding 'FCG-10' 'No token.actions.githubusercontent.com:aud condition.')) }
        elseif ($auds -notcontains $script:AwsAudience -or $auds.Count -gt 1) { $f.Add((New-FcgFinding 'FCG-10' "Audience is '$($auds -join ', ')'.")) }
    }
    else {
        $auds = @($Credential.Audiences)
        if ($auds -and ($auds -notcontains $script:EntraAudience)) { $f.Add((New-FcgFinding 'FCG-15' "Audience is '$($auds -join ', ')'.")) }
    }
    if ($flex -and -not $flex.HasRepositoryId) { $f.Add((New-FcgFinding 'FCG-11' 'claimsMatchingExpression has no claims[''repository_id''] condition.')) }

    [pscustomobject]@{ Parsed = $p; Findings = $f }
}

function Get-FcgCredentialScore {
    param($Findings)
    $s = 100
    foreach ($x in @($Findings)) { $s -= $script:SeverityWeight[$x.Severity] }
    [math]::Max(0, $s)
}

function Get-FcgGrade {
    param([int]$Score)
    if ($Score -ge 90) { 'A' } elseif ($Score -ge 80) { 'B' } elseif ($Score -ge 70) { 'C' } elseif ($Score -ge 60) { 'D' } else { 'F' }
}

# ---------------------------------------------------------------------------------------
# Migration plan
# ---------------------------------------------------------------------------------------
function ConvertTo-ImmutableSubject {
    param($Parsed, [string]$OwnerId, [string]$RepoId, [string]$Owner, [string]$Repo)
    $o = if ($Owner) { $Owner } else { $Parsed.Owner }
    $rp = if ($Repo) { $Repo } else { $Parsed.Repo }
    $oid = if ($OwnerId) { $OwnerId } else { '<OWNER_ID>' }
    $rid = if ($RepoId) { $RepoId } else { '<REPO_ID>' }
    $tail = if ($Parsed.Raw -match '^repo:[^/:]+/[^:]+(?<t>:.*)?$' -and $Matches['t']) { $Matches['t'] } else { '' }
    "repo:$o@$oid/$rp@$rid$tail"
}

function New-FcgMigrationPlan {
    <# Builds ordered steps with commands. Returns $null when nothing needs migrating. #>
    param($Credential, $Parsed, $GitHub, $Findings)
    $ids = @($Findings | ForEach-Object CheckId)
    $q = [char]39
    if ($ids -contains 'FCG-01' -or $ids -contains 'FCG-02') {
        return [pscustomobject]@{ Action = 'Restrict'; NewSubject = $null
            Steps = @([pscustomobject]@{ Title = 'Scope the trust to exact repositories'; Text = 'This identity can be used by any GitHub repository. Replace the condition with exact StringEquals subjects for the repositories that need it, using the immutable format.'; Command = $null }) }
    }
    if ($ids -contains 'FCG-04' -or $ids -contains 'FCG-14' -or ($ids -contains 'FCG-07')) {
        $cmd = switch ($Credential.Platform) {
            'Entra app' { "az ad app federated-credential delete --id $($Credential.ResourceId) --federated-credential-id $($Credential.CredentialId)" }
            'Managed identity' { $rg = ($Credential.ResourceId -split '/')[4]; "az identity federated-credential delete --name $($Credential.CredentialName) --identity-name $($Credential.ResourceName) --resource-group $rg --yes" }
            default { "# Remove this sub value from the trust policy of role $($Credential.ResourceName), then:`naws iam update-assume-role-policy --role-name $($Credential.ResourceName) --policy-document file://trust-$($Credential.ResourceName).json" }
        }
        return [pscustomobject]@{ Action = 'Delete'; NewSubject = $null
            Steps = @(
                [pscustomobject]@{ Title = 'Confirm nothing still uses it'; Text = 'If the repository is private, re-run with -GitHubToken first. Then check sign-in logs (Entra: service principal sign-ins, AWS: CloudTrail AssumeRoleWithWebIdentity) for the last 30 days.'; Command = $null },
                [pscustomobject]@{ Title = 'Delete the credential'; Text = 'The repository it trusted is gone, so the credential only creates risk.'; Command = $cmd }) }
    }
    if ($Parsed.Kind -ne 'Repo' -or $Parsed.Format -eq 'Immutable') { return $null }
    if ($Parsed.WildcardScope -ne 'None' -and $Parsed.WildcardScope -ne 'AnyContext' -and $Parsed.Format -ne 'ImmutableHyphen') {
        return [pscustomobject]@{ Action = 'Restrict'; NewSubject = $null
            Steps = @([pscustomobject]@{ Title = 'Replace the wildcard with exact repositories'; Text = 'List the repositories that really need this identity and create one immutable credential per repository (or per environment).'; Command = $null }) }
    }

    $owner = $Parsed.Owner; $repo = $Parsed.Repo; $oid = $Parsed.OwnerId; $rid = $Parsed.RepoId
    if ($GitHub -and $GitHub.Status -in @('Found', 'Renamed')) {
        if ($GitHub.Status -eq 'Renamed') { $owner, $repo = $GitHub.FullName -split '/', 2 }
        $oid = $GitHub.OwnerId; $rid = $GitHub.RepoId
    }
    if ($Parsed.Format -eq 'ImmutableHyphen') { $oid = $Parsed.OwnerId; $rid = $Parsed.RepoId }
    $new = ConvertTo-ImmutableSubject -Parsed $Parsed -OwnerId $oid -RepoId $rid -Owner $owner -Repo $repo
    $newName = ("$($Credential.CredentialName)-immutable" -replace '[^A-Za-z0-9_-]', '-')
    $steps = New-Object System.Collections.Generic.List[object]

    if ($GitHub -and $GitHub.Status -eq 'Renamed') {
        $steps.Add([pscustomobject]@{ Title = 'Confirm the intended repository'; Text = "The old name now redirects to $($GitHub.FullName). Make sure that is the repository that should keep this access before migrating."; Command = $null })
    }
    if (-not $oid -or -not $rid) {
        $steps.Add([pscustomobject]@{ Title = 'Look up the owner and repository IDs'; Text = 'Replace <OWNER_ID> and <REPO_ID> below.'; Command = "gh api repos/$owner/$repo --jq '{repo_id: .id, owner_id: .owner.id}'" })
    }

    switch ($Credential.Platform) {
        'Entra app' {
            $json = [ordered]@{ name = $newName; issuer = $script:GitHubIssuer; subject = $new; audiences = @($script:EntraAudience); description = "Immutable subject for $owner/$repo (FedCred Guardian)" } | ConvertTo-Json
            $steps.Add([pscustomobject]@{ Title = 'Create the immutable credential next to the old one'; Text = "Save as $newName.json, then run the command."; Command = "$json`n`naz ad app federated-credential create --id $($Credential.ResourceId) --parameters $newName.json" })
        }
        'Managed identity' {
            $rg = ($Credential.ResourceId -split '/')[4]
            $steps.Add([pscustomobject]@{ Title = 'Create the immutable credential next to the old one'; Text = 'Both credentials work side by side until you remove the old one.'; Command = "az identity federated-credential create --name $newName --identity-name $($Credential.ResourceName) --resource-group $rg --issuer $($script:GitHubIssuer) --subject $q$new$q --audiences $($script:EntraAudience)" })
        }
        'AWS IAM role' {
            $steps.Add([pscustomobject]@{ Title = 'Trust both subjects during the switch'; Text = "In the trust policy of $($Credential.ResourceName), set token.actions.githubusercontent.com:sub (StringEquals) to both values: `"$($Parsed.Raw)`" and `"$new`"."; Command = "aws iam update-assume-role-policy --role-name $($Credential.ResourceName) --policy-document file://trust-$($Credential.ResourceName)-transition.json" })
        }
    }
    $steps.Add([pscustomobject]@{ Title = 'Opt the repository in on GitHub'; Text = "Repository (or organization) Settings > Actions > OIDC > Use immutable subject claim, for $owner/$repo."; Command = $null })
    $steps.Add([pscustomobject]@{ Title = 'Validate'; Text = 'Run the workflow once and confirm it signs in with the new credential.'; Command = "gh workflow run <workflow.yml> --repo $owner/$repo" })
    switch ($Credential.Platform) {
        'Entra app' { $steps.Add([pscustomobject]@{ Title = 'Remove the old credential'; Text = 'Only after validation succeeds.'; Command = "az ad app federated-credential delete --id $($Credential.ResourceId) --federated-credential-id $($Credential.CredentialId)" }) }
        'Managed identity' { $rg = ($Credential.ResourceId -split '/')[4]; $steps.Add([pscustomobject]@{ Title = 'Remove the old credential'; Text = 'Only after validation succeeds.'; Command = "az identity federated-credential delete --name $($Credential.CredentialName) --identity-name $($Credential.ResourceName) --resource-group $rg --yes" }) }
        'AWS IAM role' { $steps.Add([pscustomobject]@{ Title = 'Remove the old subject'; Text = "Keep only `"$new`" in the sub condition."; Command = "aws iam update-assume-role-policy --role-name $($Credential.ResourceName) --policy-document file://trust-$($Credential.ResourceName).json" }) }
    }
    [pscustomobject]@{ Action = 'Migrate'; NewSubject = $new; Steps = $steps }
}

# ---------------------------------------------------------------------------------------
# Analysis pipeline
# ---------------------------------------------------------------------------------------
function Invoke-FcgAnalysis {
    param([object[]]$Credentials, [hashtable]$OfflineGitHub, [string]$Token, [switch]$NoLookup)
    $results = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($c in $Credentials) {
        $i++
        $wild = $c.Operator -in @('like', 'matches')
        $subj = $c.Subject
        if ($c.ClaimsExpression) { $fx = Get-SubFromClaimsExpression $c.ClaimsExpression; $subj = $fx.Subject; $wild = $fx.Operator -eq 'matches' }
        $p = ConvertFrom-GitHubSubject -Subject $subj -AllowWildcards:$wild
        $gh = $null; $hyId = $null
        if (-not $NoLookup -and $p.Kind -eq 'Repo' -and $p.WildcardScope -notin @('AnyOwner', 'AnyRepo')) {
            if ($p.Format -eq 'Immutable') { $gh = Resolve-FcgGitHubRepo -RepoId $p.RepoId -Token $Token -Offline $OfflineGitHub }
            elseif ($p.Format -eq 'ImmutableHyphen') { $hyId = Resolve-FcgGitHubOwnerId -Owner $p.Owner -Token $Token -Offline $OfflineGitHub }
            else { $gh = Resolve-FcgGitHubRepo -Owner $p.Owner -Repo $p.Repo -Token $Token -Offline $OfflineGitHub }
        }
        $t = Test-FcgCredential -Credential $c -GitHub $gh -HyphenOwnerId $hyId
        $findings = @($t.Findings | Sort-Object { - $script:SeverityRank[$_.Severity] })
        $plan = New-FcgMigrationPlan -Credential $c -Parsed $t.Parsed -GitHub $gh -Findings $findings
        $score = Get-FcgCredentialScore $findings
        $worst = if ($findings) { $findings[0].Severity } else { 'Pass' }
        $status = if ($t.Parsed.Format -eq 'Immutable' -and -not ($findings | Where-Object { $script:SeverityRank[$_.Severity] -ge 2 })) { 'Ready' } elseif ($plan) { $plan.Action } else { 'Review' }
        $results.Add([pscustomobject][ordered]@{
                Id = "C$('{0:D3}' -f $i)"; Platform = $c.Platform; ResourceName = $c.ResourceName; ResourceId = $c.ResourceId
                Location = $c.Location; CredentialName = $c.CredentialName; CredentialId = $c.CredentialId
                Subject = $subj; Operator = $(if ($c.ClaimsExpression) { 'expression' } else { $c.Operator })
                ClaimsExpression = $c.ClaimsExpression; Audiences = @($c.Audiences)
                Format = $t.Parsed.Format; Kind = $t.Parsed.Kind; Context = $t.Parsed.Context; ContextValue = $t.Parsed.ContextValue
                WildcardScope = $t.Parsed.WildcardScope; Owner = $t.Parsed.Owner; Repo = $t.Parsed.Repo
                GitHub = $gh; Score = $score; Worst = $worst; Status = $status; Findings = $findings; Plan = $plan
            })
    }
    $results
}

function Get-FcgSummary {
    param([object[]]$Results)
    $all = @($Results | ForEach-Object { $_.Findings })
    $sev = [ordered]@{}
    foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'Info') { $sev[$s] = @($all | Where-Object Severity -eq $s).Count }
    $n = @($Results).Count
    $score = if ($n) { [int][math]::Round((($Results | Measure-Object Score -Average).Average)) } else { 100 }
    $ready = @($Results | Where-Object Status -eq 'Ready').Count
    $plat = [ordered]@{}
    foreach ($p in 'Entra app', 'Managed identity', 'AWS IAM role') { $plat[$p] = @($Results | Where-Object Platform -eq $p).Count }
    $fmt = [ordered]@{
        Immutable = @($Results | Where-Object Format -eq 'Immutable').Count
        NameBased = @($Results | Where-Object Format -eq 'Name').Count
        Hyphen    = @($Results | Where-Object Format -eq 'ImmutableHyphen').Count
        Other     = @($Results | Where-Object { -not $_.Format }).Count
    }
    [pscustomobject][ordered]@{
        Credentials = $n; Score = $score; Grade = (Get-FcgGrade $score); Ready = $ready
        ReadyPct = $(if ($n) { [int][math]::Round(100 * $ready / $n) } else { 100 })
        Severity = $sev; Platforms = $plat; Formats = $fmt
        ToMigrate = @($Results | Where-Object Status -eq 'Migrate').Count
        ToDelete = @($Results | Where-Object Status -eq 'Delete').Count
        ToRestrict = @($Results | Where-Object Status -eq 'Restrict').Count
    }
}

# ---------------------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------------------
function Export-FcgMarkdown {
    param($Report, [string]$Path)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("# FedCred Guardian migration plan")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("Scope: $($Report.Scope.Label) - generated $($Report.GeneratedAt)")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("Score **$($Report.Summary.Score)/100 (grade $($Report.Summary.Grade))** - $($Report.Summary.Credentials) credentials, $($Report.Summary.Ready) ready, $($Report.Summary.ToMigrate) to migrate, $($Report.Summary.ToRestrict) to restrict, $($Report.Summary.ToDelete) to delete.")
    foreach ($r in $Report.Credentials | Where-Object { $_.Plan }) {
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("## $($r.Id) $($r.Plan.Action): $($r.Platform) '$($r.ResourceName)' / $($r.CredentialName)")
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("Current subject: ``$($r.Subject)``")
        if ($r.Plan.NewSubject) { [void]$sb.AppendLine(); [void]$sb.AppendLine("New subject: ``$($r.Plan.NewSubject)``") }
        $n = 0
        foreach ($s in $r.Plan.Steps) {
            $n++
            [void]$sb.AppendLine(); [void]$sb.AppendLine("$n. **$($s.Title).** $($s.Text)")
            if ($s.Command) { [void]$sb.AppendLine(); [void]$sb.AppendLine('   ```'); foreach ($l in ($s.Command -split "`n")) { [void]$sb.AppendLine("   $l") }; [void]$sb.AppendLine('   ```') }
        }
    }
    Set-Content -Path $Path -Value $sb.ToString() -Encoding UTF8
}

function Export-FcgHtml {
    param($Report, [string]$Path, [string]$TemplatePath)
    $tpl = Get-Content -Path $TemplatePath -Raw -Encoding UTF8
    $json = $Report | ConvertTo-Json -Depth 12 -Compress
    $json = $json -replace '</', '<\/'
    $html = $tpl.Replace('/*__FCG_DATA__*/null', $json)
    Set-Content -Path $Path -Value $html -Encoding UTF8
}

function Invoke-FedCredGuardian {
    [CmdletBinding()]
    param($Demo, $Source, $SubscriptionId, $AwsProfile, $GitHubToken, $SkipGitHubLookup, $InputPath, $OutputPath, $Format, $FailOn)
    $root = $PSScriptRoot
    if (-not $root) { $root = (Get-Location).Path }
    $offline = $null; $creds = @(); $label = $null; $sources = @()

    if ($Demo -or $InputPath) {
        $file = if ($Demo) { Join-Path $root 'demo/sample-environment.json' } else { $InputPath }
        $snap = Get-Content -Path $file -Raw -Encoding UTF8 | ConvertFrom-Json
        $label = $snap.label
        foreach ($a in @($snap.entra)) {
            foreach ($f in @($a.federatedIdentityCredentials)) {
                $expr = if ($f.PSObject.Properties['claimsMatchingExpression'] -and $f.claimsMatchingExpression) { $f.claimsMatchingExpression.value } else { $null }
                $creds += New-FcgCredential -Platform 'Entra app' -ResourceName $a.displayName -ResourceId $a.id -Location "appId $($a.appId)" `
                    -CredentialName $f.name -CredentialId $f.id -Issuer $f.issuer -Subject $f.subject -Audiences $f.audiences -ClaimsExpression $expr -Raw $f
            }
        }
        foreach ($m in @($snap.managedIdentities)) {
            $rg = ($m.id -split '/')[4]; $sub = ($m.id -split '/')[2]
            foreach ($f in @($m.federatedIdentityCredentials)) {
                $creds += New-FcgCredential -Platform 'Managed identity' -ResourceName $m.name -ResourceId $m.id -Location "rg $rg / sub $sub" `
                    -CredentialName $f.name -CredentialId $f.id -Issuer $f.properties.issuer -Subject $f.properties.subject -Audiences $f.properties.audiences -Raw $f
            }
        }
        foreach ($r in @($snap.aws.roles)) { $creds += @(ConvertFrom-AwsTrustPolicy -Role $r -AccountId $snap.aws.accountId) }
        $creds = @($creds | Where-Object { $_.Issuer -and $_.Issuer.StartsWith($script:GitHubIssuer) })
        $offline = @{}
        foreach ($p in @($snap.github.PSObject.Properties)) { $offline[$p.Name] = $p.Value }
        $sources = @('Entra', 'ManagedIdentity', 'AWS')
    }
    else {
        $label = 'Live scan'
        if ('Entra' -in $Source) { Write-Host '  Scanning Entra ID app registrations...'; $creds += @(Get-FcgEntraCredentials) }
        if ('ManagedIdentity' -in $Source) { Write-Host '  Scanning user-assigned managed identities...'; $creds += @(Get-FcgManagedIdentityCredentials -SubscriptionId $SubscriptionId) }
        if ('AWS' -in $Source) { Write-Host '  Scanning AWS IAM role trust policies...'; $creds += @(Get-FcgAwsCredentials -AwsProfile $AwsProfile) }
        $sources = $Source
    }

    Write-Host "  Found $(@($creds).Count) GitHub-trusting credentials. Evaluating..."
    $results = Invoke-FcgAnalysis -Credentials $creds -OfflineGitHub $offline -Token $GitHubToken -NoLookup:$SkipGitHubLookup
    $summary = Get-FcgSummary -Results $results
    $report = [pscustomobject][ordered]@{
        Tool = 'FedCred Guardian'; Version = $script:FcgVersion; GeneratedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        Scope = [pscustomobject]@{ Label = $label; Sources = $sources; Demo = [bool]$Demo; GitHubLookup = (-not $SkipGitHubLookup) }
        Summary = $summary
        Checks = @($script:Checks.Keys | ForEach-Object { [pscustomobject]@{ Id = $_; Severity = $script:Checks[$_].Severity; Title = $script:Checks[$_].Title; Why = $script:Checks[$_].Why } })
        Credentials = $results
    }

    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location) ("FedCredGuardian_" + (Get-Date -Format 'yyyyMMdd_HHmmss')) }
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    if ('Json' -in $Format) { $report | ConvertTo-Json -Depth 12 | Set-Content -Path (Join-Path $OutputPath 'fedcred-report.json') -Encoding UTF8 }
    if ('Csv' -in $Format) {
        $rows = foreach ($r in $results) {
            $fs = @($r.Findings)
            if (-not $fs) { $fs = @([pscustomobject]@{ CheckId = ''; Severity = 'Pass'; Title = 'No issues'; Detail = '' }) }
            foreach ($x in $fs) {
                [pscustomobject][ordered]@{ Credential = $r.Id; Platform = $r.Platform; Resource = $r.ResourceName; CredentialName = $r.CredentialName
                    Subject = $r.Subject; Format = $r.Format; Status = $r.Status; CheckId = $x.CheckId; Severity = $x.Severity; Title = $x.Title; Detail = $x.Detail; NewSubject = $(if ($r.Plan) { $r.Plan.NewSubject }) }
            }
        }
        $rows | Export-Csv -Path (Join-Path $OutputPath 'fedcred-findings.csv') -NoTypeInformation -Encoding UTF8
    }
    if ('Markdown' -in $Format) { Export-FcgMarkdown -Report $report -Path (Join-Path $OutputPath 'migration-plan.md') }
    if ('Html' -in $Format) { Export-FcgHtml -Report $report -Path (Join-Path $OutputPath 'index.html') -TemplatePath (Join-Path $root 'report/template.html') }

    $s = $summary.Severity
    Write-Host ''
    Write-Host "  Score: $($summary.Score)/100  (Grade $($summary.Grade))   Ready: $($summary.Ready)/$($summary.Credentials)"
    Write-Host "  Critical $($s.Critical)  High $($s.High)  Medium $($s.Medium)  Low $($s.Low)"
    Write-Host "  Migrate $($summary.ToMigrate)  Restrict $($summary.ToRestrict)  Delete $($summary.ToDelete)"
    Write-Host "  Report: $OutputPath"

    $code = 0
    if ($FailOn -ne 'None') {
        $limit = $script:SeverityRank[$FailOn]
        if (@($results.Findings | Where-Object { $script:SeverityRank[$_.Severity] -ge $limit }).Count) { $code = 1 }
    }
    [pscustomobject]@{ Report = $report; OutputPath = $OutputPath; ExitCode = $code }
}

# Run unless dot-sourced (tests dot-source this file to load the functions).
if ($MyInvocation.InvocationName -ne '.') {
    Write-Host ''
    Write-Host "  FedCred Guardian v$script:FcgVersion  -  read-only audit of GitHub OIDC trust"
    Write-Host ''
    $run = Invoke-FedCredGuardian -Demo:$Demo -Source $Source -SubscriptionId $SubscriptionId -AwsProfile $AwsProfile `
        -GitHubToken $GitHubToken -SkipGitHubLookup:$SkipGitHubLookup -InputPath $InputPath -OutputPath $OutputPath -Format $Format -FailOn $FailOn
    exit $run.ExitCode
}
