Set-StrictMode -Version Latest

function New-AccessReviewState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][string]$RawPath,
        [switch]$DeepEnumerate
    )

    [pscustomobject]@{
        OutputPath = $OutputPath
        RawPath = $RawPath
        DeepEnumerate = [bool]$DeepEnumerate
        StartedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
        CompletedAtUtc = $null
        Collectors = New-Object System.Collections.Generic.List[object]
        Findings = New-Object System.Collections.Generic.List[object]
        Data = [ordered]@{}
        ReportMarkdownPath = $null
        ReportJsonPath = $null
    }
}

function ConvertTo-PlainObject {
    [CmdletBinding()]
    param(
        [AllowNull()]$InputObject,
        [int]$Depth = 6
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $json = $InputObject | ConvertTo-Json -Depth $Depth -Compress
    if ([string]::IsNullOrWhiteSpace($json)) {
        return $null
    }

    return $json | ConvertFrom-Json
}

function Write-AccessReviewJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowNull()]$Data,
        [int]$Depth = 20
    )

    $Data | ConvertTo-Json -Depth $Depth | Set-Content -Path $Path -Encoding UTF8
}

function ConvertFrom-JwtPayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Token
    )

    $parts = $Token.Split(".")
    if ($parts.Count -lt 2) {
        return $null
    }

    $payload = $parts[1].Replace("-", "+").Replace("_", "/")
    switch ($payload.Length % 4) {
        2 { $payload += "==" }
        3 { $payload += "=" }
        1 { return $null }
    }

    try {
        $bytes = [Convert]::FromBase64String($payload)
        $json = [System.Text.Encoding]::UTF8.GetString($bytes)
        return $json | ConvertFrom-Json
    }
    catch {
        return $null
    }
}

function ConvertTo-PlainAccessToken {
    [CmdletBinding()]
    param(
        [AllowNull()]$Token
    )

    if ($null -eq $Token) {
        return $null
    }

    if ($Token -is [securestring]) {
        $ptr = [IntPtr]::Zero
        try {
            $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token)
            return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        }
        finally {
            if ($ptr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
            }
        }
    }

    return [string]$Token
}

function New-AccountSummary {
    [CmdletBinding()]
    param(
        [AllowNull()]$Session,
        [AllowNull()]$Entra
    )

    function Get-ReviewValue {
        param(
            [AllowNull()]$Object,
            [Parameter(Mandatory)][string]$Name
        )

        if ($null -eq $Object) {
            return $null
        }

        if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name)) {
            return $Object[$Name]
        }

        if ($Object.PSObject.Properties.Name -contains $Name) {
            return $Object.$Name
        }

        return $null
    }

    $activeContext = Get-ReviewValue -Object $Session -Name "active_context"

    $currentUser = $null
    $tokenClaims = $null
    if ($Entra) {
        $currentUser = Get-ReviewValue -Object $Entra -Name "current_user"
        $tokenClaims = Get-ReviewValue -Object $Entra -Name "token_claims"
    }

    [ordered]@{
        display_name = if (Get-ReviewValue -Object $currentUser -Name "displayName") { Get-ReviewValue -Object $currentUser -Name "displayName" } elseif (Get-ReviewValue -Object $tokenClaims -Name "name") { Get-ReviewValue -Object $tokenClaims -Name "name" } else { $null }
        user_principal_name = if (Get-ReviewValue -Object $currentUser -Name "userPrincipalName") { Get-ReviewValue -Object $currentUser -Name "userPrincipalName" } elseif (Get-ReviewValue -Object $tokenClaims -Name "upn") { Get-ReviewValue -Object $tokenClaims -Name "upn" } elseif (Get-ReviewValue -Object $tokenClaims -Name "preferred_username") { Get-ReviewValue -Object $tokenClaims -Name "preferred_username" } else { $null }
        user_id = if (Get-ReviewValue -Object $currentUser -Name "id") { Get-ReviewValue -Object $currentUser -Name "id" } elseif (Get-ReviewValue -Object $tokenClaims -Name "oid") { Get-ReviewValue -Object $tokenClaims -Name "oid" } else { $null }
        tenant_id = if (Get-ReviewValue -Object $tokenClaims -Name "tid") { Get-ReviewValue -Object $tokenClaims -Name "tid" } elseif ($activeContext -and (Get-ReviewValue -Object (Get-ReviewValue -Object $activeContext -Name "Tenant") -Name "Id")) { Get-ReviewValue -Object (Get-ReviewValue -Object $activeContext -Name "Tenant") -Name "Id" } else { $null }
        tenant_display = if ($activeContext -and (Get-ReviewValue -Object (Get-ReviewValue -Object $activeContext -Name "Tenant") -Name "Name")) { Get-ReviewValue -Object (Get-ReviewValue -Object $activeContext -Name "Tenant") -Name "Name" } else { $null }
        azure_context_account = if ($activeContext -and (Get-ReviewValue -Object (Get-ReviewValue -Object $activeContext -Name "Account") -Name "Id")) { Get-ReviewValue -Object (Get-ReviewValue -Object $activeContext -Name "Account") -Name "Id" } else { $null }
        azure_context_subscription = if ($activeContext -and (Get-ReviewValue -Object (Get-ReviewValue -Object $activeContext -Name "Subscription") -Name "Id")) { Get-ReviewValue -Object (Get-ReviewValue -Object $activeContext -Name "Subscription") -Name "Id" } else { $null }
        graph_token_app_id = if (Get-ReviewValue -Object $tokenClaims -Name "appid") { Get-ReviewValue -Object $tokenClaims -Name "appid" } elseif (Get-ReviewValue -Object $tokenClaims -Name "azp") { Get-ReviewValue -Object $tokenClaims -Name "azp" } else { $null }
        graph_token_scopes = if (Get-ReviewValue -Object $tokenClaims -Name "scp") { Get-ReviewValue -Object $tokenClaims -Name "scp" } else { $null }
        graph_token_roles = if (Get-ReviewValue -Object $tokenClaims -Name "roles") { @(Get-ReviewValue -Object $tokenClaims -Name "roles") } else { @() }
    }
}

function Add-AccessReviewRawData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowNull()]$Data
    )

    $path = Join-Path $State.RawPath "$Name.json"
    Write-AccessReviewJson -Path $path -Data $Data
    return $path
}

function Add-AccessReviewFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][ValidateSet("Info","Low","Medium","High","Critical")][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Description,
        [string]$Evidence,
        [string]$Recommendation,
        [string]$Category = "General"
    )

    $State.Findings.Add([pscustomobject]@{
        severity = $Severity
        category = $Category
        title = $Title
        description = $Description
        evidence = $Evidence
        recommendation = $Recommendation
    }) | Out-Null
}

function Invoke-AccessReviewCollector {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )

    $started = Get-Date
    Write-Host "[$($started.ToString("HH:mm:ss"))] Coletor: $Name"

    try {
        & $ScriptBlock
        $status = "Succeeded"
        $errorMessage = $null
    }
    catch {
        $status = "Failed"
        $errorMessage = $_.Exception.Message
        $errorDetails = [ordered]@{
            message = $_.Exception.Message
            exception_type = $_.Exception.GetType().FullName
            script_stack_trace = $_.ScriptStackTrace
            position = if ($_.InvocationInfo) { $_.InvocationInfo.PositionMessage } else { $null }
        }
        $errorEvidence = ($errorDetails | ConvertTo-Json -Depth 6 -Compress)
        Add-AccessReviewFinding -State $State -Severity "Medium" -Category "Collector" -Title "Falha no coletor $Name" -Description "O coletor falhou e parte da visibilidade pode estar incompleta." -Evidence $errorEvidence -Recommendation "Revise permissoes, modulos instalados e autenticacao antes de usar o resultado como conclusivo."
        Write-Warning "Coletor $Name falhou: $errorMessage"
    }
    finally {
        $ended = Get-Date
        $State.Collectors.Add([pscustomobject]@{
            name = $Name
            status = $status
            started_at_utc = $started.ToUniversalTime().ToString("o")
            ended_at_utc = $ended.ToUniversalTime().ToString("o")
            duration_seconds = [math]::Round(($ended - $started).TotalSeconds, 2)
            error = $errorMessage
            error_details = if ($status -eq "Failed") { $errorDetails } else { $null }
        }) | Out-Null
    }
}

function Test-CommandAvailable {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-AccessCapabilityFromActions {
    [CmdletBinding()]
    param([string[]]$Actions)

    $actionsText = (@($Actions) -join "`n").ToLowerInvariant()

    [pscustomobject]@{
        can_manage_rbac = ($actionsText -match "microsoft.authorization/roleassignments/write" -or $actionsText -match "\*")
        can_manage_resources = ($actionsText -match "/write" -or $actionsText -match "/delete" -or $actionsText -match "\*")
        can_read_keyvault_metadata = ($actionsText -match "microsoft.keyvault/vaults/read" -or $actionsText -match "\*")
        can_manage_keyvault = ($actionsText -match "microsoft.keyvault/.*write" -or $actionsText -match "microsoft.keyvault/.*delete" -or $actionsText -match "\*")
        can_manage_storage = ($actionsText -match "microsoft.storage/.*write" -or $actionsText -match "microsoft.storage/.*delete" -or $actionsText -match "\*")
        can_manage_compute = ($actionsText -match "microsoft.compute/.*write" -or $actionsText -match "microsoft.compute/.*delete" -or $actionsText -match "\*")
        has_wildcard_action = ($actionsText -match "(^|`n)\*($|`n)" -or $actionsText -match "/\*")
    }
}

Export-ModuleMember -Function *
