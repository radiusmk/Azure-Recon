[CmdletBinding()]
param(
    [Parameter(Mandatory)]$State,
    [switch]$SkipGraph,
    [switch]$SkipResourceEnumeration,
    [ValidateSet("Auto","Rest","Sdk","ExplorerExport")]
    [string]$GraphMode = "Auto",
    [switch]$GraphAccessTokenPresent,
    [string]$GraphExplorerExportPath
)

$requiredAzModules = @(
    "Az.Accounts",
    "Az.Resources",
    "Az.KeyVault",
    "Az.Storage",
    "Az.Compute",
    "Az.Network"
)

$requiredGraphModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Applications",
    "Microsoft.Graph.Identity.DirectoryManagement"
)

if ($SkipResourceEnumeration) {
    $requiredAzModules = @("Az.Accounts", "Az.Resources")
}

$includeGraphSdkModules = [bool](-not $SkipGraph -and $GraphMode -in @("Auto","Sdk"))
$moduleChecks = New-Object System.Collections.Generic.List[object]
foreach ($moduleName in @($requiredAzModules + $(if ($includeGraphSdkModules) { $requiredGraphModules } else { @() }))) {
    $available = @(Get-Module -ListAvailable -Name $moduleName | Sort-Object Version -Descending)
    $moduleChecks.Add([pscustomobject]@{
        name = $moduleName
        installed = [bool]($available.Count -gt 0)
        version = if ($available.Count -gt 0) { $available[0].Version.ToString() } else { $null }
        module_base = if ($available.Count -gt 0) { $available[0].ModuleBase } else { $null }
    }) | Out-Null
}

$missing = @($moduleChecks | Where-Object { -not $_.installed } | Select-Object -ExpandProperty Name)
$azMissing = @($requiredAzModules | Where-Object { $missing -contains $_ })
$graphMissing = if ($includeGraphSdkModules) { @($requiredGraphModules | Where-Object { $missing -contains $_ }) } else { @() }
$azAccountsAvailable = -not ($missing -contains "Az.Accounts")
$graphSdkAvailable = [bool]($SkipGraph -or ($includeGraphSdkModules -and $graphMissing.Count -eq 0))
$graphRestAvailable = [bool]($SkipGraph -or $GraphAccessTokenPresent -or $azAccountsAvailable)
$graphExplorerExportAvailable = [bool](-not [string]::IsNullOrWhiteSpace($GraphExplorerExportPath) -and (Test-Path -LiteralPath $GraphExplorerExportPath -PathType Leaf))

$prereqData = [ordered]@{
    module_checks = @($moduleChecks | ForEach-Object { ConvertTo-PlainObject $_ })
    missing_modules = $missing
    install_commands = [ordered]@{
        az = "Install-Module Az -Scope CurrentUser"
        graph = "Install-Module Microsoft.Graph -Scope CurrentUser"
    }
    capabilities = [ordered]@{
        az_available = [bool]($azMissing.Count -eq 0)
        az_accounts_available = $azAccountsAvailable
        graph_sdk_available = $graphSdkAvailable
        graph_rest_available = $graphRestAvailable
        graph_rest_token_source = if ($GraphAccessTokenPresent) { "provided_token" } elseif ($azAccountsAvailable) { "Az.Accounts Get-AzAccessToken" } else { "none" }
        graph_explorer_export_available = $graphExplorerExportAvailable
    }
    selected_graph_mode = $GraphMode
    notes = @(
        "PowerShell pode exigir Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force para executar scripts locais.",
        "Instalacao de modulos requer acesso a PSGallery ou repositorio interno equivalente.",
        "Graph REST evita o SDK Microsoft.Graph, mas ainda precisa de um token delegado valido para https://graph.microsoft.com."
    )
}

Add-AccessReviewRawData -State $State -Name "prerequisites" -Data $prereqData | Out-Null
$State.Data.prerequisites = $prereqData

if ($missing.Count -gt 0) {
    Add-AccessReviewFinding -State $State -Severity "High" -Category "Prerequisites" -Title "Modulos PowerShell obrigatorios ausentes" -Description "A coleta completa nao pode ser executada ate que os modulos PowerShell obrigatorios estejam instalados." -Evidence "Ausentes: $($missing -join ', ')" -Recommendation "Instale os modulos com os comandos registrados em data.prerequisites.install_commands ou use um repositorio interno aprovado."
}

if (-not $SkipGraph -and $GraphMode -ne "Sdk" -and $graphRestAvailable) {
    Add-AccessReviewFinding -State $State -Severity "Info" -Category "Graph" -Title "Graph REST disponivel como alternativa ao SDK/CLI" -Description "O toolkit pode consultar Microsoft Graph por Invoke-RestMethod, sem carregar os modulos Microsoft.Graph." -Evidence "Fonte de token: $($prereqData.capabilities.graph_rest_token_source)" -Recommendation "Use este modo quando o aplicativo/cliente do SDK ou CLI estiver bloqueado, validando previamente que o token delegado tem escopos aprovados."
}
