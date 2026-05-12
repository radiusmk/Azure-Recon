[CmdletBinding()]
param(
    [string[]]$TenantIds,
    [string[]]$SubscriptionIds,
    [string]$OutputRoot = ".\reports",
    [switch]$DeepEnumerate,
    [switch]$UseExistingSessionOnly,
    [switch]$ForceLogin,
    [switch]$UseDeviceCode,
    [switch]$ClearAzContext,
    [switch]$PreserveAzContext,
    [string]$ExpectedAccountUpn,
    [switch]$SkipGraph,
    [switch]$SkipResourceEnumeration,
    [int]$PrivilegedAccountLimit = 200,
    [ValidateSet("Auto","Rest","Sdk","ExplorerExport")]
    [string]$GraphMode = "Auto",
    [string]$GraphAccessToken,
    [string]$GraphExplorerExportPath,
    [string]$GraphBaseUri = "https://graph.microsoft.com/v1.0"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $scriptRoot "modules\AccessReview.Common.psm1") -Force

$timestamp = "$(Get-Date -Format "yyyyMMdd-HHmmss-fff")-$([guid]::NewGuid().ToString("N").Substring(0, 6))"
$outputPath = New-Item -ItemType Directory -Path (Join-Path $OutputRoot "azure-access-review-$timestamp") -Force
$rawPath = New-Item -ItemType Directory -Path (Join-Path $outputPath.FullName "raw") -Force

$state = New-AccessReviewState -OutputPath $outputPath.FullName -RawPath $rawPath.FullName -DeepEnumerate:$DeepEnumerate.IsPresent

Write-Host "Azure Access Review Toolkit" -ForegroundColor Cyan
Write-Host "Output: $($outputPath.FullName)"

$isolateAzAuthentication = [bool](-not $UseExistingSessionOnly -and ($ForceLogin -or -not $PreserveAzContext))
if ($PreserveAzContext) {
    $isolateAzAuthentication = $false
}
$effectiveClearAzContext = [bool]($ClearAzContext -or $isolateAzAuthentication)

Invoke-AccessReviewCollector -Name "Prerequisites" -State $state -ScriptBlock {
    & (Join-Path $scriptRoot "collectors\Test-Prerequisites.ps1") -State $state -SkipGraph:$SkipGraph -SkipResourceEnumeration:$SkipResourceEnumeration -GraphMode $GraphMode -GraphAccessTokenPresent:([bool]($GraphAccessToken -or $env:AZURE_ACCESS_REVIEW_GRAPH_TOKEN)) -GraphExplorerExportPath $GraphExplorerExportPath
}

$azAvailable = $false
$graphSdkAvailable = $false
$graphRestAvailable = $false
$graphExplorerExportAvailable = $false
if ($state.Data.Contains("prerequisites")) {
    $azAvailable = [bool]$state.Data.prerequisites.capabilities.az_available
    $graphSdkAvailable = [bool]$state.Data.prerequisites.capabilities.graph_sdk_available
    $graphRestAvailable = [bool]$state.Data.prerequisites.capabilities.graph_rest_available
    $graphExplorerExportAvailable = [bool]$state.Data.prerequisites.capabilities.graph_explorer_export_available
}

if ($azAvailable) {
    Invoke-AccessReviewCollector -Name "SessionContext" -State $state -ScriptBlock {
        Import-Module Az.Accounts -ErrorAction Stop

        if (-not $UseExistingSessionOnly) {
            if ($effectiveClearAzContext) {
                Write-Host "Limpando contexto Az do processo antes da autenticacao desta execucao." -ForegroundColor Yellow
                Clear-AzContext -Scope Process -Force -ErrorAction SilentlyContinue | Out-Null
            }

            $existingContext = Get-AzContext -ErrorAction SilentlyContinue
            if ($ForceLogin -or -not $existingContext) {
                if ($UseDeviceCode) {
                    Write-Host "Chamando Connect-AzAccount com device code. Siga as instrucoes exibidas no terminal." -ForegroundColor Yellow
                    Connect-AzAccount -UseDeviceAuthentication -ErrorAction Stop | Out-Null
                }
                else {
                    Write-Host "Chamando Connect-AzAccount interativo. Uma janela de login pode abrir fora deste terminal." -ForegroundColor Yellow
                    Connect-AzAccount -ErrorAction Stop | Out-Null
                }
            }
            else {
                Write-Host "Login interativo nao chamado: contexto Az existente encontrado e -PreserveAzContext foi usado." -ForegroundColor DarkYellow
            }
        }

        $contexts = Get-AzContext -ListAvailable -ErrorAction SilentlyContinue
        $activeContext = Get-AzContext -ErrorAction SilentlyContinue

        $session = [ordered]@{
            active_context = ConvertTo-PlainObject $activeContext
            available_contexts = @($contexts | ForEach-Object { ConvertTo-PlainObject $_ })
            tenant_filter = @($TenantIds)
            subscription_filter = @($SubscriptionIds)
            use_existing_session_only = [bool]$UseExistingSessionOnly
        }

        Add-AccessReviewRawData -State $state -Name "session-context" -Data $session
        $state.Data.session = $session
    }
}

if (-not $azAvailable) {
    Add-AccessReviewFinding -State $state -Severity "High" -Category "Prerequisites" -Title "Coletores Azure ignorados por modulos Az ausentes" -Description "Os coletores que dependem de Az.Accounts nao foram executados porque os modulos Az necessarios nao estao instalados ou nao estao no PSModulePath." -Evidence "Instale o modulo Az ou os submodulos listados em prerequisites.missing_modules." -Recommendation "Execute Install-Module Az -Scope CurrentUser em uma sessao PowerShell com acesso a PSGallery."
}

if (-not $SkipGraph -and $GraphMode -eq "Sdk" -and -not $graphSdkAvailable) {
    Add-AccessReviewFinding -State $state -Severity "High" -Category "Prerequisites" -Title "Coletor Entra/Graph SDK ignorado por modulos Microsoft.Graph ausentes" -Description "A coleta Entra ID/Graph via SDK nao foi executada porque os modulos Microsoft.Graph necessarios nao estao instalados ou nao estao no PSModulePath." -Evidence "Instale os modulos Microsoft.Graph listados em prerequisites.missing_modules." -Recommendation "Use -GraphMode Rest para evitar o SDK ou execute Install-Module Microsoft.Graph -Scope CurrentUser em uma sessao PowerShell com acesso a PSGallery."
}

if (-not $SkipGraph -and $GraphMode -eq "Rest" -and -not $graphRestAvailable) {
    Add-AccessReviewFinding -State $state -Severity "High" -Category "Prerequisites" -Title "Coletor Entra/Graph REST sem fonte de token" -Description "A coleta Graph REST precisa de Az.Accounts para obter token delegado ou de um token Graph fornecido explicitamente." -Evidence "Az.Accounts ausente e nenhum GraphAccessToken foi informado." -Recommendation "Instale Az.Accounts ou execute com -GraphAccessToken/variavel AZURE_ACCESS_REVIEW_GRAPH_TOKEN usando token delegado aprovado para auditoria."
}

if (-not $SkipGraph -and $GraphMode -eq "ExplorerExport" -and -not $graphExplorerExportAvailable) {
    Add-AccessReviewFinding -State $state -Severity "High" -Category "Prerequisites" -Title "Export do Graph Explorer nao encontrado" -Description "O modo ExplorerExport precisa de um arquivo JSON local com respostas exportadas do Graph Explorer." -Evidence "Caminho informado: $GraphExplorerExportPath" -Recommendation "Crie o arquivo seguindo o modelo documentado no README ou use -GraphMode Rest com token delegado aprovado."
}

if (-not $SkipGraph -and $GraphMode -eq "Auto" -and -not $graphRestAvailable -and -not $graphSdkAvailable) {
    Add-AccessReviewFinding -State $state -Severity "High" -Category "Prerequisites" -Title "Coletor Entra/Graph sem caminho disponivel" -Description "Nenhum caminho Graph esta disponivel: REST nao tem fonte de token e o SDK Microsoft.Graph nao esta instalado." -Evidence "Revise prerequisites.capabilities." -Recommendation "Prefira -GraphMode Rest com Az.Accounts ou token delegado; use -GraphMode Sdk apenas se o SDK Microsoft.Graph for permitido."
}

if (-not $SkipGraph -and $graphExplorerExportAvailable -and ($GraphMode -eq "ExplorerExport" -or ($GraphMode -eq "Auto" -and $GraphExplorerExportPath))) {
    Invoke-AccessReviewCollector -Name "EntraGraphExplorerExport" -State $state -ScriptBlock {
        & (Join-Path $scriptRoot "collectors\Import-GraphExplorerExport.ps1") -State $state -GraphExplorerExportPath $GraphExplorerExportPath
    }
}
elseif (-not $SkipGraph -and $graphRestAvailable -and ($GraphMode -eq "Rest" -or ($GraphMode -eq "Auto" -and $graphRestAvailable))) {
    Invoke-AccessReviewCollector -Name "EntraGraphRest" -State $state -ScriptBlock {
        & (Join-Path $scriptRoot "collectors\Get-EntraGraphRestAccess.ps1") -State $state -TenantIds $TenantIds -UseExistingSessionOnly:$UseExistingSessionOnly -ForceLogin:$ForceLogin -UseDeviceCode:$UseDeviceCode -ClearAzContext:$effectiveClearAzContext -ExpectedAccountUpn $ExpectedAccountUpn -GraphAccessToken $GraphAccessToken -GraphBaseUri $GraphBaseUri -DeepEnumerate:$DeepEnumerate -PrivilegedAccountLimit $PrivilegedAccountLimit
    }
}
elseif (-not $SkipGraph -and ($GraphMode -eq "Sdk" -or ($GraphMode -eq "Auto" -and $graphSdkAvailable))) {
    Invoke-AccessReviewCollector -Name "EntraGraphSdk" -State $state -ScriptBlock {
        & (Join-Path $scriptRoot "collectors\Get-EntraGraphAccess.ps1") -State $state -TenantIds $TenantIds -UseExistingSessionOnly:$UseExistingSessionOnly
    }
}

if ($azAvailable) {
    Invoke-AccessReviewCollector -Name "AzureSubscriptionsAndRbac" -State $state -ScriptBlock {
        & (Join-Path $scriptRoot "collectors\Get-AzureRbacAccess.ps1") -State $state -TenantIds $TenantIds -SubscriptionIds $SubscriptionIds
    }
}

if (-not $SkipResourceEnumeration -and $azAvailable) {
    Invoke-AccessReviewCollector -Name "AzureResources" -State $state -ScriptBlock {
        & (Join-Path $scriptRoot "collectors\Get-AzureResourceAccess.ps1") -State $state -SubscriptionIds $SubscriptionIds -DeepEnumerate:$DeepEnumerate
    }
}

Invoke-AccessReviewCollector -Name "Report" -State $state -ScriptBlock {
    & (Join-Path $scriptRoot "reporting\New-AccessReviewReport.ps1") -State $state
}

$metadata = [ordered]@{
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    output_path = $outputPath.FullName
    powershell_version = $PSVersionTable.PSVersion.ToString()
    parameters = [ordered]@{
        tenant_ids = @($TenantIds)
        subscription_ids = @($SubscriptionIds)
        deep_enumerate = [bool]$DeepEnumerate
        use_existing_session_only = [bool]$UseExistingSessionOnly
        force_login = [bool]$ForceLogin
        use_device_code = [bool]$UseDeviceCode
        clear_az_context = [bool]$effectiveClearAzContext
        preserve_az_context = [bool]$PreserveAzContext
        expected_account_upn = $ExpectedAccountUpn
        skip_graph = [bool]$SkipGraph
        skip_resource_enumeration = [bool]$SkipResourceEnumeration
        privileged_account_limit = $PrivilegedAccountLimit
        graph_mode = $GraphMode
        graph_base_uri = $GraphBaseUri
        graph_access_token_supplied = [bool]$GraphAccessToken
        graph_explorer_export_path_supplied = [bool]$GraphExplorerExportPath
    }
}

Add-AccessReviewRawData -State $state -Name "run-metadata" -Data $metadata

Write-Host ""
Write-Host "Concluido." -ForegroundColor Green
Write-Host "Markdown: $($state.ReportMarkdownPath)"
Write-Host "JSON:     $($state.ReportJsonPath)"
