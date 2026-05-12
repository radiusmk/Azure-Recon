[CmdletBinding()]
param(
    [Parameter(Mandatory)]$State,
    [Parameter(Mandatory)][string]$GraphExplorerExportPath
)

if (-not (Test-Path -LiteralPath $GraphExplorerExportPath -PathType Leaf)) {
    throw "Arquivo de export do Graph Explorer nao encontrado: $GraphExplorerExportPath"
}

$export = Get-Content -LiteralPath $GraphExplorerExportPath -Raw | ConvertFrom-Json

function Get-ExportValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$ExportObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($ExportObject.PSObject.Properties.Name -notcontains $Name) {
        return @()
    }

    $value = $ExportObject.$Name
    if ($null -eq $value) {
        return @()
    }

    if ($value.PSObject.Properties.Name -contains "value") {
        return @($value.value)
    }

    return $value
}

$me = Get-ExportValue -ExportObject $export -Name "me"
$org = Get-ExportValue -ExportObject $export -Name "organization"
$memberOf = Get-ExportValue -ExportObject $export -Name "memberOf"
$ownedObjects = Get-ExportValue -ExportObject $export -Name "ownedObjects"
$directoryRoles = Get-ExportValue -ExportObject $export -Name "directoryRoles"
$applications = Get-ExportValue -ExportObject $export -Name "applications"
$servicePrincipals = Get-ExportValue -ExportObject $export -Name "servicePrincipals"

$graphData = [ordered]@{
    method = "graph_explorer_export"
    source_file = (Resolve-Path -LiteralPath $GraphExplorerExportPath).Path
    current_user = ConvertTo-PlainObject $me
    organizations = @($org | ForEach-Object { ConvertTo-PlainObject $_ })
    member_of = @($memberOf | ForEach-Object { ConvertTo-PlainObject $_ })
    owned_objects = @($ownedObjects | ForEach-Object { ConvertTo-PlainObject $_ })
    visible_directory_roles = @($directoryRoles | ForEach-Object { ConvertTo-PlainObject $_ })
    visible_applications_sample = @($applications | ForEach-Object { ConvertTo-PlainObject $_ })
    visible_service_principals_sample = @($servicePrincipals | ForEach-Object { ConvertTo-PlainObject $_ })
    notes = @(
        "Dados importados de arquivo JSON salvo manualmente a partir do Graph Explorer ou ferramenta equivalente.",
        "O arquivo deve conter propriedades como me, organization, memberOf, ownedObjects, directoryRoles, applications e servicePrincipals."
    )
}

Add-AccessReviewRawData -State $State -Name "entra-graph-explorer-export" -Data $graphData | Out-Null
$State.Data.entra = $graphData

if (@($ownedObjects).Count -gt 0) {
    Add-AccessReviewFinding -State $State -Severity "Medium" -Category "Entra ID" -Title "Conta possui objetos Entra ID sob sua propriedade" -Description "Objetos pertencentes ao usuario podem permitir alteracoes em aplicacoes, service principals ou grupos dependendo do tipo do objeto e das politicas do tenant." -Evidence "$(@($ownedObjects).Count) objeto(s) importado(s) do export do Graph Explorer." -Recommendation "Revise proprietarios de apps, service principals e grupos. Remova ownership desnecessario e aplique processos de aprovacao para objetos privilegiados."
}
