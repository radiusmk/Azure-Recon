[CmdletBinding()]
param(
    [Parameter(Mandatory)]$State,
    [string[]]$TenantIds,
    [switch]$UseExistingSessionOnly
)

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Users -ErrorAction Stop
Import-Module Microsoft.Graph.Groups -ErrorAction Stop
Import-Module Microsoft.Graph.Applications -ErrorAction Stop
Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop

$requestedScopes = @(
    "User.Read",
    "Directory.Read.All",
    "Group.Read.All",
    "Application.Read.All",
    "RoleManagement.Read.Directory"
)

if (-not $UseExistingSessionOnly) {
    $graphContext = Get-MgContext
    if (-not $graphContext) {
        Connect-MgGraph -Scopes $requestedScopes -NoWelcome | Out-Null
    }
}

$context = Get-MgContext
$currentUserId = if ($context -and $context.Account) { $context.Account } else { "me" }
$me = $null
$org = @()
$memberOf = @()
$ownedObjects = @()
$directoryRoles = @()
$applications = @()
$servicePrincipals = @()

try { $me = Get-MgUser -UserId $currentUserId -Property "id,displayName,userPrincipalName,accountEnabled,createdDateTime,userType,assignedLicenses" } catch {}
try { $org = @(Get-MgOrganization -All -Property "id,displayName,verifiedDomains") } catch {}
try { $memberOf = @(Get-MgUserMemberOf -UserId $currentUserId -All | Select-Object Id, DeletedDateTime, AdditionalProperties) } catch {}
try { $ownedObjects = @(Get-MgUserOwnedObject -UserId $currentUserId -All | Select-Object Id, DeletedDateTime, AdditionalProperties) } catch {}
try { $directoryRoles = @(Get-MgDirectoryRole -All | Select-Object Id, DisplayName, Description, RoleTemplateId) } catch {}
try { $applications = @(Get-MgApplication -All -Top 100 | Select-Object Id, AppId, DisplayName, SignInAudience, PublisherDomain) } catch {}
try { $servicePrincipals = @(Get-MgServicePrincipal -All -Top 100 | Select-Object Id, AppId, DisplayName, ServicePrincipalType, AccountEnabled) } catch {}

$graphData = [ordered]@{
    context = ConvertTo-PlainObject $context
    current_user = ConvertTo-PlainObject $me
    organizations = @($org | ForEach-Object { ConvertTo-PlainObject $_ })
    member_of = @($memberOf | ForEach-Object { ConvertTo-PlainObject $_ })
    owned_objects = @($ownedObjects | ForEach-Object { ConvertTo-PlainObject $_ })
    visible_directory_roles = @($directoryRoles | ForEach-Object { ConvertTo-PlainObject $_ })
    visible_applications_sample = @($applications | ForEach-Object { ConvertTo-PlainObject $_ })
    visible_service_principals_sample = @($servicePrincipals | ForEach-Object { ConvertTo-PlainObject $_ })
    notes = @(
        "Amostras de applications e service principals limitadas a 100 itens para reduzir volume.",
        "Falhas parciais normalmente indicam ausencia de consentimento ou permissao Graph insuficiente."
    )
}

Add-AccessReviewRawData -State $State -Name "entra-graph-access" -Data $graphData | Out-Null
$State.Data.entra = $graphData

if ($ownedObjects.Count -gt 0) {
    Add-AccessReviewFinding -State $State -Severity "Medium" -Category "Entra ID" -Title "Conta possui objetos Entra ID sob sua propriedade" -Description "Objetos pertencentes ao usuario podem permitir alteracoes em aplicacoes, service principals ou grupos dependendo do tipo do objeto e das politicas do tenant." -Evidence "$($ownedObjects.Count) objeto(s) retornado(s) por Get-MgUserOwnedObject." -Recommendation "Revise proprietarios de apps, service principals e grupos. Remova ownership desnecessario e aplique processos de aprovacao para objetos privilegiados."
}
