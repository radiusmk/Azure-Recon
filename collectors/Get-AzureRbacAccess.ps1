[CmdletBinding()]
param(
    [Parameter(Mandatory)]$State,
    [string[]]$TenantIds,
    [string[]]$SubscriptionIds
)

Import-Module Az.Accounts -ErrorAction Stop
Import-Module Az.Resources -ErrorAction Stop
$WarningPreference = "SilentlyContinue"

$subscriptions = @()
try {
    $allSubscriptions = @(Get-AzSubscription -ErrorAction Stop)
    if ($TenantIds) {
        $allSubscriptions = @($allSubscriptions | Where-Object { $TenantIds -contains $_.TenantId })
    }
    if ($SubscriptionIds) {
        $allSubscriptions = @($allSubscriptions | Where-Object { $SubscriptionIds -contains $_.Id })
    }
    $subscriptions = $allSubscriptions
}
catch {
    Add-AccessReviewFinding -State $State -Severity "High" -Category "Azure RBAC" -Title "Nao foi possivel listar subscriptions" -Description "A conta nao conseguiu listar subscriptions ou a sessao Azure nao esta autenticada." -Evidence $_.Exception.Message -Recommendation "Confirme autenticacao com Connect-AzAccount e se a conta deveria ter visibilidade de subscriptions."
}

$subscriptionResults = New-Object System.Collections.Generic.List[object]
$allAssignments = New-Object System.Collections.Generic.List[object]
$allRoleDefinitions = New-Object System.Collections.Generic.List[object]

foreach ($subscription in $subscriptions) {
    try {
        Set-AzContext -SubscriptionId $subscription.Id -TenantId $subscription.TenantId -ErrorAction Stop | Out-Null

        $assignments = @(Get-AzRoleAssignment -Scope "/subscriptions/$($subscription.Id)" -ErrorAction SilentlyContinue)
        $roleDefinitions = @(Get-AzRoleDefinition -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
        $resourceGroups = @(Get-AzResourceGroup -ErrorAction SilentlyContinue | Select-Object ResourceGroupName, Location, ProvisioningState, ResourceId)

        foreach ($assignment in $assignments) {
            $allAssignments.Add($assignment) | Out-Null
        }
        foreach ($definition in $roleDefinitions) {
            $allRoleDefinitions.Add($definition) | Out-Null
        }

        $subscriptionResults.Add([pscustomobject]@{
            id = $subscription.Id
            name = $subscription.Name
            tenant_id = $subscription.TenantId
            state = $subscription.State
            role_assignments_visible = @($assignments | ForEach-Object { ConvertTo-PlainObject $_ })
            role_definitions_visible = @($roleDefinitions | Select-Object Name, Id, IsCustom, Description, Actions, NotActions, DataActions, NotDataActions | ForEach-Object { ConvertTo-PlainObject $_ })
            resource_groups_visible = @($resourceGroups | ForEach-Object { ConvertTo-PlainObject $_ })
        }) | Out-Null
    }
    catch {
        $subscriptionResults.Add([pscustomobject]@{
            id = $subscription.Id
            name = $subscription.Name
            tenant_id = $subscription.TenantId
            state = $subscription.State
            error = $_.Exception.Message
        }) | Out-Null
    }
}

$effectiveRoleNames = @($allAssignments | Select-Object -ExpandProperty RoleDefinitionName -Unique | Sort-Object)
$visibleRoleDefinitionsByName = @{}
foreach ($roleDefinition in $allRoleDefinitions) {
    if (-not $visibleRoleDefinitionsByName.ContainsKey($roleDefinition.Name)) {
        $visibleRoleDefinitionsByName[$roleDefinition.Name] = $roleDefinition
    }
}

$capabilities = New-Object System.Collections.Generic.List[object]
foreach ($roleName in $effectiveRoleNames) {
    $definition = $visibleRoleDefinitionsByName[$roleName]
    if ($definition) {
        $capability = Get-AccessCapabilityFromActions -Actions @($definition.Actions + $definition.DataActions)
        $capabilities.Add([pscustomobject]@{
            role = $roleName
            is_custom = [bool]$definition.IsCustom
            capability = $capability
        }) | Out-Null
    }
}

$rbacData = [ordered]@{
    subscriptions_visible_count = $subscriptions.Count
    subscriptions = @($subscriptionResults | ForEach-Object { ConvertTo-PlainObject $_ })
    effective_role_names = $effectiveRoleNames
    effective_role_capabilities = @($capabilities | ForEach-Object { ConvertTo-PlainObject $_ })
}

Add-AccessReviewRawData -State $State -Name "azure-rbac-access" -Data $rbacData | Out-Null
$State.Data.rbac = $rbacData

foreach ($capabilityRow in $capabilities) {
    if ($capabilityRow.capability.can_manage_rbac) {
        Add-AccessReviewFinding -State $State -Severity "Critical" -Category "Azure RBAC" -Title "Conta aparenta poder alterar atribuicoes RBAC" -Description "A role '$($capabilityRow.role)' inclui acoes que podem permitir concessao, remocao ou escalacao de privilegios via RBAC." -Evidence "Role: $($capabilityRow.role)" -Recommendation "Restrinja roles como Owner, User Access Administrator ou custom roles com Microsoft.Authorization/roleAssignments/write. Use PIM, MFA forte e revisoes periodicas."
    }
    elseif ($capabilityRow.capability.has_wildcard_action) {
        Add-AccessReviewFinding -State $State -Severity "High" -Category "Azure RBAC" -Title "Conta possui role com wildcard de acoes" -Description "A role '$($capabilityRow.role)' contem wildcard em Actions/DataActions, ampliando muito o conjunto de operacoes permitidas." -Evidence "Role: $($capabilityRow.role)" -Recommendation "Substitua roles amplas por roles minimas e custom roles sem wildcard sempre que viavel."
    }
}

