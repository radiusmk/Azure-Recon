[CmdletBinding()]
param(
    [Parameter(Mandatory)]$State,
    [string[]]$TenantIds,
    [switch]$UseExistingSessionOnly,
    [switch]$ForceLogin,
    [switch]$UseDeviceCode,
    [switch]$ClearAzContext,
    [string]$ExpectedAccountUpn,
    [string]$GraphAccessToken,
    [string]$GraphBaseUri = "https://graph.microsoft.com/v1.0",
    [switch]$DeepEnumerate,
    [int]$PrivilegedAccountLimit = 200,
    [switch]$EnumerateAllUsers,
    [int]$DirectorySampleSize = 100
)

$tokenSource = "provided_parameter"
$accessToken = $GraphAccessToken
$authDiagnostics = [ordered]@{
    token_source = $tokenSource
    used_existing_session_only = [bool]$UseExistingSessionOnly
    force_login = [bool]$ForceLogin
    use_device_code = [bool]$UseDeviceCode
    clear_az_context = [bool]$ClearAzContext
    expected_account_upn = $ExpectedAccountUpn
    login_attempted = $false
    login_reason = $null
    context_before = $null
    context_after = $null
    token_acquired = $false
    token_claims_available = $false
}

if ([string]::IsNullOrWhiteSpace($accessToken) -and -not [string]::IsNullOrWhiteSpace($env:AZURE_ACCESS_REVIEW_GRAPH_TOKEN)) {
    $accessToken = $env:AZURE_ACCESS_REVIEW_GRAPH_TOKEN
    $tokenSource = "environment_variable"
}

if ([string]::IsNullOrWhiteSpace($accessToken)) {
    Import-Module Az.Accounts -ErrorAction Stop
    $tokenSource = "Az.Accounts"
    $authDiagnostics.token_source = $tokenSource
    $authDiagnostics.context_before = ConvertTo-PlainObject (Get-AzContext -ErrorAction SilentlyContinue)

    if ($ClearAzContext) {
        Write-Host "Limpando contexto Az do processo antes de obter token Graph." -ForegroundColor Yellow
        Clear-AzContext -Scope Process -Force -ErrorAction SilentlyContinue | Out-Null
    }

    if (-not $UseExistingSessionOnly) {
        $existingContext = Get-AzContext -ErrorAction SilentlyContinue
        if ($ForceLogin -or -not $existingContext) {
            $authDiagnostics.login_attempted = $true
            $authDiagnostics.login_reason = if ($ForceLogin) { "ForceLogin" } else { "No existing Az context" }
            if ($UseDeviceCode) {
                Write-Host "Chamando Connect-AzAccount com device code. Copie o codigo exibido e autentique no endereco indicado." -ForegroundColor Yellow
                Connect-AzAccount -UseDeviceAuthentication -ErrorAction Stop | Out-Null
            }
            else {
                Write-Host "Chamando Connect-AzAccount interativo. Uma janela de login pode abrir fora deste terminal." -ForegroundColor Yellow
                Connect-AzAccount -ErrorAction Stop | Out-Null
            }
        }
        else {
            Write-Host "Login interativo nao chamado: contexto Az existente encontrado. Use -ForceLogin ou -ClearAzContext para forcar nova autenticacao." -ForegroundColor DarkYellow
        }
    }
    else {
        Write-Host "Login interativo nao chamado: -UseExistingSessionOnly foi informado." -ForegroundColor DarkYellow
    }

    $tokenResponse = $null
    try {
        $tokenResponse = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop
    }
    catch {
        if (-not $UseExistingSessionOnly -and -not $authDiagnostics.login_attempted) {
            $authDiagnostics.login_attempted = $true
            $authDiagnostics.login_reason = "Get-AzAccessToken failed with existing context"
            if ($UseDeviceCode) {
                Write-Host "Get-AzAccessToken falhou. Chamando Connect-AzAccount com device code." -ForegroundColor Yellow
                Connect-AzAccount -UseDeviceAuthentication -ErrorAction Stop | Out-Null
            }
            else {
                Write-Host "Get-AzAccessToken falhou. Chamando Connect-AzAccount interativo." -ForegroundColor Yellow
                Connect-AzAccount -ErrorAction Stop | Out-Null
            }
        }

        try {
            $tokenResponse = Get-AzAccessToken -ResourceTypeName MSGraph -ErrorAction Stop
        }
        catch {
            $tokenResponse = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop
        }
    }

    $accessToken = ConvertTo-PlainAccessToken -Token $tokenResponse.Token
    $authDiagnostics.context_after = ConvertTo-PlainObject (Get-AzContext -ErrorAction SilentlyContinue)
}

if ([string]::IsNullOrWhiteSpace($accessToken)) {
    throw "Nao foi possivel obter token para Microsoft Graph."
}

$authDiagnostics.token_acquired = $true
$tokenClaims = ConvertFrom-JwtPayload -Token $accessToken
$authDiagnostics.token_claims_available = [bool]$tokenClaims

function Get-TokenClaim {
    [CmdletBinding()]
    param(
        [AllowNull()]$Claims,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Claims) {
        return $null
    }

    if ($Claims.PSObject.Properties.Name -contains $Name) {
        return $Claims.$Name
    }

    return $null
}

$headers = @{
    Authorization = "Bearer $accessToken"
    ConsistencyLevel = "eventual"
}

$tokenAccountUpn = $null
if ($tokenClaims) {
    $tokenAccountUpn = Get-TokenClaim -Claims $tokenClaims -Name "upn"
    if ([string]::IsNullOrWhiteSpace($tokenAccountUpn)) {
        $tokenAccountUpn = Get-TokenClaim -Claims $tokenClaims -Name "preferred_username"
    }
}

if (-not [string]::IsNullOrWhiteSpace($ExpectedAccountUpn) -and -not [string]::IsNullOrWhiteSpace($tokenAccountUpn)) {
    if ($ExpectedAccountUpn.ToLowerInvariant() -ne $tokenAccountUpn.ToLowerInvariant()) {
        throw "Conta autenticada no token Graph ('$tokenAccountUpn') diferente da conta esperada ('$ExpectedAccountUpn'). Execute novamente e autentique com a conta correta."
    }
}

function Invoke-GraphRestGet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path
    )

    $uri = if ($Path -like "https://*") { $Path } else { "$GraphBaseUri$Path" }

    try {
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ErrorAction Stop
        return [pscustomobject]@{
            name = $Name
            uri = $uri
            status = "Succeeded"
            data = ConvertTo-PlainObject $response
            error = $null
        }
    }
    catch {
        return [pscustomobject]@{
            name = $Name
            uri = $uri
            status = "Failed"
            data = $null
            error = $_.Exception.Message
        }
    }
}

function Invoke-GraphRestCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxPages = 10
    )

    $originalUri = if ($Path -like "https://*") { [string]$Path } else { [string]::Concat($GraphBaseUri, $Path) }
    $uri = $originalUri
    $items = New-Object System.Collections.Generic.List[object]
    $pageCount = 0

    try {
        while (-not [string]::IsNullOrWhiteSpace($uri) -and $pageCount -lt $MaxPages) {
            $pageCount++
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ErrorAction Stop
            if ($response.PSObject.Properties.Name -contains "value") {
                foreach ($item in @($response.value)) {
                    $items.Add((ConvertTo-PlainObject $item)) | Out-Null
                }
            }
            elseif ($null -ne $response) {
                $items.Add((ConvertTo-PlainObject $response)) | Out-Null
            }

            if ($response.PSObject.Properties.Name -contains "@odata.nextLink") {
                $uri = $response.'@odata.nextLink'
            }
            else {
                $uri = $null
            }
        }

        return [pscustomobject]@{
            name = $Name
            uri = $originalUri
            status = "Succeeded"
            data = @($items | ForEach-Object { $_ })
            page_count = $pageCount
            truncated = [bool](-not [string]::IsNullOrWhiteSpace($uri))
            error = $null
        }
    }
    catch {
        return [pscustomobject]@{
            name = $Name
            uri = $originalUri
            status = "Failed"
            data = @($items | ForEach-Object { $_ })
            page_count = $pageCount
            truncated = $false
            error = $_.Exception.Message
        }
    }
}

function Get-GraphCountFromCollectionResult {
    [CmdletBinding()]
    param(
        [AllowNull()]$Result
    )

    if ($null -eq $Result -or $Result.status -ne "Succeeded" -or $null -eq $Result.data) {
        return $null
    }

    if ($Result.data.PSObject.Properties.Name -contains "@odata.count") {
        return [int]$Result.data.'@odata.count'
    }

    return $null
}

function Get-ObjectPropertyValue {
    [CmdletBinding()]
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

function Get-GraphCollectionValue {
    [CmdletBinding()]
    param(
        [AllowNull()]$Result
    )

    if ($null -eq $Result -or $Result.status -ne "Succeeded" -or $null -eq $Result.data) {
        return @()
    }

    if ($Result.data.PSObject.Properties.Name -contains "value") {
        return @($Result.data.value)
    }

    return @($Result.data)
}

function Invoke-GraphReadableProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,
        [string[]]$ExpectedProperties = @(),
        [switch]$Collection
    )

    $result = if ($Collection) {
        Invoke-GraphRestCollectionSafe -Name $Name -Path $Path -MaxPages 1
    }
    else {
        Invoke-GraphRestGet -Name $Name -Path $Path
    }

    $availableProperties = @()
    if ($result.status -eq "Succeeded" -and $null -ne $result.data) {
        $target = $result.data
        if ($Collection) {
            $values = @(Get-GraphCollectionValue -Result $result)
            if ($values.Count -gt 0) {
                $target = $values[0]
            }
        }

        foreach ($propertyName in $ExpectedProperties) {
            if ($target.PSObject.Properties.Name -contains $propertyName) {
                $availableProperties += $propertyName
            }
        }
    }

    [pscustomobject]@{
        name = $Name
        uri = $result.uri
        status = $result.status
        readable = [bool]($result.status -eq "Succeeded")
        expected_properties = @($ExpectedProperties)
        available_properties = @($availableProperties)
        error = $result.error
    }
}

function Invoke-GraphRestCollectionSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxPages = 10
    )

    try {
        return Invoke-GraphRestCollection -Name $Name -Path $Path -MaxPages $MaxPages
    }
    catch {
        return [pscustomobject]@{
            name = $Name
            uri = if ($Path -like "https://*") { $Path } else { "$GraphBaseUri$Path" }
            status = "Failed"
            data = @()
            page_count = 0
            truncated = $false
            error = $_.Exception.Message
        }
    }
}

$userSelectFields = @(
    "id",
    "displayName",
    "userPrincipalName",
    "mail",
    "accountEnabled",
    "userType",
    "createdDateTime",
    "lastPasswordChangeDateTime",
    "onPremisesSyncEnabled",
    "onPremisesLastSyncDateTime",
    "department",
    "jobTitle",
    "companyName",
    "officeLocation",
    "mobilePhone",
    "businessPhones",
    "employeeId",
    "employeeType",
    "onPremisesExtensionAttributes"
)
$groupSelectFields = @("id", "displayName", "description", "mail", "securityEnabled", "mailEnabled", "groupTypes", "createdDateTime")
$meSelectFields = @("id", "displayName", "userPrincipalName", "mail", "accountEnabled", "createdDateTime", "userType")
$meSelect = $meSelectFields -join ","
$userSelect = $userSelectFields -join ","
$groupSelect = $groupSelectFields -join ","

$requests = @(
    @{ name = "me"; path = "/me?`$select=$meSelect" },
    @{ name = "organization"; path = "/organization?`$select=id,displayName,verifiedDomains" },
    @{ name = "memberOf"; path = "/me/memberOf?`$top=100&`$select=id,displayName,description" },
    @{ name = "ownedObjects"; path = "/me/ownedObjects?`$top=100&`$select=id,displayName,appId" },
    @{ name = "directoryRoles"; path = "/directoryRoles?`$top=100" },
    @{ name = "applications"; path = "/applications?`$top=100&`$select=id,appId,displayName,signInAudience,publisherDomain" },
    @{ name = "servicePrincipals"; path = "/servicePrincipals?`$top=100&`$select=id,appId,displayName,servicePrincipalType,accountEnabled" }
)

$responses = @()
foreach ($request in $requests) {
    $responses += (Invoke-GraphRestGet -Name $request.name -Path $request.path)
}

function Get-GraphResponseValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Responses,
        [Parameter(Mandatory)][string]$Name
    )

    $item = @($Responses | Where-Object { $_.name -eq $Name } | Select-Object -First 1)
    if ($item.Count -eq 0 -or $item[0].status -ne "Succeeded" -or $null -eq $item[0].data) {
        return @()
    }

    if ($item[0].data.PSObject.Properties.Name -contains "value") {
        return @($item[0].data.value)
    }

    return $item[0].data
}

$me = Get-GraphResponseValue -Responses $responses -Name "me"
$org = Get-GraphResponseValue -Responses $responses -Name "organization"
$memberOf = Get-GraphResponseValue -Responses $responses -Name "memberOf"
$ownedObjects = Get-GraphResponseValue -Responses $responses -Name "ownedObjects"
$directoryRoles = Get-GraphResponseValue -Responses $responses -Name "directoryRoles"
$applications = Get-GraphResponseValue -Responses $responses -Name "applications"
$servicePrincipals = Get-GraphResponseValue -Responses $responses -Name "servicePrincipals"

$currentUserForReport = $me
$currentUserId = Get-ObjectPropertyValue -Object $me -Name "id"
if (-not [string]::IsNullOrWhiteSpace($currentUserId)) {
    $meExtendedResult = Invoke-GraphRestGet -Name "meExtended" -Path "/users/${currentUserId}?`$select=$userSelect"
    if ($meExtendedResult.status -eq "Succeeded" -and $null -ne $meExtendedResult.data) {
        $currentUserForReport = $meExtendedResult.data
        $responses += $meExtendedResult
    }
    else {
        $responses += $meExtendedResult
    }
}

$safeDirectorySampleSize = [Math]::Max(1, [Math]::Min($DirectorySampleSize, 999))
$usersSampleResult = Invoke-GraphRestGet -Name "tenantUsersSample" -Path "/users?`$count=true&`$top=$safeDirectorySampleSize&`$select=$userSelect"
$groupsSampleResult = Invoke-GraphRestGet -Name "tenantGroupsSample" -Path "/groups?`$count=true&`$top=$safeDirectorySampleSize&`$select=$groupSelect"
$tenantUsersSample = Get-GraphCollectionValue -Result $usersSampleResult
$tenantGroupsSample = Get-GraphCollectionValue -Result $groupsSampleResult

$allUsersResult = $null
$allUsers = @()
if ($EnumerateAllUsers) {
    $allUsersResult = Invoke-GraphRestCollection -Name "tenantUsersAll" -Path "/users?`$top=999&`$select=$userSelect" -MaxPages ([int]::MaxValue)
    $allUsers = @($allUsersResult.data)
}

$readableProbes = New-Object System.Collections.Generic.List[object]
$sampleUserId = $null
if (@($tenantUsersSample).Count -gt 0) {
    $sampleUserId = Get-ObjectPropertyValue -Object $tenantUsersSample[0] -Name "id"
}
elseif ($me -and (Get-ObjectPropertyValue -Object $me -Name "id")) {
    $sampleUserId = Get-ObjectPropertyValue -Object $me -Name "id"
}

if (-not [string]::IsNullOrWhiteSpace($sampleUserId)) {
    $readableProbes.Add((Invoke-GraphReadableProbe -Name "userStandardProperties" -Path "/users/${sampleUserId}?`$select=$userSelect" -ExpectedProperties $userSelectFields)) | Out-Null
    $readableProbes.Add((Invoke-GraphReadableProbe -Name "userCustomSecurityAttributes" -Path "/users/${sampleUserId}?`$select=id,displayName,userPrincipalName,customSecurityAttributes" -ExpectedProperties @("id", "displayName", "userPrincipalName", "customSecurityAttributes"))) | Out-Null
    $readableProbes.Add((Invoke-GraphReadableProbe -Name "userMemberOfGroups" -Path "/users/$sampleUserId/memberOf?`$top=100&`$select=id,displayName,description" -ExpectedProperties @("id", "displayName", "description") -Collection)) | Out-Null
    $readableProbes.Add((Invoke-GraphReadableProbe -Name "userTransitiveMemberOfGroups" -Path "/users/$sampleUserId/transitiveMemberOf?`$top=100&`$select=id,displayName,description" -ExpectedProperties @("id", "displayName", "description") -Collection)) | Out-Null
    $readableProbes.Add((Invoke-GraphReadableProbe -Name "userRegisteredDevices" -Path "/users/$sampleUserId/registeredDevices?`$top=100&`$select=id,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,approximateLastSignInDateTime" -ExpectedProperties @("id", "displayName", "operatingSystem", "operatingSystemVersion", "trustType", "isCompliant", "isManaged", "approximateLastSignInDateTime") -Collection)) | Out-Null
    $readableProbes.Add((Invoke-GraphReadableProbe -Name "userAuthenticationMethods" -Path "/users/$sampleUserId/authentication/methods" -ExpectedProperties @("id", "@odata.type", "displayName") -Collection)) | Out-Null
}

$tenantDirectoryData = [ordered]@{
    user_count_visible = Get-GraphCountFromCollectionResult -Result $usersSampleResult
    group_count_visible = Get-GraphCountFromCollectionResult -Result $groupsSampleResult
    sample_size_requested = $safeDirectorySampleSize
    users_sample_count = @($tenantUsersSample).Count
    groups_sample_count = @($tenantGroupsSample).Count
    users_sample_truncated = [bool]($usersSampleResult.status -eq "Succeeded" -and $null -ne $usersSampleResult.data -and $usersSampleResult.data.PSObject.Properties.Name -contains "@odata.nextLink")
    groups_sample_truncated = [bool]($groupsSampleResult.status -eq "Succeeded" -and $null -ne $groupsSampleResult.data -and $groupsSampleResult.data.PSObject.Properties.Name -contains "@odata.nextLink")
    user_select_properties_requested = @($userSelectFields)
    group_select_properties_requested = @($groupSelectFields)
    readable_property_probes = @($readableProbes | ForEach-Object { ConvertTo-PlainObject $_ })
    sample_user_id_used_for_property_probe = $sampleUserId
    all_users_enumeration_requested = [bool]$EnumerateAllUsers
    all_users_returned_count = @($allUsers).Count
    all_users_truncated = if ($allUsersResult) { [bool]$allUsersResult.truncated } else { $false }
    users_sample = @($tenantUsersSample | ForEach-Object { ConvertTo-PlainObject $_ })
    groups_sample = @($tenantGroupsSample | ForEach-Object { ConvertTo-PlainObject $_ })
    all_users = if ($EnumerateAllUsers) { @($allUsers | ForEach-Object { ConvertTo-PlainObject $_ }) } else { @() }
    collection_results = @(
        [pscustomobject]@{
            name = $usersSampleResult.name
            uri = $usersSampleResult.uri
            status = $usersSampleResult.status
            count = @($tenantUsersSample).Count
            error = $usersSampleResult.error
        },
        [pscustomobject]@{
            name = $groupsSampleResult.name
            uri = $groupsSampleResult.uri
            status = $groupsSampleResult.status
            count = @($tenantGroupsSample).Count
            error = $groupsSampleResult.error
        }
    ) + $(if ($allUsersResult) {
        @([pscustomobject]@{
            name = $allUsersResult.name
            uri = $allUsersResult.uri
            status = $allUsersResult.status
            count = @($allUsers).Count
            page_count = $allUsersResult.page_count
            truncated = $allUsersResult.truncated
            error = $allUsersResult.error
        })
    } else { @() })
    notes = @(
        "A coleta padrao contabiliza usuarios e grupos enumeraveis e guarda amostras limitadas pelo parametro DirectorySampleSize.",
        "Use -EnumerateAllUsers para salvar todos os usuarios enumeraveis em tenant_directory.all_users.",
        "Memberships, customSecurityAttributes, dispositivos e metodos de autenticacao sao testados por probe em um usuario de amostra para indicar propriedades legiveis sem enumerar todo o tenant por padrao."
    )
}

Add-AccessReviewRawData -State $State -Name "entra-tenant-directory" -Data $tenantDirectoryData | Out-Null

Add-AccessReviewRawData -State $State -Name "entra-graph-rest-partial-base" -Data ([ordered]@{
    current_user = ConvertTo-PlainObject $currentUserForReport
    organizations = @($org | ForEach-Object { ConvertTo-PlainObject $_ })
    member_of_count = @($memberOf).Count
    owned_objects_count = @($ownedObjects).Count
    tenant_user_count_visible = $tenantDirectoryData.user_count_visible
    tenant_group_count_visible = $tenantDirectoryData.group_count_visible
    tenant_users_sample_count = $tenantDirectoryData.users_sample_count
    tenant_groups_sample_count = $tenantDirectoryData.groups_sample_count
    applications_sample_count = @($applications).Count
    service_principals_sample_count = @($servicePrincipals).Count
    request_results = @($responses | ForEach-Object {
        [pscustomobject]@{
            name = $_.name
            status = $_.status
            error = $_.error
        }
    })
}) | Out-Null

$privilegedCollectionResults = @(
    Invoke-GraphRestCollectionSafe -Name "directoryRoleTemplates" -Path "/directoryRoleTemplates?`$top=999"
    Invoke-GraphRestCollectionSafe -Name "directoryRolesExpanded" -Path "/directoryRoles?`$expand=members&`$top=100"
    Invoke-GraphRestCollectionSafe -Name "roleManagementAssignments" -Path "/roleManagement/directory/roleAssignments?`$expand=principal,roleDefinition&`$top=100"
    Invoke-GraphRestCollectionSafe -Name "roleManagementEligibility" -Path "/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=principal,roleDefinition&`$top=100"
)

function Get-CollectionData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Collections,
        [Parameter(Mandatory)][string]$Name
    )

    $item = @($Collections | Where-Object { $_.name -eq $Name } | Select-Object -First 1)
    if ($item.Count -eq 0) {
        return @()
    }

    return @($item[0].data)
}

function Set-MapValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Map,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()]$Value
    )

    if ($Map -is [System.Collections.IDictionary]) {
        $Map[$Name] = $Value
        return
    }

    $Map.$Name = $Value
}

function Add-MapListValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Map,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()]$Value
    )

    if ($Map -is [System.Collections.IDictionary]) {
        $current = @()
        if ($Map.Contains($Name) -and $null -ne $Map[$Name]) {
            $current = @($Map[$Name])
        }
        $Map[$Name] = @($current + $Value)
        return
    }

    $Map.$Name = @(@($Map.$Name) + $Value)
}

function New-PrivilegedPrincipalRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [AllowNull()][string]$DisplayName,
        [AllowNull()][string]$UserPrincipalName,
        [AllowNull()][string]$PrincipalType
    )

    [ordered]@{
        id = $Id
        displayName = $DisplayName
        userPrincipalName = $UserPrincipalName
        principalType = $PrincipalType
        roles = @()
        assignment_sources = @()
        details = $null
        groups = @()
        owned_objects = @()
        registered_devices = @()
        owned_devices = @()
        auth_methods = @()
        enrichment_errors = @()
    }
}

$directoryRolesExpanded = Get-CollectionData -Collections @($privilegedCollectionResults) -Name "directoryRolesExpanded"
$roleAssignments = Get-CollectionData -Collections $privilegedCollectionResults -Name "roleManagementAssignments"
$roleEligibilities = Get-CollectionData -Collections $privilegedCollectionResults -Name "roleManagementEligibility"

$privilegedPrincipalsById = [ordered]@{}

foreach ($role in @($directoryRolesExpanded)) {
    $roleName = Get-ObjectPropertyValue -Object $role -Name "displayName"
    $roleId = Get-ObjectPropertyValue -Object $role -Name "id"
    $members = Get-ObjectPropertyValue -Object $role -Name "members"
    foreach ($member in @($members)) {
        $principalId = Get-ObjectPropertyValue -Object $member -Name "id"
        if ([string]::IsNullOrWhiteSpace($principalId)) {
            continue
        }
        if (-not $privilegedPrincipalsById.Contains($principalId)) {
            $privilegedPrincipalsById[$principalId] = New-PrivilegedPrincipalRecord -Id $principalId -DisplayName (Get-ObjectPropertyValue -Object $member -Name "displayName") -UserPrincipalName (Get-ObjectPropertyValue -Object $member -Name "userPrincipalName") -PrincipalType (Get-ObjectPropertyValue -Object $member -Name "@odata.type")
        }
        Add-MapListValue -Map $privilegedPrincipalsById[$principalId] -Name "roles" -Value ([pscustomobject]@{
            role_name = $roleName
            role_id = $roleId
            assignment_type = "active_directory_role_member"
            source = "directoryRoles.members"
        })
        Add-MapListValue -Map $privilegedPrincipalsById[$principalId] -Name "assignment_sources" -Value "directoryRoles.members"
    }
}

foreach ($assignment in @($roleAssignments)) {
    $principal = Get-ObjectPropertyValue -Object $assignment -Name "principal"
    $roleDefinition = Get-ObjectPropertyValue -Object $assignment -Name "roleDefinition"
    $principalId = Get-ObjectPropertyValue -Object $assignment -Name "principalId"
    if ([string]::IsNullOrWhiteSpace($principalId) -and $principal) {
        $principalId = Get-ObjectPropertyValue -Object $principal -Name "id"
    }
    if ([string]::IsNullOrWhiteSpace($principalId)) {
        continue
    }
    if (-not $privilegedPrincipalsById.Contains($principalId)) {
        $privilegedPrincipalsById[$principalId] = New-PrivilegedPrincipalRecord -Id $principalId -DisplayName (Get-ObjectPropertyValue -Object $principal -Name "displayName") -UserPrincipalName (Get-ObjectPropertyValue -Object $principal -Name "userPrincipalName") -PrincipalType (Get-ObjectPropertyValue -Object $assignment -Name "principalType")
    }
    Add-MapListValue -Map $privilegedPrincipalsById[$principalId] -Name "roles" -Value ([pscustomobject]@{
        role_name = Get-ObjectPropertyValue -Object $roleDefinition -Name "displayName"
        role_id = Get-ObjectPropertyValue -Object $assignment -Name "roleDefinitionId"
        assignment_type = "active_role_assignment"
        directory_scope_id = Get-ObjectPropertyValue -Object $assignment -Name "directoryScopeId"
        app_scope_id = Get-ObjectPropertyValue -Object $assignment -Name "appScopeId"
        source = "roleManagement.directory.roleAssignments"
    })
    Add-MapListValue -Map $privilegedPrincipalsById[$principalId] -Name "assignment_sources" -Value "roleManagement.directory.roleAssignments"
}

foreach ($eligibility in @($roleEligibilities)) {
    $principal = Get-ObjectPropertyValue -Object $eligibility -Name "principal"
    $roleDefinition = Get-ObjectPropertyValue -Object $eligibility -Name "roleDefinition"
    $principalId = Get-ObjectPropertyValue -Object $eligibility -Name "principalId"
    if ([string]::IsNullOrWhiteSpace($principalId) -and $principal) {
        $principalId = Get-ObjectPropertyValue -Object $principal -Name "id"
    }
    if ([string]::IsNullOrWhiteSpace($principalId)) {
        continue
    }
    if (-not $privilegedPrincipalsById.Contains($principalId)) {
        $privilegedPrincipalsById[$principalId] = New-PrivilegedPrincipalRecord -Id $principalId -DisplayName (Get-ObjectPropertyValue -Object $principal -Name "displayName") -UserPrincipalName (Get-ObjectPropertyValue -Object $principal -Name "userPrincipalName") -PrincipalType (Get-ObjectPropertyValue -Object $eligibility -Name "principalType")
    }
    Add-MapListValue -Map $privilegedPrincipalsById[$principalId] -Name "roles" -Value ([pscustomobject]@{
        role_name = Get-ObjectPropertyValue -Object $roleDefinition -Name "displayName"
        role_id = Get-ObjectPropertyValue -Object $eligibility -Name "roleDefinitionId"
        assignment_type = "eligible_role_assignment"
        member_type = Get-ObjectPropertyValue -Object $eligibility -Name "memberType"
        start_date_time = Get-ObjectPropertyValue -Object $eligibility -Name "startDateTime"
        end_date_time = Get-ObjectPropertyValue -Object $eligibility -Name "endDateTime"
        source = "roleManagement.directory.roleEligibilityScheduleInstances"
    })
    Add-MapListValue -Map $privilegedPrincipalsById[$principalId] -Name "assignment_sources" -Value "roleManagement.directory.roleEligibilityScheduleInstances"
}

$privilegedPrincipals = @($privilegedPrincipalsById.Values | Select-Object -First $PrivilegedAccountLimit)

if ($DeepEnumerate) {
    foreach ($principal in $privilegedPrincipals) {
        $principalId = Get-ObjectPropertyValue -Object $principal -Name "id"
        $principalType = [string](Get-ObjectPropertyValue -Object $principal -Name "principalType")
        $principalUpn = Get-ObjectPropertyValue -Object $principal -Name "userPrincipalName"
        $isUser = ($principalType -match "user" -or -not [string]::IsNullOrWhiteSpace($principalUpn))

        if ($isUser) {
            $userDetail = Invoke-GraphRestGet -Name "privilegedUser:$principalId" -Path "/users/${principalId}?`$select=id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime,lastPasswordChangeDateTime,signInActivity,onPremisesSyncEnabled,onPremisesLastSyncDateTime,department,jobTitle,companyName,officeLocation,mobilePhone,businessPhones"
            if ($userDetail.status -eq "Succeeded") {
                Set-MapValue -Map $principal -Name "details" -Value (ConvertTo-PlainObject $userDetail.data)
            }
            else {
                Add-MapListValue -Map $principal -Name "enrichment_errors" -Value "user_details: $($userDetail.error)"
            }

            $groupsResult = Invoke-GraphRestCollection -Name "privilegedUserGroups:$principalId" -Path "/users/$principalId/memberOf?`$top=100&`$select=id,displayName,description" -MaxPages 5
            if ($groupsResult.status -eq "Succeeded") {
                Set-MapValue -Map $principal -Name "groups" -Value @($groupsResult.data)
            }
            else {
                Add-MapListValue -Map $principal -Name "enrichment_errors" -Value "groups: $($groupsResult.error)"
            }

            $registeredDevicesResult = Invoke-GraphRestCollection -Name "privilegedUserRegisteredDevices:$principalId" -Path "/users/$principalId/registeredDevices?`$top=100&`$select=id,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,approximateLastSignInDateTime" -MaxPages 5
            if ($registeredDevicesResult.status -eq "Succeeded") {
                Set-MapValue -Map $principal -Name "registered_devices" -Value @($registeredDevicesResult.data)
            }
            else {
                Add-MapListValue -Map $principal -Name "enrichment_errors" -Value "registered_devices: $($registeredDevicesResult.error)"
            }

            $ownedDevicesResult = Invoke-GraphRestCollection -Name "privilegedUserOwnedDevices:$principalId" -Path "/users/$principalId/ownedDevices?`$top=100&`$select=id,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,approximateLastSignInDateTime" -MaxPages 5
            if ($ownedDevicesResult.status -eq "Succeeded") {
                Set-MapValue -Map $principal -Name "owned_devices" -Value @($ownedDevicesResult.data)
            }
            else {
                Add-MapListValue -Map $principal -Name "enrichment_errors" -Value "owned_devices: $($ownedDevicesResult.error)"
            }

            $authMethodsResult = Invoke-GraphRestCollection -Name "privilegedUserAuthMethods:$principalId" -Path "/users/$principalId/authentication/methods" -MaxPages 2
            if ($authMethodsResult.status -eq "Succeeded") {
                Set-MapValue -Map $principal -Name "auth_methods" -Value @($authMethodsResult.data | ForEach-Object {
                    [pscustomobject]@{
                        id = Get-ObjectPropertyValue -Object $_ -Name "id"
                        type = Get-ObjectPropertyValue -Object $_ -Name "@odata.type"
                        displayName = Get-ObjectPropertyValue -Object $_ -Name "displayName"
                    }
                })
            }
            else {
                Add-MapListValue -Map $principal -Name "enrichment_errors" -Value "auth_methods: $($authMethodsResult.error)"
            }
        }
    }
}

$privilegedAccountsData = [ordered]@{
    collection_mode = if ($DeepEnumerate) { "detailed" } else { "standard" }
    limit = $PrivilegedAccountLimit
    privileged_principal_count = @($privilegedPrincipalsById.Values).Count
    returned_principal_count = @($privilegedPrincipals).Count
    truncated = [bool](@($privilegedPrincipalsById.Values).Count -gt @($privilegedPrincipals).Count)
    directory_roles_expanded_count = @($directoryRolesExpanded).Count
    active_assignment_count = @($roleAssignments).Count
    eligible_assignment_count = @($roleEligibilities).Count
    privileged_principals = @($privilegedPrincipals | ForEach-Object { ConvertTo-PlainObject $_ })
    collection_results = @($privilegedCollectionResults | ForEach-Object {
        [pscustomobject]@{
            name = $_.name
            uri = $_.uri
            status = $_.status
            count = @($_.data).Count
            page_count = $_.page_count
            truncated = $_.truncated
            error = $_.error
        }
    })
    notes = @(
        "Contas privilegiadas sao inferidas a partir de directoryRoles, roleAssignments e roleEligibilityScheduleInstances.",
        "Campos como signInActivity, authentication methods e dispositivos dependem de permissoes Graph e licenciamento.",
        "Valores de segredos, senhas, chaves e tokens nao sao coletados."
    )
}

$graphData = [ordered]@{
    method = "rest"
    graph_base_uri = $GraphBaseUri
    token_source = $tokenSource
    token_persisted = $false
    authentication = $authDiagnostics
    authenticated_account_upn = $tokenAccountUpn
    token_claims = if ($tokenClaims) {
        [ordered]@{
            aud = Get-TokenClaim -Claims $tokenClaims -Name "aud"
            iss = Get-TokenClaim -Claims $tokenClaims -Name "iss"
            tid = Get-TokenClaim -Claims $tokenClaims -Name "tid"
            oid = Get-TokenClaim -Claims $tokenClaims -Name "oid"
            upn = Get-TokenClaim -Claims $tokenClaims -Name "upn"
            preferred_username = Get-TokenClaim -Claims $tokenClaims -Name "preferred_username"
            name = Get-TokenClaim -Claims $tokenClaims -Name "name"
            appid = Get-TokenClaim -Claims $tokenClaims -Name "appid"
            azp = Get-TokenClaim -Claims $tokenClaims -Name "azp"
            scp = Get-TokenClaim -Claims $tokenClaims -Name "scp"
            roles = if (Get-TokenClaim -Claims $tokenClaims -Name "roles") { @(Get-TokenClaim -Claims $tokenClaims -Name "roles") } else { @() }
            idtyp = Get-TokenClaim -Claims $tokenClaims -Name "idtyp"
            amr = if (Get-TokenClaim -Claims $tokenClaims -Name "amr") { @(Get-TokenClaim -Claims $tokenClaims -Name "amr") } else { @() }
        }
    } else { $null }
    current_user = ConvertTo-PlainObject $currentUserForReport
    organizations = @($org | ForEach-Object { ConvertTo-PlainObject $_ })
    member_of = @($memberOf | ForEach-Object { ConvertTo-PlainObject $_ })
    owned_objects = @($ownedObjects | ForEach-Object { ConvertTo-PlainObject $_ })
    visible_directory_roles = @($directoryRoles | ForEach-Object { ConvertTo-PlainObject $_ })
    visible_applications_sample = @($applications | ForEach-Object { ConvertTo-PlainObject $_ })
    visible_service_principals_sample = @($servicePrincipals | ForEach-Object { ConvertTo-PlainObject $_ })
    tenant_directory = $tenantDirectoryData
    privileged_accounts = $privilegedAccountsData
    request_results = @($responses | ForEach-Object {
        [pscustomobject]@{
            name = $_.name
            uri = $_.uri
            status = $_.status
            error = $_.error
        }
    }) + @($privilegedCollectionResults | ForEach-Object {
        [pscustomobject]@{
            name = $_.name
            uri = $_.uri
            status = $_.status
            error = $_.error
        }
    })
    notes = @(
        "Este coletor usa Invoke-RestMethod contra Microsoft Graph e nao carrega Microsoft.Graph PowerShell SDK.",
        "Amostras de usuarios e grupos do tenant sao limitadas por DirectorySampleSize; use -EnumerateAllUsers para salvar todos os usuarios enumeraveis.",
        "Amostras de memberOf, ownedObjects, applications e servicePrincipals limitadas a 100 itens para reduzir volume.",
        "O token de acesso nao e gravado no relatorio."
    )
}

Add-AccessReviewRawData -State $State -Name "entra-graph-rest-access" -Data $graphData | Out-Null
$State.Data.entra = $graphData

$failedRequests = @($responses | Where-Object { $_.status -ne "Succeeded" })
if ($failedRequests.Count -gt 0) {
    Add-AccessReviewFinding -State $State -Severity "Medium" -Category "Graph" -Title "Algumas consultas Microsoft Graph REST falharam" -Description "O token usado nao conseguiu executar todas as consultas REST planejadas. Isso normalmente indica falta de escopo delegado, consentimento, politica de tenant ou bloqueio por aplicacao." -Evidence "$($failedRequests.Count) de $($responses.Count) chamada(s) falharam." -Recommendation "Compare os endpoints falhos com o Graph Explorer. Se funcionarem no Explorer, use token/consentimento equivalente aprovado ou exporte respostas do Explorer para complementar a analise."
}

$failedPrivilegedRequests = @($privilegedCollectionResults | Where-Object { $_.status -ne "Succeeded" })
if ($failedPrivilegedRequests.Count -gt 0) {
    Add-AccessReviewFinding -State $State -Severity "Medium" -Category "Privileged Accounts" -Title "Algumas consultas de contas privilegiadas falharam" -Description "Nem todas as fontes de roles privilegiadas puderam ser consultadas. A lista de administradores pode estar incompleta." -Evidence "$($failedPrivilegedRequests.Count) consulta(s) falharam: $((@($failedPrivilegedRequests | Select-Object -ExpandProperty Name) -join ', '))" -Recommendation "Revise permissoes Graph para RoleManagement.Read.Directory, Directory.Read.All e endpoints PIM antes de usar a lista como conclusiva."
}

if ($privilegedAccountsData.privileged_principal_count -gt 0) {
    Add-AccessReviewFinding -State $State -Severity "High" -Category "Privileged Accounts" -Title "Principais privilegiados identificados no Entra ID" -Description "A coleta identificou principals com roles administrativas ativas ou elegiveis no diretorio." -Evidence "$($privilegedAccountsData.privileged_principal_count) principal(is) privilegiado(s) identificado(s)." -Recommendation "Revise MFA forte, PIM, escopo das roles, ultima atividade, ownership, grupos e dispositivos associados a estas contas."
}

if (@($ownedObjects).Count -gt 0) {
    Add-AccessReviewFinding -State $State -Severity "Medium" -Category "Entra ID" -Title "Conta possui objetos Entra ID sob sua propriedade" -Description "Objetos pertencentes ao usuario podem permitir alteracoes em aplicacoes, service principals ou grupos dependendo do tipo do objeto e das politicas do tenant." -Evidence "$(@($ownedObjects).Count) objeto(s) retornado(s) por /me/ownedObjects." -Recommendation "Revise proprietarios de apps, service principals e grupos. Remova ownership desnecessario e aplique processos de aprovacao para objetos privilegiados."
}
