[CmdletBinding()]
param(
    [Parameter(Mandatory)]$State,
    [string[]]$SubscriptionIds,
    [switch]$DeepEnumerate
)

Import-Module Az.Accounts -ErrorAction Stop
Import-Module Az.Resources -ErrorAction Stop
Import-Module Az.KeyVault -ErrorAction SilentlyContinue
Import-Module Az.Storage -ErrorAction SilentlyContinue
Import-Module Az.Compute -ErrorAction SilentlyContinue
Import-Module Az.Network -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

$subscriptions = @(Get-AzSubscription -ErrorAction SilentlyContinue)
if ($SubscriptionIds) {
    $subscriptions = @($subscriptions | Where-Object { $SubscriptionIds -contains $_.Id })
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($subscription in $subscriptions) {
    Set-AzContext -SubscriptionId $subscription.Id -TenantId $subscription.TenantId -ErrorAction SilentlyContinue | Out-Null

    $resources = @()
    $keyVaults = @()
    $storageAccounts = @()
    $virtualMachines = @()
    $networkSecurityGroups = @()
    $publicIps = @()
    $storageDeep = @()

    try { $resources = @(Get-AzResource -ErrorAction SilentlyContinue | Select-Object Name, ResourceType, ResourceGroupName, Location, ResourceId, Tags) } catch {}
    try { $keyVaults = @(Get-AzKeyVault -ErrorAction SilentlyContinue | Select-Object VaultName, ResourceGroupName, Location, ResourceId, EnableRbacAuthorization, EnabledForDeployment, EnabledForTemplateDeployment, EnabledForDiskEncryption, PublicNetworkAccess) } catch {}
    try { $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue | Select-Object StorageAccountName, ResourceGroupName, Location, Id, Kind, Sku, EnableHttpsTrafficOnly, AllowBlobPublicAccess, MinimumTlsVersion, PublicNetworkAccess) } catch {}
    try { $virtualMachines = @(Get-AzVM -Status -ErrorAction SilentlyContinue | Select-Object Name, ResourceGroupName, Location, PowerState, ProvisioningState, Id) } catch {}
    try { $networkSecurityGroups = @(Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue | Select-Object Name, ResourceGroupName, Location, Id, SecurityRules, DefaultSecurityRules) } catch {}
    try { $publicIps = @(Get-AzPublicIpAddress -ErrorAction SilentlyContinue | Select-Object Name, ResourceGroupName, Location, IpAddress, PublicIpAllocationMethod, Sku, Id) } catch {}

    if ($DeepEnumerate -and $storageAccounts.Count -gt 0) {
        foreach ($storageAccount in $storageAccounts) {
            $accountDeep = [ordered]@{
                storage_account = $storageAccount.StorageAccountName
                resource_group = $storageAccount.ResourceGroupName
                blob_containers = @()
                queues = @()
                tables = @()
                error = $null
            }

            try {
                $ctx = New-AzStorageContext -StorageAccountName $storageAccount.StorageAccountName -UseConnectedAccount -ErrorAction Stop
                $accountDeep.blob_containers = @(Get-AzStorageContainer -Context $ctx -ErrorAction SilentlyContinue | Select-Object Name, PublicAccess, LastModified)
                $accountDeep.queues = @(Get-AzStorageQueue -Context $ctx -ErrorAction SilentlyContinue | Select-Object Name)
                $accountDeep.tables = @(Get-AzStorageTable -Context $ctx -ErrorAction SilentlyContinue | Select-Object Name)
            }
            catch {
                $accountDeep.error = $_.Exception.Message
            }

            $storageDeep.Add([pscustomobject]$accountDeep) | Out-Null
        }
    }

    $subscriptionResult = [pscustomobject]@{
        id = $subscription.Id
        name = $subscription.Name
        tenant_id = $subscription.TenantId
        resource_count_visible = $resources.Count
        resources_by_type = @($resources | Group-Object ResourceType | Sort-Object Count -Descending | Select-Object Name, Count)
        key_vaults = @($keyVaults | ForEach-Object { ConvertTo-PlainObject $_ })
        storage_accounts = @($storageAccounts | ForEach-Object { ConvertTo-PlainObject $_ })
        virtual_machines = @($virtualMachines | ForEach-Object { ConvertTo-PlainObject $_ })
        network_security_groups = @($networkSecurityGroups | ForEach-Object { ConvertTo-PlainObject $_ })
        public_ips = @($publicIps | ForEach-Object { ConvertTo-PlainObject $_ })
        storage_deep_enumeration = @($storageDeep | ForEach-Object { ConvertTo-PlainObject $_ })
    }

    $results.Add($subscriptionResult) | Out-Null

    foreach ($vault in $keyVaults) {
        if ($vault.PublicNetworkAccess -eq "Enabled") {
            Add-AccessReviewFinding -State $State -Severity "Medium" -Category "Key Vault" -Title "Key Vault visivel com acesso publico de rede habilitado" -Description "A conta consegue visualizar um Key Vault com PublicNetworkAccess habilitado. Isso nao confirma acesso a segredos, mas amplia a superficie exposta." -Evidence "$($vault.VaultName) em $($subscription.Name)" -Recommendation "Use private endpoints, firewall de rede e RBAC/access policies minimas para Key Vaults sensiveis."
        }
    }

    foreach ($storage in $storageAccounts) {
        if ($storage.AllowBlobPublicAccess -eq $true) {
            Add-AccessReviewFinding -State $State -Severity "Medium" -Category "Storage" -Title "Storage account permite configuracao de blob publico" -Description "A conta consegue visualizar uma storage account onde AllowBlobPublicAccess esta habilitado." -Evidence "$($storage.StorageAccountName) em $($subscription.Name)" -Recommendation "Desabilite AllowBlobPublicAccess exceto quando houver justificativa aprovada e monitoramento."
        }
        if ($storage.MinimumTlsVersion -and $storage.MinimumTlsVersion -ne "TLS1_2") {
            Add-AccessReviewFinding -State $State -Severity "Low" -Category "Storage" -Title "Storage account com TLS minimo abaixo de TLS 1.2" -Description "A storage account visivel nao exige TLS 1.2 como minimo." -Evidence "$($storage.StorageAccountName): $($storage.MinimumTlsVersion)" -Recommendation "Configure MinimumTlsVersion para TLS1_2 ou superior."
        }
    }

    foreach ($publicIp in $publicIps) {
        if (-not [string]::IsNullOrWhiteSpace($publicIp.IpAddress)) {
            Add-AccessReviewFinding -State $State -Severity "Info" -Category "Network" -Title "Conta consegue listar IPs publicos" -Description "A conta consegue enumerar enderecos publicos associados a recursos Azure." -Evidence "$($publicIp.Name): $($publicIp.IpAddress)" -Recommendation "Garanta que inventario publico seja intencional e que NSGs/WAF/Defender estejam alinhados ao risco."
        }
    }
}

$resourceData = [ordered]@{
    subscriptions = @($results | ForEach-Object { ConvertTo-PlainObject $_ })
    deep_enumeration_enabled = [bool]$DeepEnumerate
    sensitive_data_policy = "Nao coleta valores de segredos, chaves, conteudo de blobs, bancos ou payloads de VMs."
}

Add-AccessReviewRawData -State $State -Name "azure-resource-access" -Data $resourceData | Out-Null
$State.Data.resources = $resourceData

