[CmdletBinding()]
param(
    [Parameter(Mandatory)]$State
)

$State.CompletedAtUtc = (Get-Date).ToUniversalTime().ToString("o")

$severityOrder = @{
    Critical = 0
    High = 1
    Medium = 2
    Low = 3
    Info = 4
}

$findings = @($State.Findings | Sort-Object @{ Expression = { $severityOrder[$_.severity] } }, Category, Title)
$subscriptionsVisible = 0
if ($State.Data.Contains("rbac") -and $State.Data.rbac.subscriptions_visible_count -ne $null) {
    $subscriptionsVisible = $State.Data.rbac.subscriptions_visible_count
}

$roles = @()
if ($State.Data.Contains("rbac")) {
    $roles = @($State.Data.rbac.effective_role_names)
}

$resourceCount = 0
if ($State.Data.Contains("resources")) {
    foreach ($sub in @($State.Data.resources.subscriptions)) {
        $resourceCount += [int]$sub.resource_count_visible
    }
}

$accountSummary = New-AccountSummary -Session $(if ($State.Data.Contains("session")) { $State.Data.session } else { $null }) -Entra $(if ($State.Data.Contains("entra")) { $State.Data.entra } else { $null })

$capabilitySummary = [ordered]@{
    subscriptions_visible = $subscriptionsVisible
    azure_roles_visible = $roles
    resource_count_visible = $resourceCount
    can_infer_rbac_management = [bool](@($findings | Where-Object { $_.title -like "*RBAC*" -and $_.severity -in @("Critical","High") }).Count -gt 0)
    graph_collected = [bool]$State.Data.Contains("entra")
    resource_inventory_collected = [bool]$State.Data.Contains("resources")
    deep_enumeration = [bool]$State.DeepEnumerate
}

$privilegedAccounts = $null
if ($State.Data.Contains("entra") -and $State.Data.entra.PSObject.Properties.Name -contains "privileged_accounts") {
    $privilegedAccounts = $State.Data.entra.privileged_accounts
}
elseif ($State.Data.Contains("entra") -and $State.Data.entra -is [System.Collections.IDictionary] -and $State.Data.entra.Contains("privileged_accounts")) {
    $privilegedAccounts = $State.Data.entra["privileged_accounts"]
}

$tenantDirectory = $null
if ($State.Data.Contains("entra") -and $State.Data.entra.PSObject.Properties.Name -contains "tenant_directory") {
    $tenantDirectory = $State.Data.entra.tenant_directory
}
elseif ($State.Data.Contains("entra") -and $State.Data.entra -is [System.Collections.IDictionary] -and $State.Data.entra.Contains("tenant_directory")) {
    $tenantDirectory = $State.Data.entra["tenant_directory"]
}

$report = [ordered]@{
    schema_version = "1.0"
    generated_at_utc = $State.CompletedAtUtc
    purpose = "Azure user access security review"
    collection_safety = [ordered]@{
        default_mode = "read-only metadata and permission enumeration"
        sensitive_values_collected = $false
        deep_enumeration_enabled = [bool]$State.DeepEnumerate
    }
    capability_summary = $capabilitySummary
    account_summary = $accountSummary
    collectors = @($State.Collectors | ForEach-Object { ConvertTo-PlainObject $_ })
    findings = @($findings | ForEach-Object { ConvertTo-PlainObject $_ })
    data = $State.Data
}

$jsonPath = Join-Path $State.OutputPath "azure-access-review.json"
Write-AccessReviewJson -Path $jsonPath -Data $report -Depth 30
$State.ReportJsonPath = $jsonPath

$md = New-Object System.Collections.Generic.List[string]
$md.Add("# Azure User Access Review") | Out-Null
$md.Add("") | Out-Null
$md.Add("Gerado em UTC: $($State.CompletedAtUtc)") | Out-Null
$md.Add("") | Out-Null
$md.Add("## Resumo executivo") | Out-Null
$md.Add("") | Out-Null
$md.Add("- Subscriptions visiveis: $($capabilitySummary.subscriptions_visible)") | Out-Null
$md.Add("- Recursos Azure visiveis: $($capabilitySummary.resource_count_visible)") | Out-Null
$md.Add("- Roles Azure observadas: $((@($roles) -join ', '))") | Out-Null
$md.Add("- Coleta Graph/Entra ID executada: $($capabilitySummary.graph_collected)") | Out-Null
$md.Add("- Enumeracao profunda habilitada: $($capabilitySummary.deep_enumeration)") | Out-Null
$md.Add("- Usuarios do tenant enumeraveis: $(if ($tenantDirectory -and $null -ne $tenantDirectory.user_count_visible) { $tenantDirectory.user_count_visible } else { 'Nao coletado' })") | Out-Null
$md.Add("- Grupos do tenant enumeraveis: $(if ($tenantDirectory -and $null -ne $tenantDirectory.group_count_visible) { $tenantDirectory.group_count_visible } else { 'Nao coletado' })") | Out-Null
$md.Add("- Conta avaliada: $(if ($accountSummary.user_principal_name) { $accountSummary.user_principal_name } elseif ($accountSummary.azure_context_account) { $accountSummary.azure_context_account } else { 'Nao identificada' })") | Out-Null
$md.Add("- Tenant avaliado: $(if ($accountSummary.tenant_id) { $accountSummary.tenant_id } else { 'Nao identificado' })") | Out-Null
$md.Add("") | Out-Null
$md.Add("## Conta Identificada") | Out-Null
$md.Add("") | Out-Null
$md.Add("- Nome: $(if ($accountSummary.display_name) { $accountSummary.display_name } else { 'Nao identificado' })") | Out-Null
$md.Add("- UPN/login: $(if ($accountSummary.user_principal_name) { $accountSummary.user_principal_name } else { 'Nao identificado' })") | Out-Null
$md.Add("- Email: $(if ($accountSummary.mail) { $accountSummary.mail } else { 'Nao identificado' })") | Out-Null
$md.Add("- Object ID: $(if ($accountSummary.user_id) { $accountSummary.user_id } else { 'Nao identificado' })") | Out-Null
$md.Add("- Conta habilitada: $(if ($null -ne $accountSummary.account_enabled) { $accountSummary.account_enabled } else { 'Nao identificado' })") | Out-Null
$md.Add("- Tipo de usuario: $(if ($accountSummary.user_type) { $accountSummary.user_type } else { 'Nao identificado' })") | Out-Null
$md.Add("- Criada em: $(if ($accountSummary.created_date_time) { $accountSummary.created_date_time } else { 'Nao identificado' })") | Out-Null
$md.Add("- Ultima troca de senha: $(if ($accountSummary.last_password_change_date_time) { $accountSummary.last_password_change_date_time } else { 'Nao identificado' })") | Out-Null
$md.Add("- Departamento: $(if ($accountSummary.department) { $accountSummary.department } else { 'Nao identificado' })") | Out-Null
$md.Add("- Cargo: $(if ($accountSummary.job_title) { $accountSummary.job_title } else { 'Nao identificado' })") | Out-Null
$md.Add("- Empresa: $(if ($accountSummary.company_name) { $accountSummary.company_name } else { 'Nao identificado' })") | Out-Null
$md.Add("- Escritorio/localizacao: $(if ($accountSummary.office_location) { $accountSummary.office_location } else { 'Nao identificado' })") | Out-Null
$md.Add("- Employee ID: $(if ($accountSummary.employee_id) { $accountSummary.employee_id } else { 'Nao identificado' })") | Out-Null
$md.Add("- Employee type: $(if ($accountSummary.employee_type) { $accountSummary.employee_type } else { 'Nao identificado' })") | Out-Null
$md.Add("- Sincronizada do on-premises: $(if ($null -ne $accountSummary.on_premises_sync_enabled) { $accountSummary.on_premises_sync_enabled } else { 'Nao identificado' })") | Out-Null
$md.Add("- Ultima sincronizacao on-premises: $(if ($accountSummary.on_premises_last_sync_date_time) { $accountSummary.on_premises_last_sync_date_time } else { 'Nao identificado' })") | Out-Null
$md.Add("- Tenant ID: $(if ($accountSummary.tenant_id) { $accountSummary.tenant_id } else { 'Nao identificado' })") | Out-Null
$md.Add("- Conta no contexto Az: $(if ($accountSummary.azure_context_account) { $accountSummary.azure_context_account } else { 'Nao identificada' })") | Out-Null
$md.Add("- Subscription ativa no contexto Az: $(if ($accountSummary.azure_context_subscription) { $accountSummary.azure_context_subscription } else { 'Nao identificada' })") | Out-Null
$md.Add("- App/client ID do token Graph: $(if ($accountSummary.graph_token_app_id) { $accountSummary.graph_token_app_id } else { 'Nao identificado' })") | Out-Null
$md.Add("- Escopos Graph no token: $(if ($accountSummary.graph_token_scopes) { $accountSummary.graph_token_scopes } else { 'Nao identificados' })") | Out-Null
$md.Add("") | Out-Null
$md.Add("## Resumo de capacidades") | Out-Null
$md.Add("") | Out-Null
$md.Add("Esta conta consegue visualizar $($capabilitySummary.subscriptions_visible) subscription(s) e $($capabilitySummary.resource_count_visible) recurso(s) Azure com as permissoes concedidas no momento da coleta.") | Out-Null
if ($roles.Count -gt 0) {
    $md.Add("") | Out-Null
    $md.Add("Roles identificadas:") | Out-Null
    foreach ($role in $roles) {
        $md.Add("- $role") | Out-Null
    }
}

if ($privilegedAccounts) {
    $md.Add("") | Out-Null
    $md.Add("## Contas Privilegiadas") | Out-Null
    $md.Add("") | Out-Null
    $md.Add("- Modo de coleta: $($privilegedAccounts.collection_mode)") | Out-Null
    $md.Add("- Principals privilegiados identificados: $($privilegedAccounts.privileged_principal_count)") | Out-Null
    $md.Add("- Principals retornados no relatorio: $($privilegedAccounts.returned_principal_count)") | Out-Null
    $md.Add("- Role assignments ativos: $($privilegedAccounts.active_assignment_count)") | Out-Null
    $md.Add("- Role assignments elegiveis: $($privilegedAccounts.eligible_assignment_count)") | Out-Null
    $md.Add("") | Out-Null
    $md.Add("| Conta/Principal | Tipo | Roles | Fontes |") | Out-Null
    $md.Add("| --- | --- | --- | --- |") | Out-Null
    foreach ($principal in @($privilegedAccounts.privileged_principals | Select-Object -First 25)) {
        $principalName = if ($principal.userPrincipalName) { $principal.userPrincipalName } elseif ($principal.displayName) { $principal.displayName } else { $principal.id }
        $roleNames = @($principal.roles | ForEach-Object { $_.role_name } | Where-Object { $_ } | Select-Object -Unique) -join ", "
        $sources = @($principal.assignment_sources | Select-Object -Unique) -join ", "
        $principalType = if ($principal.principalType) { $principal.principalType } else { "" }
        $md.Add("| $principalName | $principalType | $roleNames | $sources |") | Out-Null
    }
    if ($privilegedAccounts.returned_principal_count -gt 25) {
        $md.Add("") | Out-Null
        $md.Add("A tabela mostra os primeiros 25 principals privilegiados; use o JSON para a lista completa.") | Out-Null
    }
}

if ($tenantDirectory) {
    $md.Add("") | Out-Null
    $md.Add("## Diretorio Entra ID") | Out-Null
    $md.Add("") | Out-Null
    $md.Add("- Usuarios enumeraveis: $(if ($null -ne $tenantDirectory.user_count_visible) { $tenantDirectory.user_count_visible } else { 'Nao identificado' })") | Out-Null
    $md.Add("- Grupos enumeraveis: $(if ($null -ne $tenantDirectory.group_count_visible) { $tenantDirectory.group_count_visible } else { 'Nao identificado' })") | Out-Null
    $md.Add("- Amostra de usuarios retornada: $($tenantDirectory.users_sample_count)") | Out-Null
    $md.Add("- Amostra de grupos retornada: $($tenantDirectory.groups_sample_count)") | Out-Null
    $md.Add("- Enumeracao completa de usuarios solicitada: $($tenantDirectory.all_users_enumeration_requested)") | Out-Null
    if ($tenantDirectory.all_users_enumeration_requested) {
        $md.Add("- Usuarios retornados na enumeracao completa: $($tenantDirectory.all_users_returned_count)") | Out-Null
        $md.Add("- Enumeracao completa truncada: $($tenantDirectory.all_users_truncated)") | Out-Null
    }
    $md.Add("") | Out-Null
    $md.Add("Propriedades de usuario solicitadas na amostra:") | Out-Null
    foreach ($propertyName in @($tenantDirectory.user_select_properties_requested)) {
        $md.Add("- ``$propertyName``") | Out-Null
    }
    $md.Add("") | Out-Null
    $md.Add("Probes de propriedades e relacionamentos legiveis:") | Out-Null
    $md.Add("") | Out-Null
    $md.Add("| Probe | Legivel | Propriedades retornadas | Erro |") | Out-Null
    $md.Add("| --- | --- | --- | --- |") | Out-Null
    foreach ($probe in @($tenantDirectory.readable_property_probes)) {
        $probeError = if ($probe.error) { $probe.error.Replace("|", "\|") } else { "" }
        $available = @($probe.available_properties) -join ", "
        $md.Add("| $($probe.name) | $($probe.readable) | $available | $probeError |") | Out-Null
    }
    $md.Add("") | Out-Null
    $md.Add("Amostra de usuarios:") | Out-Null
    $md.Add("") | Out-Null
    $md.Add("| Nome | UPN | Tipo | Habilitada | Departamento | Cargo |") | Out-Null
    $md.Add("| --- | --- | --- | --- | --- | --- |") | Out-Null
    foreach ($user in @($tenantDirectory.users_sample | Select-Object -First 25)) {
        $md.Add("| $($user.displayName) | $($user.userPrincipalName) | $($user.userType) | $($user.accountEnabled) | $($user.department) | $($user.jobTitle) |") | Out-Null
    }
    if ($tenantDirectory.users_sample_count -gt 25) {
        $md.Add("") | Out-Null
        $md.Add("A tabela mostra os primeiros 25 usuarios da amostra; use o JSON para a amostra completa.") | Out-Null
    }
}
$md.Add("") | Out-Null
$md.Add("## Achados") | Out-Null
$md.Add("") | Out-Null
if ($findings.Count -eq 0) {
    $md.Add("Nenhum achado automatico foi gerado. Isso nao significa ausencia de risco; significa que os coletores nao identificaram condicoes predefinidas de alerta.") | Out-Null
}
else {
    foreach ($finding in $findings) {
        $md.Add("### [$($finding.severity)] $($finding.title)") | Out-Null
        $md.Add("") | Out-Null
        $md.Add("- Categoria: $($finding.category)") | Out-Null
        $md.Add("- Descricao: $($finding.description)") | Out-Null
        if ($finding.evidence) {
            $md.Add("- Evidencia: $($finding.evidence)") | Out-Null
        }
        if ($finding.recommendation) {
            $md.Add("- Recomendacao inicial: $($finding.recommendation)") | Out-Null
        }
        $md.Add("") | Out-Null
    }
}

$md.Add("## Coletores") | Out-Null
$md.Add("") | Out-Null
$md.Add("| Coletor | Status | Duracao (s) | Erro |") | Out-Null
$md.Add("| --- | --- | ---: | --- |") | Out-Null
foreach ($collector in $State.Collectors) {
    $errorText = if ($collector.error) { $collector.error.Replace("|", "\|") } else { "" }
    $md.Add("| $($collector.name) | $($collector.status) | $($collector.duration_seconds) | $errorText |") | Out-Null
}

$md.Add("") | Out-Null
$md.Add("## Dados para IA") | Out-Null
$md.Add("") | Out-Null
$md.Add('Use o arquivo `azure-access-review.json` como entrada preferencial para recomendacoes de seguranca. Ele preserva estrutura, evidencias, roles, subscriptions e resultados brutos normalizados.') | Out-Null
$md.Add("") | Out-Null
$md.Add("Prompt sugerido:") | Out-Null
$md.Add("") | Out-Null
$md.Add('```text') | Out-Null
$md.Add("Analise este relatorio JSON de acesso Azure de uma conta de usuario. Gere recomendacoes priorizadas para reduzir privilegios, melhorar governanca de identidade, proteger recursos sensiveis e aumentar deteccao. Separe a resposta em riscos criticos, acoes de curto prazo, controles estruturais e perguntas de validacao para o analista.") | Out-Null
$md.Add('```') | Out-Null

$mdPath = Join-Path $State.OutputPath "azure-access-review.md"
$md | Set-Content -Path $mdPath -Encoding UTF8
$State.ReportMarkdownPath = $mdPath
