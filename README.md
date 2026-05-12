# Azure User Access Review Toolkit

Conjunto de scripts PowerShell para avaliar, de forma read-only, quais acessos e informações uma conta de usuário consegue obter em um ambiente Azure/Entra ID.

O objetivo é apoiar analistas de segurança a entenderem a exposição real de uma conta: tenants acessíveis, identidade autenticada, roles, escopos RBAC, recursos visíveis, permissões efetivas em serviços sensíveis e achados que merecem revisão.

## O que o toolkit coleta

- Contexto de autenticação Azure e Microsoft Graph.
- Subscriptions visíveis e roles RBAC efetivas.
- Inventário de recursos Azure visíveis pela conta.
- Metadados de Key Vaults, Storage Accounts, VMs, NSGs e IPs públicos.
- Dados Entra ID/Graph permitidos ao token usado, incluindo usuário atual, grupos, objetos possuídos, roles administrativas e principals privilegiados.
- Relatórios em Markdown e JSON para revisão humana ou automação.

Por padrão, o toolkit não coleta valores de segredos, chaves privadas, conteúdo de blobs, dados de bancos ou payloads de máquinas virtuais.

## Saídas

Cada execução cria uma pasta em `.\reports\azure-access-review-<timestamp>` com:

- `azure-access-review.json`: resultado estruturado para automação ou envio a uma IA.
- `azure-access-review.md`: relatório humano com resumo executivo, achados e evidências.
- `raw\*.json`: respostas brutas normalizadas por coletor.
- `run-metadata.json`: parâmetros, timestamps e versões relevantes.

## Requisitos

- PowerShell 5.1+ ou PowerShell 7+.
- Módulos PowerShell para coleta Azure:
  - `Az.Accounts`
  - `Az.Resources`
  - `Az.KeyVault`
  - `Az.Storage`
  - `Az.Compute`
  - `Az.Network`
- Módulos Microsoft Graph somente se usar `-GraphMode Sdk`:
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Users`
  - `Microsoft.Graph.Groups`
  - `Microsoft.Graph.Applications`
  - `Microsoft.Graph.Identity.DirectoryManagement`

Instalação sugerida:

```powershell
Install-Module Az -Scope CurrentUser
Install-Module Microsoft.Graph -Scope CurrentUser
```

Esses comandos instalam módulos "rollup": `Az` traz os submódulos Azure usados pelo script, como `Az.Accounts`, `Az.Resources`, `Az.KeyVault`, `Az.Storage`, `Az.Compute` e `Az.Network`; `Microsoft.Graph` traz os submódulos do SDK, incluindo os usados pelo modo `-GraphMode Sdk`. Isso depende de acesso à PSGallery e resolução normal de dependências pelo PowerShellGet/PSResourceGet.

Em ambientes restritos, você pode instalar somente os submódulos necessários:

```powershell
Install-Module Az.Accounts,Az.Resources,Az.KeyVault,Az.Storage,Az.Compute,Az.Network -Scope CurrentUser
Install-Module Microsoft.Graph.Authentication,Microsoft.Graph.Users,Microsoft.Graph.Groups,Microsoft.Graph.Applications,Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
```

Se a organização usa repositório interno de módulos PowerShell, instale os mesmos módulos a partir da fonte aprovada.

## Uso rápido

Execute a partir da pasta do projeto:

```powershell
.\Invoke-AzureAccessReview.ps1
```

Se a máquina bloquear scripts pela Execution Policy local, execute em um processo temporário com bypass:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-AzureAccessReview.ps1
```

Por padrão, o script cria a saída em `.\reports` e usa `-GraphMode Auto`.

## Exemplos comuns

Selecionar tenants ou subscriptions específicos:

```powershell
.\Invoke-AzureAccessReview.ps1 `
  -TenantIds "11111111-1111-1111-1111-111111111111" `
  -SubscriptionIds "00000000-0000-0000-0000-000000000000"
```

Alterar a pasta de saída:

```powershell
.\Invoke-AzureAccessReview.ps1 -OutputRoot ".\reports\cliente-a"
```

Executar apenas coleta Graph/Entra ID, sem enumerar recursos Azure:

```powershell
.\Invoke-AzureAccessReview.ps1 -SkipResourceEnumeration
```

Executar apenas coleta Azure/RBAC, sem Graph:

```powershell
.\Invoke-AzureAccessReview.ps1 -SkipGraph
```

Reutilizar somente sessões já existentes, sem abrir login interativo:

```powershell
.\Invoke-AzureAccessReview.ps1 -UseExistingSessionOnly
```

Forçar novo login interativo:

```powershell
.\Invoke-AzureAccessReview.ps1 -ForceLogin
```

Usar device code quando o browser interativo não abrir corretamente:

```powershell
.\Invoke-AzureAccessReview.ps1 -ForceLogin -UseDeviceCode
```

Exigir que o token Graph pertença a uma conta específica:

```powershell
.\Invoke-AzureAccessReview.ps1 -GraphMode Rest -ExpectedAccountUpn usuario@dominio.gov.br
```

## Enumeração profunda

Use `-DeepEnumerate` para tentativas read-only mais detalhadas quando a conta tiver permissão:

```powershell
.\Invoke-AzureAccessReview.ps1 -DeepEnumerate
```

Esse modo pode tentar:

- listar containers, filas e tabelas de Storage Accounts usando a conta conectada;
- enriquecer principals privilegiados com detalhes de usuário;
- consultar grupos, dispositivos registrados e dispositivos possuídos;
- consultar métodos de autenticação cadastrados sem coletar segredos;
- listar assignments ativos e elegíveis de roles administrativas.

Para controlar volume de principals privilegiados:

```powershell
.\Invoke-AzureAccessReview.ps1 -GraphMode Rest -DeepEnumerate -PrivilegedAccountLimit 100
```

Use `-DeepEnumerate` somente em janelas aprovadas de auditoria, pois mesmo operações read-only podem gerar logs, alertas e custos em ambientes grandes.

## Modos Microsoft Graph

O parâmetro `-GraphMode` aceita:

- `Auto`: prefere importação do Graph Explorer quando um arquivo for informado, depois REST, depois SDK.
- `Rest`: usa `Invoke-RestMethod` direto contra Microsoft Graph, sem carregar módulos `Microsoft.Graph.*`.
- `Sdk`: usa os módulos PowerShell `Microsoft.Graph.*`.
- `ExplorerExport`: importa respostas salvas manualmente a partir do Graph Explorer.

### REST com Az.Accounts

```powershell
.\Invoke-AzureAccessReview.ps1 -GraphMode Rest
```

Para reduzir risco de herdar login anterior, quando o script não é executado com `-UseExistingSessionOnly`, ele limpa o contexto Az do processo antes de autenticar. Se você quiser preservar explicitamente o contexto Az do processo:

```powershell
.\Invoke-AzureAccessReview.ps1 -GraphMode Rest -PreserveAzContext
```

Para limpar também antes de obter token Graph:

```powershell
.\Invoke-AzureAccessReview.ps1 -GraphMode Rest -ForceLogin -UseDeviceCode -ClearAzContext
```

### REST com token delegado informado

Também é possível fornecer um token delegado aprovado pelo analista. O token não é persistido no relatório.

Via parâmetro:

```powershell
.\Invoke-AzureAccessReview.ps1 -GraphMode Rest -GraphAccessToken "<token-delegado-aprovado>"
```

Via variável de ambiente:

```powershell
$env:AZURE_ACCESS_REVIEW_GRAPH_TOKEN = "<token-delegado-aprovado>"
.\Invoke-AzureAccessReview.ps1 -GraphMode Rest
Remove-Item Env:\AZURE_ACCESS_REVIEW_GRAPH_TOKEN
```

### Graph Explorer Export

Importar respostas do Graph Explorer:

```powershell
.\Invoke-AzureAccessReview.ps1 `
  -GraphMode ExplorerExport `
  -GraphExplorerExportPath .\examples\graph-explorer-export.sample.json
```

Modelo mínimo:

```json
{
  "me": {},
  "organization": { "value": [] },
  "memberOf": { "value": [] },
  "ownedObjects": { "value": [] },
  "directoryRoles": { "value": [] },
  "applications": { "value": [] },
  "servicePrincipals": { "value": [] }
}
```

Endpoints sugeridos para coletar no Graph Explorer:

- `/me?$select=id,displayName,userPrincipalName,accountEnabled,createdDateTime,userType`
- `/organization?$select=id,displayName,verifiedDomains`
- `/me/memberOf?$top=100&$select=id,displayName,description`
- `/me/ownedObjects?$top=100&$select=id,displayName,appId`
- `/directoryRoles?$top=100&$select=id,displayName,description,roleTemplateId`
- `/applications?$top=100&$select=id,appId,displayName,signInAudience,publisherDomain`
- `/servicePrincipals?$top=100&$select=id,appId,displayName,servicePrincipalType,accountEnabled`

## Parâmetros principais

| Parâmetro | Descrição |
| --- | --- |
| `-TenantIds` | Filtra tenants usados na coleta. |
| `-SubscriptionIds` | Filtra subscriptions usadas na coleta Azure/RBAC. |
| `-OutputRoot` | Define a pasta base de saída. Padrão: `.\reports`. |
| `-DeepEnumerate` | Habilita enumeração read-only mais detalhada. |
| `-UseExistingSessionOnly` | Não abre login; usa apenas sessões existentes. |
| `-ForceLogin` | Força chamada de login interativo ou device code. |
| `-UseDeviceCode` | Usa device code com `Connect-AzAccount`. |
| `-ClearAzContext` | Limpa o contexto Az do processo antes da autenticação/token. |
| `-PreserveAzContext` | Preserva contexto Az existente no processo. |
| `-ExpectedAccountUpn` | Falha se o token Graph não pertencer ao UPN esperado. |
| `-SkipGraph` | Ignora coletores Microsoft Graph/Entra ID. |
| `-SkipResourceEnumeration` | Ignora inventário de recursos Azure. |
| `-PrivilegedAccountLimit` | Limita principals privilegiados retornados. Padrão: `200`. |
| `-GraphMode` | Seleciona `Auto`, `Rest`, `Sdk` ou `ExplorerExport`. |
| `-GraphAccessToken` | Token Graph delegado fornecido diretamente. |
| `-GraphExplorerExportPath` | Caminho para JSON exportado do Graph Explorer. |
| `-GraphBaseUri` | Base URI do Graph. Padrão: `https://graph.microsoft.com/v1.0`. |

## Interpretação dos resultados

O campo `capability_summary` no JSON e a seção "Resumo de capacidades" no Markdown respondem:

- O que a conta consegue ver?
- Em quais subscriptions e escopos ela tem permissões?
- Ela aparenta conseguir modificar IAM, recursos, segredos, storage ou computação?
- Quais controles devem ser revisados primeiro?

O relatório também inclui `account_summary` com a conta avaliada, tenant, object ID, conta do contexto Az, subscription ativa, app/client ID do token Graph e escopos do token quando essas informações puderem ser inferidas sem gravar o token.

## Observações de segurança

- Execute somente com autorização e em janelas aprovadas de auditoria.
- O toolkit prioriza metadados e permissões efetivas; ele não deve ser usado para extrair segredos ou dados de negócio.
- Os achados automáticos são triagem inicial. Revise o JSON e valide com o contexto do tenant antes de tomar decisões de remediação.
- Falhas em chamadas Graph normalmente indicam falta de escopo delegado, consentimento, política de tenant ou bloqueio por aplicação.
