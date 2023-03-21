<#
.DESCRIPTION
    Permission requirements:
    - Azure AD: Application needs to be owner of it's own application.
    - Azure AD: Application requires the application permission Application.ReadWrite.OwnedBy.

    Run Add-AppOwner.ps1 separately for one-time setup of proper permissions on your application.

    https://docs.microsoft.com/en-us/graph/api/resources/application?view-graph-rest-1.0

    .PARAMETER tenantId [string]
    The Tenant ID of the Azure Active Directory in which the app registration and Azure subscription resides.
    .PARAMETER appId [string]
    The app id of the application used to query Defender and to deploy Azure resources.
    .PARAMETER appSecret [string]
    An active secret for the app registration to query Defender and to deploy Azure resources.
    .PARAMETER subscriptionId [string]
    Azure subscription Id in where archive resources should be deployed.
    .PARAMETER resourceGroup [string]
    Name of resource group in which archive resources should be deployed.
    .PARAMETER m365defenderTables [string]
    Single line string and comma-sepparated list of tables you want to setup an archive for.
    Of none provided, this solution will query all tables in Defender and will setup archival on al of them.

#>

[CmdletBinding()]
param (

    [Parameter (Mandatory = $true)]
    [string] $tenantId,

    [Parameter (Mandatory = $true)]
    [string] $appId,

    [Parameter (Mandatory = $true)]
    [string] $appSecret,

    [Parameter (Mandatory = $true)]
    [string] $subscriptionId,

    [Parameter (Mandatory = $true)]
    [string] $resourceGroup,

    [Parameter (Mandatory = $false)]
    [string] $m365defenderTables

)

### M365Defender details

$query = " | getschema | project ColumnName, ColumnType"

### ADX details

$eventHubNamespaceNamePrefix    = "eh-defender-archive"
$adxClusterName                 = "adx-defender-archive"
$adxDatabaseName                = "m365d-archive"
$adxTableRetention              = "365d"
$adxTableRawRetention           = "1d"
$adxScript                      = ""

### Get authorization token

Clear-Host

Write-Host ""
Write-Host "   ▲ Getting access token from api.securitycenter.microsoft.com..." -ForegroundColor Cyan

$resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
$oAuthUri = "https://login.microsoftonline.com/$tenantId/oauth2/token"
$body = [Ordered] @{
    resource      = "$resourceAppIdUri"
    client_id     = "$appId"
    client_secret = "$appSecret"
    grant_type    = 'client_credentials'
}
$response = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $body -ErrorAction Stop
$aadToken = $response.access_token

### Construct header for API requests towards defender

$url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
$headers = @{ 
    'Content-Type' = 'application/json'
    Accept         = 'application/json'
    Authorization  = "Bearer $aadToken" 
}

### Set m365d tables variable to dtermine which tables to process

If ($m365defenderTables) {
    $m365defenderTables = ($m365defenderTables -split (',')).trim()
} else {
    $m365defenderTables = @()
    $body = ConvertTo-Json -InputObject @{ 'Query' = 'search * | distinct table=$table' }
    $webResponse = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
    $m365defenderTables = ($webResponse | ConvertFrom-Json).Results | Select-Object -ExpandProperty table
}

Write-Host "      ─┰─ " -ForegroundColor DarkGray
Write-Host "       ┖─ The folowwing tables will be processed from Microsoft 365 Defender:" -ForegroundColor DarkGray
foreach($table in $m365defenderTables) {
    Write-Host "             - $($table)" -ForegroundColor DarkGray
}

### Loop through all m365d tables, query schema and construct ADX script variable

foreach ($tableName in $m365defenderTables) {

    # Query schema @ Defender
    
    Write-Host "       ┖─ Querying schema for $($tableName) @ Defender..." -ForegroundColor DarkGray

    $body = ConvertTo-Json -InputObject @{ 'Query' = $tableName + $query }
    $webResponse = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
    $response = $webResponse | ConvertFrom-Json
    $results = $response.Results
    $tableSchema = $response.Schema

    # Create ADX commands script

    $tableExpandFunction = $tableName + 'Expand'
    $tableRaw = $tableName + 'Raw'
    $rawMapping = $tableRaw + 'Mapping'

    $tableColumns = @()
    $expandColumns = @()

    # Make sure dataType functions (tostring(), tobool(), tolong() etc.) are added

    foreach ($record in $results) {
        $dataType = $record.ColumnType
        $expandColumns += $record.ColumnName + " = to$($dataType)(events.properties." + $record.ColumnName + "),"

        $tableColumns += $record.ColumnName + ":" + "$dataType" + ","    
    }

    $tableSchema = ($tableColumns -join '') -replace ',$'
    $expandFunction = ($expandColumns -join '') -replace ',$'

    # Create ADX commands

    $createRawTable = '.create table {0} (records:dynamic)' -f $tableRaw
    $CreateRawMapping = @'
.create table {0} ingestion json mapping '{1}' '[{{"Column":"records","Properties":{{"path":"$.records"}}}}]'
'@ -f $TableRaw, $RawMapping
    $createRawTableRetention = '.alter-merge table {0} policy retention softdelete = {1}' -f $tableRaw, $adxTableRawRetention
    $createTable = '.create table {0} ({1})' -f $tableName, $tableSchema
    $createTableRetention = '.alter-merge table {0} policy retention softdelete = {1} recoverability = enabled' -f $tableName, $adxTableRetention
    $createFunction = @'
.create-or-alter function {0} {{{1} | mv-expand events = records | project {2} }}
'@ -f $tableExpandFunction, $tableRaw, $expandFunction
    $createPolicyUpdate = @'
.alter table {0} policy update @'[{{"Source": "{1}", "Query": "{2}()", "IsEnabled": "True", "IsTransactional": true}}]'
'@ -f $tableName, $tableRaw, $tableExpandFunction

    # Write ADX commands to ADX script variable

    Write-Host "           ┖─ Adding ADX commands for $($tableName) to ADX script..." -ForegroundColor DarkGray

    $adxScript = $adxScript + "$createRawTable"
    $adxScript = $adxScript + "`n`n$createRawMapping"
    $adxScript = $adxScript + "`n`n$createRawTableRetention"
    $adxScript = $adxScript + "`n`n$createTable"
    $adxScript = $adxScript + "`n`n$createTableRetention"
    $adxScript = $adxScript + "`n`n$createFunction"
    $adxScript = $adxScript + "`n`n$createPolicyUpdate"
}

$adxScript = $adxScript + "`n"

# Display ADX script
Write-Host ""
Write-Host "       ✓ Done generating ADX script, press any key to display..." -ForegroundColor DarkGreen
Write-Host ""

[void][System.Console]::ReadKey($true)

Write-Host $adxScript -ForegroundColor Cyan
Write-Host "       Press any key to continue..." -ForegroundColor DarkGreen

[void][System.Console]::ReadKey($true)

Clear-Host

### Deploy Azure resources

# Construct Credentials object
$credentials = [ordered]@{
    tenantId            = $tenantId
    serviceprincipalId  = $appId
    servicePrincipalKey = $appSecret
}
# Create PowerShell credential object
$psCred = New-Object System.Management.Automation.PSCredential($credentials.serviceprincipalId , (ConvertTo-SecureString $credentials.servicePrincipalKey -AsPlainText -Force))
# Sign-in to Azure
Write-Host ""
Write-Host "   ▲ Signing in to Azure..." -ForegroundColor Cyan
Add-AzAccount -Credential $psCred -TenantId $credentials.tenantId -ServicePrincipal -SubscriptionId $subscriptionId | Out-Null

# Check if required Azure role prerequisites are met
Write-Host "      ─┰─ " -ForegroundColor DarkGray
Write-Host "       ┖─ Checking if role assignment prerequisites are met..." -ForegroundColor DarkGray
$assignedRoles = Get-AzRoleAssignment | Select-Object RoleDefinitionName -ExpandProperty RoleDefinitionName 
if (!($assignedRoles -contains "Owner")) {
    if (!(($assignedRoles -contains "Contributor") -and ($assignedRoles -contains "User Access Administrator")))
    {
        Write-Host "              ✘ Application permission on Azure resource group '$($resourceGroup)' in subscription '$($subscriptionId)' are insufficient!" -ForegroundColor Red
        Write-Host "                Make sure that appId '$($appId)' is either 'Owner', or both 'Contributor' and 'UserAccess Administrator'" -ForegroundColor Red
        exit
    }
}
Write-Host "              ✓ Role assignment prerequisites are setup correctly" -ForegroundColor Green

### Deploy Azure Event Hub(s)

# Since we can only deply 10 Event Hubs per Event Hub Namespace, we need to determine how many Event Hub Namespaces we'll be needing
Write-Host "       ┃" -ForegroundColor DarkGray
Write-Host "       ┖─ Calculating the amount of Event Hub Namespaces needed..." -ForegroundColor DarkGray

$eventHubNamespacesCount = [int][math]::ceiling($m365defenderTables.Count / 10) 
Write-Host "              ✓ In order to create $($m365defenderTables.Count) Event Hubs, we'll be needing $($eventHubNamespacesCount) Event Hub Namespaces." -ForegroundColor Green

For ($count = 1; $count -le $eventHubNamespacesCount; $count++) {
    $eventHubNamespaceName = "$($eventHubNamespaceNamePrefix)-0$($count)"
    $eventHubNames = $m365defenderTables | Select-Object -First 10 -Skip (($count - 1) * 10) # Select ten tables for event hub creating
    
    if(1 -eq $count) {
        Write-Host "                ─┰─ " -ForegroundColor DarkGray
    } else {
        Write-Host "                 ┃" -ForegroundColor DarkGray
    }
    Write-Host "                 ┖─ Deploying Event Hub Namespace $($count) / $($eventHubNamespacesCount)..." -ForegroundColor DarkGray
    Write-Host "                     ┖─ Event Hub Namespace '$($eventHubNamespaceName)'" -ForegroundColor DarkGray
    foreach($eventHubName in $eventHubNames) {
        Write-Host "                         ┖─ Event Hub '$($eventHubName)'" -ForegroundColor DarkGray
    }

    try {
        New-AzResourceGroupDeployment `
            -ResourceGroupName $resourceGroup `
            -TemplateFile ../arm.templates/eventhub.template.json `
            -namespaceName $eventHubNamespaceName `
            -eventHubNames $eventHubNames
    }
    catch {
        Write-Host ""
        Write-Host "                 ✘ There was a problem deploying to Azure! Exiting..." -ForegroundColor Red
        Write-Host ""
        exit
    }

}

### Deploy Azure Data Explorer