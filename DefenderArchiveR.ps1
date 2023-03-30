<#
.DESCRIPTION
    Permission requirements:
    - Azure AD Application needs ThreatHunting.Read.All on Microsoft Graph.
    - User running this script should be Owner, or both contributor and User Access Administrator, on the Azure subscription.

    .PARAMETER tenantId [string]
    The Tenant ID of the Azure Active Directory in which the app registration and Azure subscription resides.
    .PARAMETER appId [string]
    The App ID of the application used to query Microsoft Graph to retrieve Defender table schemas.
    .PARAMETER appSecret [string]
    An active secret for the App Registration to query Microsoft Graph to retrieve Defender table schemas.
    .PARAMETER subscriptionId [string]
    Azure Subscription ID in which the archive resources should be deployed.
    .PARAMETER resourceGroupName [string]
    Name of the Resource Group in which archive resources should be deployed.
    .PARAMETER m365defenderTables [string]
    Comma-separated list of tables you want to setup an archive for. Keep in mind to user proper "PascalCase" for table names!
    If this parameter is not provided, the script will use all tables supported by streaming API, and will setup archival on all of them.
    .PARAMETER outputAdxScript [switch]
    Used for debugging purposes so that the script will output the ADX script on screen before it gets passed into the deployments.
    .PARAMETER saveAdxScript [switch]
    Use -savedAdxScript to write content of $adxScript to 'adxScript.kusto' file. File can be re-used with -useAdxScript parameter.
    .PARAMETER useAdxScriptFile [string]
    Provide path to existing 'adxScript.kusto' file created by -saveAdxScript parameter.
    .PARAMETER skipPreReqChecks [switch]
    Skip Azure subscription checks like checking enabled resource providers and current permissions. Useful when using this script in a pipeline where you're already sure of these prerequisites.
    .PARAMETER noDeploy [switch]
    Used for debugging purposes so that the actual Azure deployment steps are skipped.
    .PARAMETER deploySentinelFunctions [switch]
    Use -deploySentinelFunctions to add optional step to the deployment process where (Sentinel) workspace functions are deployed (savedSearches) to be able to query ADX from Log Analytics / Sentinel UI.

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
    [string] $resourceGroupName,

    [Parameter (Mandatory = $false)]
    [string] $m365defenderTables,

    [Parameter (Mandatory = $false)]
    [switch] $outputAdxScript,

    [Parameter (Mandatory = $false)]
    [switch] $saveAdxScript,

    [Parameter (Mandatory = $false)]
    [string] $useAdxScriptFile,

    [Parameter (Mandatory = $false)]
    [switch] $skipPreReqChecks,

    [Parameter (Mandatory = $false)]
    [switch] $noDeploy,

    [Parameter (Mandatory = $false)]
    [switch] $deploySentinelFunctions
)

### Environment specific variables

$eventHubNamespaceNamePrefix    = "eh-defender-archive"     # number-suffix ('-01', '-02', '-03') will be added during deployment
$adxClusterName                 = "adx-defender-archive"    # Cannot exceed 22 characters!
$adxDatabaseName                = "m365d-archive"
$adxDatabasePermissionsRole     = "viewers"
$adxDatabasePermissionsTenant   = "sqn.international"
$adxDatabasePermissionsGroup    = "SQN Admin Accounts"
$adxTableRetention              = "365d"
$adxTableRawRetention           = "1d"
$adxScript                      = ""
$adxScriptFile                  = "adxScript.kusto"

$sentinelWorkspaceName          = "sqn-sentinel-01"
$sentinelWorkspaceResourceGroup = "rg-security-01" 

### M365Defender details

$query                          = " | getschema | project ColumnName, ColumnType"
# Supported tables for streaming to Event Hub as of time of writing. Update accordingly if applicable
$m365defenderSupportedTables    = @(
    "AlertInfo",
    "AlertEvidence",
    "DeviceInfo",
    "DeviceNetworkInfo",
    "DeviceProcessEvents",
    "DeviceNetworkEvents",
    "DeviceFileEvents",
    "DeviceRegistryEvents",
    "DeviceLogonEvents",
    "DeviceImageLoadEvents",
    "DeviceEvents",
    "DeviceFileCertificateInfo",
    "EmailAttachmentInfo",
    "EmailEvents",
    "EmailPostDeliveryEvents",
    "EmailUrlInfo",
    "UrlClickEvents",
    "IdentityLogonEvents",
    "IdentityQueryEvents",
    "IdentityDirectoryEvents",
    "CloudAppEvents"
)

# If m365defenderTables parameter was used; contents need to be prepped (split and trimmed)
# If no specific tables are passed in parameter, it will use all supported tables
$exit = $false
If ($m365defenderTables) {
    # Proces m365defenderTables parameter (split and trim) into array
    $m365defenderTables = ($m365defenderTables -split (',')).trim()
    foreach ($table in $m365defenderTables) {
        # Check if all provided table names are support by streaming API
        if (!($m365defenderSupportedTables -contains $table)) {
            Write-Host " ✘ Invalid 'm365defenderTables' parameter!" -ForegroundColor Red
            Write-Host "   Table name '$($Table)' is currently not supported by streaming API." -ForegroundColor Red
            Write-Host ""
            $exit = $true
        }
    }
    if ($exit) { 
        exit
    }
} else {
    $m365defenderTables = $m365defenderSupportedTables
}

Clear-Host

Write-Host "                                                                    "
Write-Host "           Microsoft 365 Defender                                   " -ForegroundColor DarkBlue
Write-Host "         _______             ______ _____            ________       " -ForegroundColor DarkGreen
Write-Host "        ____    |_______________  /____(_)__   _________  __ \      " -ForegroundColor DarkGreen
Write-Host "      _____  /| |_  ___/  ___/_  __ \_  /__ | / /  _ \_  /_/ /      " -ForegroundColor DarkGreen
Write-Host "     _____  ___ |  /   / /__ _  / / /  / __ |/ //  __/  _, _/       " -ForegroundColor DarkGreen
Write-Host "    _____/_/  |_/_/    \___/ /_/ /_//_/  _____/ \___//_/ |_|        " -ForegroundColor DarkGreen
Write-Host " ╱──────────────┬─────────────────────────────┬───────────────╱     " -ForegroundColor DarkGray
Write-Host "                │ AZURE DATA EXPLORER EDiTION │                     " -ForegroundColor DarkGray
Write-Host "                └─────────────────────────────┘                     " -ForegroundColor DarkGray
Write-Host "                                                                    "

### Construct AdxScript with all ADX commands for appropriate tables and schemas

If (!($useAdxScriptFile)) {

    # Get AAD authorization token

    Write-Host "   ▲ Getting access token from api.securitycenter.microsoft.com..." -ForegroundColor Cyan

    $scope = 'https://graph.microsoft.com/.default'
    $oAuthUri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    $body = [Ordered] @{
        scope         = $scope
        client_id     = "$appId"
        client_secret = "$appSecret"
        grant_type    = 'client_credentials'
    }
    $response = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $body -ErrorAction Stop
    $aadToken = $response.access_token

    # Construct header for API requests towards AdvancedHunting API

    $url = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
    $headers = @{ 
        'Content-Type' = 'application/json'
        Authorization  = "Bearer $aadToken" 
    }

    # Output all tables that will be processed for schema query

    Write-Host "      ─┰─ " -ForegroundColor Gray
    Write-Host "       ┖─ The folowwing tables will be processed from Microsoft 365 Defender:" -ForegroundColor Gray
    foreach ($table in $m365defenderTables) {
        Write-Host "             - $($table)" -ForegroundColor Gray
    }

    # Loop through all m365d tables, query schema and construct ADX script variable

    foreach ($tableName in $m365defenderTables) {

        # Query schema @ AdvancedHunting API
        Write-Host "       ┖─ Querying schema for '$($tableName)' @ AdvancedHunting API..." -ForegroundColor Gray

        $body = ConvertTo-Json -InputObject @{ 'Query' = $tableName + $query }
        
        # Query API and retry if timeout occurs
        try {
            For ($retry = 0; $retry -le 5; $retry++) {
                try {
                    $webResponse = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
                    $retry = 5
                } catch {
                    Write-Host "              ! Timeout occured while querying the AdvancedHunting API! Retrying..." -ForegroundColor Yellow
                }
            }
        } catch {
            Write-Host "              ✘ Something went wrong while querying the AdvancedHunting API!" -ForegroundColor Red
            Write-Host ""
            exit
        }
        $response               = $webResponse | ConvertFrom-Json
        $results                = $response.Results
        $tableSchema            = $response.Schema

        # Create ADX commands script

        $tableExpandFunction    = $tableName + 'Expand'
        $tableRaw               = $tableName + 'Raw'
        $rawMapping             = $tableRaw + 'Mapping'

        $tableColumns           = @()
        $expandColumns          = @()

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
.create-or-alter table {0} ingestion json mapping '{1}' '[{{"Column":"records","Properties":{{"path":"$.records"}}}}]'
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

        Write-Host "           ┖─ Adding ADX commands for $($tableName) to ADX script..." -ForegroundColor Gray

        $adxScript = $adxScript + "`n$createRawTable`n"
        $adxScript = $adxScript + "`n$createRawMapping`n"
        $adxScript = $adxScript + "`n$createRawTableRetention`n"
        $adxScript = $adxScript + "`n$createTable`n"
        $adxScript = $adxScript + "`n$createTableRetention`n"
        $adxScript = $adxScript + "`n$createFunction`n"
        $adxScript = $adxScript + "`n$createPolicyUpdate`n"
    }

    # Add ADX database permissions
    $createTablePermissions = ".add database ['{0}'] {1} ('aadgroup={2};{3}')" -f $adxDatabaseName, $adxDatabasePermissionsRole, $adxDatabasePermissionsGroup, $adxDatabasePermissionsTenant
    $adxScript = $adxScript + "`n$createTablePermissions`n"

    # Add empty line at end
    $adxScript = $adxScript + "`n"

    # Display ADX script (optional depending on outputAdxScript switch)
    If ($outputAdxScript) {
        Write-Host "              ✓ Done generating ADX script, press any key to display..." -ForegroundColor DarkGreen
        Write-Host ""
        # write adxScript to file
        If ($saveAdxScript) {
            New-Item $adxScriptFile -Force | Out-Null
            Add-Content $adxScriptFile $adxScript 
            Write-Host "              ✓ ADX script written to file '$($adxScriptFile)'" -ForegroundColor DarkGreen
            Write-Host ""
        }

        [void][System.Console]::ReadKey($true)

        Clear-Host
        Write-Host $adxScript -ForegroundColor Magenta
        Write-Host "                Press any key to continue..." -ForegroundColor DarkGreen

        [void][System.Console]::ReadKey($true)
        Clear-Host
    } else {
        Write-Host "              ✓ Done generating ADX script!" -ForegroundColor DarkGreen
        Write-Host ""
        # write adxScript to file
        If ($saveAdxScript) {
            New-Item $adxScriptFile -Force | Out-Null
            Add-Content $adxScriptFile $adxScript 
            Write-Host "              ✓ ADX script written to file '$($adxScriptFile)'" -ForegroundColor DarkGreen
        }
    }

} else {
    Write-Host ""
    Write-Host "   ✓ Using previously created adxScript file: '$($adxScriptFile)'." -ForegroundColor Magenta
    $adxScript = Get-Content -Path $adxScriptFile -Raw
}

### Deploy Azure resources

# Sign-in to Azure
Write-Host ""
Write-Host "   ▲ Signing in to Azure..." -ForegroundColor Cyan

# Check if already connected to Azure
if(!(Get-AzContext)) {
    Add-AzAccount -TenantId $tenantId -SubscriptionId $subscriptionId | Out-Null
    Start-Sleep -Seconds 2
}

# Check Azure prerequisites or skip is -skipPreReqChecks was used
Write-Host "      ─┰─ " -ForegroundColor Gray
Write-Host "       ┖─ Checking if role assignment prerequisites are met..." -ForegroundColor Gray
if (!($skipPreReqChecks)) {

    $assignedRoles = Get-AzRoleAssignment | Select-Object RoleDefinitionName -ExpandProperty RoleDefinitionName 
    if (!($assignedRoles -contains "Owner")) {
        if (!(($assignedRoles -contains "Contributor") -and ($assignedRoles -contains "User Access Administrator"))) {
            Write-Host "              ✘ Application permission on Azure resource group '$($resourceGroupName)' in subscription '$($subscriptionId)' are insufficient!" -ForegroundColor Red
            Write-Host "                Make sure that appId '$($appId)' is either 'Owner', or both 'Contributor' and 'UserAccess Administrator'" -ForegroundColor Red
            Write-Host ""
            exit
        }
    }
    Write-Host "              ✓ Role assignment prerequisites are setup correctly" -ForegroundColor DarkGreen

    # Check if required Azure resource providers are registered
    Write-Host "       ┃" -ForegroundColor Gray
    Write-Host "       ┖─ Checking if Azure resource providers are registered..." -ForegroundColor Gray

    try {
        $resourceProviderEventHubStatus = Get-AzResourceProvider -ProviderNamespace Microsoft.EventHub | Select-Object -ExpandProperty RegistrationState
        $resourceProviderKustoStatus    = Get-AzResourceProvider -ProviderNamespace Microsoft.Kusto | Select-Object -ExpandProperty RegistrationState
    } catch {
        try {
            $resourceProviderEventHubStatus = Get-AzResourceProvider -ProviderNamespace Microsoft.EventHub | Select-Object -ExpandProperty RegistrationState
            $resourceProviderKustoStatus    = Get-AzResourceProvider -ProviderNamespace Microsoft.Kusto | Select-Object -ExpandProperty RegistrationState
        } catch {
            Write-Host "              ✘ There were timeouts while retrieving the Azure resource provider statuses. Exiting..." -ForegroundColor Red
            Write-Host ""
            exit
        }
    }

    $exit = $false
    if (($resourceProviderEventHubStatus -contains "Unregistered")) {
        Write-Host "              ✘ Azure resource provider 'Microsoft.EventHub' is not registered on subscription '$($subscriptionId)'!" -ForegroundColor Red
        Write-Host "                Please register this resource provider and try again." -ForegroundColor Red
        $exit = $true
    }
    if (($resourceProviderKustoStatus -contains "Unregistered")) {
        Write-Host "              ✘ Azure resource provider 'Microsoft.Kusto' is not registered on subscription '$($subscriptionId)'!" -ForegroundColor Red
        Write-Host "                Please register this resource provider and try again." -ForegroundColor Red
        $exit = $true
    }
    if ($exit) {
        Write-Host ""
        exit
    }

    Write-Host "              ✓ All required Azure resource providers are registered properly" -ForegroundColor DarkGreen
} else {
    Write-Host ""
    Write-Host "             ✓ Parameter 'skipPreReqChecks' was used. Skipping Azure prerequisites checks." -ForegroundColor Magenta
    Write-Host ""
}

### Deploy Azure Event Hub(s)

# Since we can only deply 10 Event Hubs per Event Hub Namespace, we need to determine how many Event Hub Namespaces we'll be needing
Write-Host "       ┃" -ForegroundColor Gray
Write-Host "       ┖─ Calculating the amount of Event Hub Namespaces needed..." -ForegroundColor Gray

$eventHubNamespacesCount = [int][math]::ceiling($m365defenderTables.Count / 10) 
Write-Host "              ✓ In order to create $($m365defenderTables.Count) Event Hubs, we'll be needing $($eventHubNamespacesCount) Event Hub Namespaces." -ForegroundColor DarkGreen

For ($count = 1; $count -le $eventHubNamespacesCount; $count++) {
    $deploymentName         = "EventHubNamespace-$(Get-Date -Format "yyyMMdd-HHmmss")"
    $eventHubNamespaceName  = "$($eventHubNamespaceNamePrefix)-0$($count)"
    # Select ten tables for each Event Hub Namespace, make them lowercase and add prefix
    $eventHubNames = $m365defenderTables.ToLower() | Select-Object -First 10 -Skip (($count - 1) * 10) | Foreach-Object { "insights-logs-advancedhunting-$_" }
    
    if (1 -eq $count) {
        Write-Host "                ─┰─ " -ForegroundColor Gray
    } else {
        Write-Host "                 ┃" -ForegroundColor Gray
    }
    Write-Host "                 ┖─ Deploying Event Hub Namespace [ $($count) / $($eventHubNamespacesCount) ] - '$($deploymentName)'..." -ForegroundColor Gray
    Write-Host "                     ┖─ Event Hub Namespace '$($eventHubNamespaceName)'" -ForegroundColor Gray
    foreach ($eventHubName in $eventHubNames) {
        Write-Host "                         ┖─ Event Hub '$($eventHubName)'" -ForegroundColor Gray
    }

    If (!$noDeploy) {
        try {
            $deployment = New-AzResourceGroupDeployment `
                -Name $deploymentName `
                -ResourceGroupName $resourceGroupName `
                -TemplateFile ./arm-templates/eventhub.template.json `
                -eventHubNamespaceName $eventHubNamespaceName `
                -eventHubNames $eventHubNames
            If ($deployment.ProvisioningState -eq "Succeeded") {
                Write-Host "                      ✓ Deployment of '$($eventHubNamespaceName)' was successful" -ForegroundColor DarkGreen
                Write-Host ""
                Write-Host "                              $($deployment.outputs.eventHubNamespaceResourceId.value)" -ForegroundColor Magenta
                Write-Host "                                   ˆ-- Note down this resource ID for setting up Streaming API in Microsoft 365 Defender later" -ForegroundColor Yellow
            } else {
                Write-Host "                      ! There was an issue deploying '$($eventHubNamespaceName)' please check deployment '$($deployment.DeploymentName)'!" -ForegroundColor Yellow
            }
        } catch {
            Write-Host ""
            Write-Host "                     ✘ There was a problem deploying to Azure! Exiting..." -ForegroundColor Red
            Write-Host ""
            exit
        }
    } else {
        Write-Host "                     ! Switch 'noDeploy' was provided, skipping Azure deployment..." -ForegroundColor Magenta
    }

}

### Deploy Azure Data Explorer

For ($count = 1; $count -le $eventHubNamespacesCount; $count++) {
    $deploymentName         = "DataExplorer-$(Get-Date -Format "yyyMMdd-HHmmss")"
    $eventHubNamespaceName  = "$($eventHubNamespaceNamePrefix)-0$($count)"
    # Select ten tables for each Event Hub Namespace, make them lowercase and add prefix
    $tableNames = $m365defenderTables | Select-Object -First 10 -Skip (($count - 1) * 10)
    
    if (1 -eq $count) {
        Write-Host "                 ┃" -ForegroundColor Gray
        Write-Host "                 ┖─ Deploying Azure Data Explorer Cluster - '$($deploymentName)'..." -ForegroundColor Gray
        Write-Host "                     ┖─ ADX cluster name '$($adxClusterName)'" -ForegroundColor Gray
        Write-Host "                         ┖─ Database name '$($adxDatabaseName)'" -ForegroundColor Gray
    }
    foreach($tableName in $tableNames) {
        Write-Host "                             ┖─ Data Connection 'dc-$($tableName)'" -ForegroundColor Gray
    }

    If (!$noDeploy) {
        try {
            $deployment = New-AzResourceGroupDeployment `
                -Name $deploymentName `
                -ResourceGroupName $resourceGroupName `
                -TemplateFile ./arm-templates/dataexplorer.template.json `
                -adxClusterName $adxClusterName `
                -adxDatabaseName $adxDatabaseName `
                -adxScript $adxScript `
                -eventHubNamespaceName $eventHubNamespaceName `
                -tableNames $tableNames
            If ($deployment.ProvisioningState -eq "Succeeded") {
                Write-Host "                      ✓ Deployment of '$($adxClusterName)' was successful" -ForegroundColor DarkGreen
                Write-Host ""
            } else {
                Write-Host "                      ! There was an issue deploying '$($adxClusterName)' please check deployment '$($deployment.DeploymentName)'!" -ForegroundColor Yellow
            }
        } catch {
            Write-Host ""
            Write-Host "                     ✘ There was a problem deploying to Azure! Exiting..." -ForegroundColor Red
            Write-Host ""
            exit
        }
    } else {
        Write-Host "                     ! Switch 'noDeploy' was provided, skipping Azure deployment..." -ForegroundColor Magenta
    }
}

### Set Managed Identity Permissions

# Get ADX Cluster resourceId
Write-Host "      ─┰─ " -ForegroundColor Gray
Write-Host "       ┖─ Looking for ADX System-Assigned Managed Identity..." -ForegroundColor Gray

$azureRole          = "Azure Event Hubs Data Receiver"  

try {
    $adxResource        = Get-AzResource | Where-Object { $_.Name -eq "$adxClusterName" }
    $managedIdentity    = (Get-AzResource -ResourceId $adxResource.ResourceId).Identity.PrincipalId
    Write-Host "          ✓ Found Managed Identity with ID '$($managedIdentity)'" -ForegroundColor DarkGreen      
} catch {
    Write-Host ""
    Write-Host "           ✘ There was a problem finding the Managed Identity! Exiting..." -ForegroundColor Red
    exit
}

Write-Host ""
Write-Host "           ┖─ Assigning role '$($azureRole)' to Resource Group '$($resourceGroupName)'..." -ForegroundColor Gray


If (!$noDeploy) {
    $paramHash = @{
        ObjectId           = $managedIdentity
        RoleDefinitionName = $AzureRole
        ResourceGroupName  = $resourceGroupName
        WarningAction      = 'SilentlyContinue'
    }

    # Check if role is already assigned to avoid errors
    try {
        $RoleAssignment = Get-AzRoleAssignment @paramHash -ErrorAction stop
    } catch {
        Write-Host ""
        Write-Host "              ✘ An error occured while retrieving permissions for '$($managedIdentity)'. Check if Managed Identity is enabled within the Data Explorer cluster."
    }

    # Assign permissions to Managed Identities
    if ($null -eq $RoleAssignment) {
        try {
            $null = New-AzRoleAssignment @paramHash -ErrorAction stop
            Write-Host "                  ✓ Role '$($azureRole)' assigned" -ForegroundColor DarkGreen
        }
        catch {
            Write-Host ""
            Write-Host "                  ✘ An error occured while assigning '$($azureRole)' for '$($managedIdentity)' to '$($resourceGroupName)'."
        }
    }
    else {
        Write-Host "                  ✓ Role '$($azureRole)' was already assigned" -ForegroundColor DarkGreen
    }
}
else {
    Write-Host "                  ! Switch 'noDeploy' was provided, skipping Azure deployment..." -ForegroundColor Magenta
}
Write-Host ""

### Deploy Sentinel workspace functions (savedSearches) [ OPTIONAL ]

if ($deploySentinelFunctions) {
    $deploymentName = "SavedSearches-$(Get-Date -Format "yyyMMdd-HHmmss")"

    Write-Host "      ─┰─ " -ForegroundColor Gray
    Write-Host "       ┖─ Deploying Sentinel workspace functions - '$($deploymentName)'..." -ForegroundColor Gray
    Write-Host "           ┖─ Log Analytics Workspace name '$($sentinelWorkspaceName)'" -ForegroundColor Gray

    If (!$noDeploy) {
        try {
            # Concatenate ADX cluster Uri
            $adxClusterName = $adxClusterName + "." + (Get-AzResourceGroup $sentinelWorkspaceResourceGroup).Location + ".kusto.windows.net"
            
            $deployment = New-AzResourceGroupDeployment `
                -Name $deploymentName `
                -ResourceGroupName $sentinelWorkspaceResourceGroup `
                -TemplateFile arm-templates/workspacefunctions.template.json `
                -workspaceName $sentinelWorkspaceName `
                -adxClusterName $adxClusterName `
                -adxDatabaseName $adxDatabaseName
            If ($deployment.ProvisioningState -eq "Succeeded") {
                Write-Host "                 ✓ Deployment of savedSearches in workspace '$($sentinelWorkspaceName)' was successful" -ForegroundColor DarkGreen
                Write-Host ""
            }
            else {
                Write-Host "                 ! There was an issue deploying to '$($sentinelWorkspaceName)' please check deployment '$($deployment.DeploymentName)'!" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host ""
            Write-Host "                 ✘ There was a problem deploying to Azure! Exiting..." -ForegroundColor Red
            Write-Host ""
            exit
        }
    }
    else {
        Write-Host "                 ! Switch 'noDeploy' was provided, skipping Azure role assignment..." -ForegroundColor Magenta
    }
}
Write-Host ""