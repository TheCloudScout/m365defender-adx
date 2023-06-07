$tenantId       = ''
$appId          = ''
$appSecret      = ''

$m365defenderSupportedTables = @(
    "IdentityQueryEvents",
    "IdentityDirectoryEvents",
    "CloudAppEvents"
)

$tableStatisticsFile = "tableStatistics.json"
$allTablesThroughput = @()

$tableMBThroughputQuery = @'
    let TimeFilter = "where Timestamp between (startofday(ago(1d)) .. endofday(ago(1d)))";
    <TABLE>
    | getschema
    | summarize CalculateStringLengths = array_strcat(make_list(strcat("strlen(tostring(", ColumnName, "))")), " + ")
    | project strcat("<TABLE>", " | ", TimeFilter, " | project totalLengthBytes = ", CalculateStringLengths, " | summarize totalThroughputGB = sum(totalLengthBytes) / (1024 * 1024) * 2")
'@

function Query-AdvancedHuntingAPI {
    param (
        $url,
        $headers,
        $body
    )

    # API retry settings
    $maxRetries     = 3
    $retryDelay     = 5 # seconds
    $retryCount     = 0

    $errorObject    = $null
    # Query API and retry if timeout occurs
    while ($retryCount -lt $maxRetries) {
        try {
            (Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop | ConvertFrom-Json).Results
        } catch {
            $errorObject = (ConvertFrom-Json $_.ErrorDetails)
            Write-Host "        Request failed, retrying..." -ForegroundColor DarkYellow
            Start-Sleep -Seconds $retryDelay
            $retryCount++
        }
    }
    
    if ($errorObject -ne $null) {
        Write-Host "        Request failed after $retryCount retries. Error message: $($errorObject.error.code) | $($errorObject.error.message)" -ForegroundColor Red
    }
}

# Get AAD authorization token
Write-Host ""
Write-Host "   ▲ Getting access token from api.securitycenter.microsoft.com..." -ForegroundColor Cyan
Write-Host ""

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

### Construct header for API requests towards AdvancedHunting API

$url = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
$headers = @{ 
    'Content-Type' = 'application/json'
    Authorization  = "Bearer $aadToken" 
}

# Retrieve MBpd (MegaBytes per day) peaks per table
foreach ($table in $m365defenderSupportedTables) {
    Write-Host "Gathering performance statistics for table '$($table)'" -ForegroundColor DarkGray
    
    # Construct KQL query to retrieve total daily throughput (MB) for table
    Write-Host "    ◑ Constructing KQL query to retrieve total daily throughput (MB)..." -ForegroundColor DarkGray
    $bodyMBQuery    = ConvertTo-Json -InputObject @{ 'Query' = $tableMBThroughputQuery.Replace("<TABLE>", $table) }
    $resultsMBQuery = Query-AdvancedHuntingAPI -url $url -headers $headers -body $bodyMBQuery
    
    # Use KQL query from result above to retrieve total daily throughput (MB) for table
    Write-Host "    ◕ Calculating total daily throughput (MB)..." -ForegroundColor DarkGray
    $bodyMBpd       = ConvertTo-Json -InputObject @{ 'Query' = ($resultsMBQuery | Select-Object -ExpandProperty Column1) }
    $resultsMBpd    = Query-AdvancedHuntingAPI -url $url -headers $headers -body $bodyMBpd | Select-Object -ExpandProperty totalThroughputGB
    
    # Calculate Event Hub throughput units (TPUs) required for table
    $RequiredTPUs   = [Math]::Round($resultsMBpd / 86400)         # One throughput unit is 1 MB per second (Megabytes per day --> Megabytes per second --> Megabytes per 86400 seconds)

    # Add results to new object
    $tableThroughput        = New-Object PSObject -property @{
        tableName           = $table;
        MBpd                = $resultsMBpd;
        RequiredTPUs        = $RequiredTPUs;
    }
    # Add object to already existing object with all the other tables
    $allTablesThroughput    += $tableThroughput
}

$allTablesThroughput | ConvertTo-Json | Out-File $tableStatisticsFiles