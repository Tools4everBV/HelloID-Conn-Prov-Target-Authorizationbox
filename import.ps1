#################################################
# HelloID-Conn-Prov-Target-Authorizationbox-Import
# PowerShell V2
#################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#region functions
function Resolve-AuthorizationboxError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json)
            # Make sure to inspect the error result object and add only the error message as a FriendlyMessage.
            # $httpErrorObj.FriendlyMessage = $errorDetailsObject.message
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails # Temporarily assignment
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-AccessToken {
    [CmdletBinding()]
    param ()
    try {
        $tokenHeaders = @{
            'Content-Type' = 'application/json'
            Accept         = 'application/json;odata.metadata=minimal;odata.streaming=true'
        }

        $tokenBody = @{
            'token'    = $actionContext.Configuration.token
            'username' = $actionContext.Configuration.UserName
        }

        $splatGetToken = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/api/v3.0/Authenticate/AccessToken"
            Method  = 'POST'
            Body    = $tokenBody | ConvertTo-Json
            Headers = $tokenHeaders
        }

        $accessToken = (Invoke-RestMethod @splatGetToken -Verbose:$false).token
        Write-Output $accessToken
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Invoke-AuthorizationboxRead {
    # A GET with a bounded retry on 429 and 5xx: on an import a single transient error costs the whole list.
    # The response bytes are decoded as UTF-8 here, because Windows PowerShell 5.1 (the HelloID agent)
    # reads a response without a charset as ISO-8859-1, which mangles diacritics in names.
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Uri,

        [Parameter(Mandatory)]
        [hashtable]
        $Headers,

        [int]
        $MaxAttempts = 3,

        [int]
        $MaxWaitSeconds = 10
    )
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $splatRead = @{
                Uri             = $Uri
                Method          = 'GET'
                Headers         = $Headers
                UseBasicParsing = $true
                TimeoutSec      = 120
            }
            $response = Invoke-WebRequest @splatRead -Verbose:$false
            if ($null -eq $response.RawContentStream -or $response.RawContentStream.Length -eq 0) {
                return $null
            }
            return ([System.Text.Encoding]::UTF8.GetString($response.RawContentStream.ToArray()) | ConvertFrom-Json)
        }
        catch {
            $ex = $PSItem
            $status = 0
            if ($null -ne $ex.Exception.Response) {
                $status = [int]$ex.Exception.Response.StatusCode
            }
            if (($status -ne 429 -and $status -lt 500) -or $attempt -ge $MaxAttempts) {
                throw
            }
            $wait = [Math]::Min(2 * $attempt, $MaxWaitSeconds)
            Write-Information "Authorizationbox answered with $status; retrying in $wait second(s) (attempt $($attempt + 1) of $MaxAttempts)"
            Start-Sleep -Seconds $wait
        }
    }
}

function Get-AuthorizationboxODataList {
    # Follows @odata.nextLink until the list is exhausted. Stopping early is an error, not a warning:
    # an incomplete import makes HelloID see the missing accounts as gone.
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Uri,

        [Parameter(Mandatory)]
        [hashtable]
        $Headers,

        [int]
        $MaxPages = 1000
    )
    $baseUrl = "$($actionContext.Configuration.BaseUrl)".TrimEnd('/')
    $items = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri
    $page = 0
    while (-not [string]::IsNullOrEmpty($nextUri)) {
        if ($page -ge $MaxPages) {
            throw "Stopped after $MaxPages pages of [$Uri]; the result would be incomplete."
        }
        $page++
        $body = Invoke-AuthorizationboxRead -Uri $nextUri -Headers $Headers
        foreach ($item in @($body.value)) {
            if ($null -ne $item) {
                $items.Add($item)
            }
        }
        $nextUri = [string]$body.'@odata.nextLink'
        if (-not [string]::IsNullOrEmpty($nextUri) -and $nextUri -notmatch '^https?://') {
            if ($nextUri.StartsWith('/')) {
                $nextUri = "$baseUrl$nextUri"
            }
            else {
                $nextUri = "$baseUrl/odata/v2.0/$nextUri"
            }
        }
    }
    Write-Output $items
}
#endregion

try {
    Write-Information 'Starting Authorizationbox account entitlement import'

    $baseUrl = "$($actionContext.Configuration.BaseUrl)".TrimEnd('/')
    $accessToken = Get-AccessToken
    $headers = @{
        Accept        = 'application/json;odata.metadata=minimal;odata.streaming=true'
        Authorization = "Bearer $($accessToken)"
    }

    # In V3 we need to convert the database name to a database ID
    $databases = @(Invoke-AuthorizationboxRead -Uri "$baseUrl/api/v2.0/Database" -Headers $headers)
    $DatabaseID = (@($databases | Where-Object { $_.name -eq $actionContext.Configuration.Database }) | Select-Object -First 1).id
    if ([string]::IsNullOrWhiteSpace([string]$DatabaseID)) {
        throw "DatabaseID could not be resolved for database [$($actionContext.Configuration.Database)]"
    }

    $userFilter = [uri]::EscapeDataString("databaseId eq $DatabaseID")
    $users = @(Get-AuthorizationboxODataList -Uri "$baseUrl/odata/v2.0/Users?`$filter=$userFilter" -Headers $headers)
    Write-Information "Queried Authorizationbox users. Result count: $($users.Count)"

    $seenSecurityIds = @{}
    $skippedNoSecurityId = 0
    $skippedDuplicate = 0
    $importedCount = 0
    foreach ($importedAccount in $users) {
        # The account reference is built on userSecurityId; without it HelloID cannot link the account
        if ([string]::IsNullOrWhiteSpace([string]$importedAccount.userSecurityId)) {
            $skippedNoSecurityId++
            continue
        }

        # A user can exist twice in a database with the same userSecurityId. The lifecycle scripts use
        # the first one the API returns, so the import does the same and keeps the reference unique.
        $securityIdKey = [string]$importedAccount.userSecurityId
        if ($seenSecurityIds.ContainsKey($securityIdKey)) {
            $skippedDuplicate++
            continue
        }
        $seenSecurityIds[$securityIdKey] = $true

        # Only send the fields HelloID has mapped
        $data = @{}
        foreach ($field in $actionContext.ImportFields) {
            $data[$field] = $importedAccount.$field
        }

        $displayName = "$($importedAccount.fullName)".Trim()
        if ([string]::IsNullOrEmpty($displayName)) {
            $displayName = $securityIdKey
        }

        $userName = "$($importedAccount.userName)".Trim()
        if ([string]::IsNullOrEmpty($userName)) {
            $userName = $securityIdKey
        }

        # Same shape and property names as the account reference set by create.ps1
        $accountReference = [PSCustomObject]@{
            userSecurityId = $importedAccount.userSecurityId
            fullName       = $importedAccount.fullName
            userName       = $importedAccount.userName
        }

        Write-Output @{
            AccountReference = $accountReference
            DisplayName      = $displayName
            UserName         = $userName.Substring(0, [Math]::Min($userName.Length, 100))
            # The Authorizationbox API exposes no account status
            Enabled          = $true
            Data             = $data
        }
        $importedCount++
    }

    if ($skippedNoSecurityId -gt 0) {
        Write-Information "Skipped $skippedNoSecurityId user(s) without userSecurityId"
    }
    if ($skippedDuplicate -gt 0) {
        Write-Information "Skipped $skippedDuplicate duplicate user(s) with a userSecurityId that was already imported"
    }
    Write-Information "Authorizationbox account entitlement import completed: $importedCount account(s)"
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-AuthorizationboxError -ErrorObject $ex
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
        throw "Could not import Authorizationbox account entitlements. Error: $($errorObj.FriendlyMessage)"
    }
    Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    throw "Could not import Authorizationbox account entitlements. Error: $($ex.Exception.Message)"
}
