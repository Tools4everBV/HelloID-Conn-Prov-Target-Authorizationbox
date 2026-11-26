####################################################################
# HelloID-Conn-Prov-Target-Authorizationbox-ImportPermissions-Roles
# PowerShell V2
####################################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Parameters for determining the company or company group of the role, as this data is not available in permissions.
# When $UseCompanyGroup is $true, $DefaultCompany contains the name of the company group.
# Use the same values as in grantPermission.ps1 and revokePermission.ps1: only role assignments on this
# scope are imported, because grant and revoke only act on this scope.
$DefaultCompany = ''
$UseCompanyGroup = $false

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
    # HelloID treats the permission import as authoritative and revokes what is missing from it.
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
    Write-Information 'Starting Authorizationbox permission entitlement import'

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

    $companyGroupId = $null
    if ($UseCompanyGroup) {
        $groupName = $DefaultCompany.Replace("'", "''")
        $groupFilter = [uri]::EscapeDataString("(databaseId eq $DatabaseID and name eq '$groupName')")
        $companyGroups = @(Get-AuthorizationboxODataList -Uri "$baseUrl/odata/v2.0/CompanyGroups?`$filter=$groupFilter" -Headers $headers)
        if ($companyGroups.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$companyGroups[0].key)) {
            throw "Expected one companyGroup for [$DefaultCompany] in database [$DatabaseID]"
        }
        $companyGroupId = $companyGroups[0].key
    }

    $databaseFilter = [uri]::EscapeDataString("databaseId eq $DatabaseID")

    # Users: map the user key (userCode on a role assignment) to the account reference set by create.ps1
    $users = @(Get-AuthorizationboxODataList -Uri "$baseUrl/odata/v2.0/Users?`$filter=$databaseFilter" -Headers $headers)
    Write-Information "Queried Authorizationbox users. Result count: $($users.Count)"

    $accountReferenceByUserKey = @{}
    $seenSecurityIds = @{}
    foreach ($user in $users) {
        if ([string]::IsNullOrWhiteSpace([string]$user.userSecurityId) -or [string]::IsNullOrWhiteSpace([string]$user.key)) {
            continue
        }
        # A user can exist twice in a database with the same userSecurityId. Grant and revoke act on the
        # first one the API returns, so only that user's roles are imported.
        $securityIdKey = [string]$user.userSecurityId
        if ($seenSecurityIds.ContainsKey($securityIdKey)) {
            continue
        }
        $seenSecurityIds[$securityIdKey] = $true
        $accountReferenceByUserKey[[string]$user.key] = [PSCustomObject]@{
            userSecurityId = $user.userSecurityId
            fullName       = $user.fullName
            userName       = $user.userName
        }
    }

    # Roles: the same list and the same reference and display name as permissions.ps1
    $organizationRoles = @(Get-AuthorizationboxODataList -Uri "$baseUrl/odata/v2.0/OrganizationRole?`$filter=$databaseFilter" -Headers $headers)
    Write-Information "Queried Authorizationbox roles. Result count: $($organizationRoles.Count)"
    $roleByKey = @{}
    foreach ($role in $organizationRoles) {
        if (-not [string]::IsNullOrWhiteSpace([string]$role.Key)) {
            $roleByKey[[string]$role.Key] = $role
        }
    }

    # Role assignments of all users in the database
    $roleAssignments = @(Get-AuthorizationboxODataList -Uri "$baseUrl/odata/v2.0/OrgRolesPerUser?`$filter=$databaseFilter" -Headers $headers)
    Write-Information "Queried Authorizationbox role assignments. Result count: $($roleAssignments.Count)"

    $membersByRoleKey = @{}
    $seenAssignments = @{}
    $skippedScope = 0
    $skippedUnknownRole = 0
    $skippedUnknownUser = 0
    foreach ($assignment in $roleAssignments) {
        # Same scope check as grant and revoke: company group when configured, otherwise company without a company group
        $inScope = if (-not [string]::IsNullOrEmpty([string]$companyGroupId)) {
            [string]$assignment.companyGroupCode -eq [string]$companyGroupId
        }
        else {
            [string]::IsNullOrEmpty([string]$assignment.companyGroupCode) -and [string]$assignment.company -eq [string]$DefaultCompany
        }
        if (-not $inScope) {
            $skippedScope++
            continue
        }

        $roleKey = [string]$assignment.OrganizationRoleCode
        if (-not $roleByKey.ContainsKey($roleKey)) {
            $skippedUnknownRole++
            continue
        }

        $userKey = [string]$assignment.userCode
        if (-not $accountReferenceByUserKey.ContainsKey($userKey)) {
            $skippedUnknownUser++
            continue
        }

        # A user can hold the same role more than once (for example with different dates); report it once
        $assignmentKey = "$roleKey|$userKey"
        if ($seenAssignments.ContainsKey($assignmentKey)) {
            continue
        }
        $seenAssignments[$assignmentKey] = $true

        if (-not $membersByRoleKey.ContainsKey($roleKey)) {
            $membersByRoleKey[$roleKey] = [System.Collections.Generic.List[object]]::new()
        }
        $membersByRoleKey[$roleKey].Add($accountReferenceByUserKey[$userKey])
    }

    if ($skippedScope -gt 0) {
        Write-Information "Skipped $skippedScope role assignment(s) outside the configured company or company group [$DefaultCompany]"
    }
    if ($skippedUnknownRole -gt 0) {
        Write-Information "Skipped $skippedUnknownRole role assignment(s) of a role that is not in OrganizationRole"
    }
    if ($skippedUnknownUser -gt 0) {
        Write-Information "Skipped $skippedUnknownUser role assignment(s) of a user without userSecurityId, or of a duplicate user"
    }

    # A role without members gets no record: HelloID rejects a record without account references
    $recordCount = 0
    foreach ($roleKey in $membersByRoleKey.Keys) {
        $role = $roleByKey[$roleKey]
        $members = $membersByRoleKey[$roleKey]

        $displayName = "Role - $($role.Name) - $($role.deparmentName)"
        $displayName = $displayName.Substring(0, [System.Math]::Min(100, $displayName.Length))

        # HelloID accepts at most 500 account references per record; a new object per batch, so that
        # every record keeps its own members
        $batchSize = 500
        for ($i = 0; $i -lt $members.Count; $i += $batchSize) {
            $batchEnd = [Math]::Min($i + $batchSize, $members.Count) - 1
            Write-Output @{
                PermissionReference = @{
                    Id = $role.Key
                }
                Description         = $displayName
                DisplayName         = $displayName
                AccountReferences   = @($members[$i..$batchEnd])
            }
            $recordCount++
        }
    }

    Write-Information "Authorizationbox permission entitlement import completed: $($membersByRoleKey.Count) role(s) with members in $recordCount record(s)"
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-AuthorizationboxError -ErrorObject $ex
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
        throw "Could not import Authorizationbox permission entitlements. Error: $($errorObj.FriendlyMessage)"
    }
    Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    throw "Could not import Authorizationbox permission entitlements. Error: $($ex.Exception.Message)"
}
