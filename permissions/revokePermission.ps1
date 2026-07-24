############################################################
# HelloID-Conn-Prov-Target-Authorizationbox-Permissions-Revoke
# PowerShell V2
############################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set to false at start, at the end, only when no error occurs it is set to true
$outputContext.Success = $false 

#$actionContext.DryRun = $false

# Set variables, as data is not available in permissions
$DefaultCompany = ''

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

#endregion

try {
    Write-Verbose 'Getting Access Token' -Verbose
    $accessToken = Get-AccessToken
    $headers = @{
        'Content-Type' = 'application/json'
        Accept         = 'application/json;odata.metadata=minimal;odata.streaming=true'
        Authorization  = "Bearer $($accessToken)"
    }

    # In V3 we need to convert the database name to a database ID
    $splatGetDatabase = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/api/v2.0/Database"
        Method  = 'GET'
        Headers = $headers
    }
    $DatabaseList = (Invoke-RestMethod @splatGetDatabase -Verbose:$false) | Group-Object name -AsHashTable
    $DatabaseID = $DatabaseList[$($actionContext.Configuration.Database)].id
    #

    # Get user to retrieve key for user data lookup
    $filter = "?`$filter=(databaseId eq $DatabaseID and userSecurityId eq $($actionContext.References.Account.userSecurityId))"
    $splatGetUsers = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/odata/v2.0/Users$($filter)"
        Method  = 'GET'
        Headers = $headers
    }
    $correlatedAccount = (Invoke-RestMethod @splatGetUsers -Verbose:$false).value | Select-Object -First 1

    # Get current user data from Authorizationbox
    if ($null -ne $correlatedAccount) {
        Write-Information 'Retrieving current user data from Authorizationbox'
        $splatGetUserData = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/api/v2.0/Users/($($correlatedAccount.key))/GetUserDataForUser"
            Method  = 'GET'
            Headers = $headers
        }
        
        try {
            $currentUserData = (Invoke-RestMethod @splatGetUserData -Verbose:$false)
        }
        catch {
            Write-Warning "Could not retrieve current user data: $($_.Exception.Message)"
            $currentUserData = $null
        }
    }

    ## Get roles to check if permission exists
    $splatGetRoles = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)" + '/odata/v2.0/OrgRolesPerUser?$filter=' + "databaseID eq $databaseid and userName eq '$($actionContext.References.Account.Username)'"
        Method  = 'GET'
        Headers = $headers
    }

    $Roles = (Invoke-RestMethod @splatGetRoles -Verbose:$false).value

    $currentPermissions = [System.Collections.Generic.List[Object]]::new()
    if ($Roles.count -gt 0) {
        foreach ($entitlement in $Roles) {
            $currentPermission = @{
                DisplayName = $entitlement.OrganizationRoleName
                Id          = $entitlement.OrganizationRoleCode
                Company     = $entitlement.company
            }
            $currentPermissions.Add($currentPermission)

        }
    }  

    write-verbose -verbose "Current permissions" 
    write-verbose -verbose ($currentPermissions | out-string)

    $PermissionObject = @{
        status               = "Revoke"
        displayname          = $($actionContext.PermissionDisplayName)
        endDate              = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        organizationRoleCode = $($actionContext.References.Permission.id)
        company              = $DefaultCompany
    }

    # Check if permission exists in AB (match on Id only; stored company may be stale/mismatched)
    $inABRole = $null
    if ($currentPermissions -and $currentPermissions.Count -gt 0) {
        $matchingRoles = $currentPermissions | Where-Object { $_.Id -eq $PermissionObject.organizationRoleCode }
        # Prefer the role that matches the default company; fall back to first match
        $inABRole = $matchingRoles | Where-Object { $_.Company -eq $DefaultCompany } | Select-Object -First 1
        if (-not $inABRole) {
            $inABRole = $matchingRoles | Select-Object -First 1
        }
    }

    if (-not $inABRole) {
        Write-Information "Revoke skipped; role not found in AB: [$($actionContext.PermissionDisplayName) / $($PermissionObject.organizationRoleCode)]"
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Message = "Revoke skipped; role not found in AB: [$($actionContext.PermissionDisplayName)]"
                IsError = $false
            })
    }
    else {
        # Build userValueSourcesModel from current user data
        if ($null -ne $currentUserData) {
            $excludedFields = @("userSecurityId", "fullName")
            
            # Use all fields from currentUserData
            $userValueData = @{}
            foreach ($field in $currentUserData) {
                if ($excludedFields -notcontains $field.type) {
                    $userValueData[$field.type] = $field.value
                }
            }

            $userValueSourcesModel = [PSCustomObject]@{}
            $userValueSourcesModel | Add-Member -NotePropertyName 'fullName' -NotePropertyValue $($actionContext.References.Account.FullName)
            
            foreach ($fieldName in $userValueData.Keys) {
                $userValueSourcesModel | Add-Member -NotePropertyName $fieldName -NotePropertyValue $userValueData[$fieldName]
            }
        }
        else {
            Throw "No current user data available, authorization request cannot be processed"
        }
        
        $authorization = [PSCustomObject]@{
            securityId            = $($actionContext.References.Account.userSecurityId)
            databaseId            = $DatabaseID
            userValueSourcesModel = $userValueSourcesModel
            processRequest        = $true
            organizationRoles     = @()
        }

        # Override company with the actual value from AB to correct any stale/mismatched stored value
        $PermissionObject['company'] = $inABRole.Company
        $PermissionObject.Remove("displayname")
        $authorization.organizationRoles += $PermissionObject

        # Convert to JSON and encode as UTF-8
        $authorization_json = $authorization | ConvertTo-Json -Depth 10

        write-verbose -verbose ($authorization_json)

        $headers = @{
            'Content-Type' = 'application/json;charset=utf-8'
            Accept         = 'application/json;odata.metadata=minimal;odata.streaming=true'
            Authorization  = "Bearer $($accessToken)"
        }

        #Send Auth request
        $splatSendAuthorization = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/authorizationrequest/V3/Authorization"
            Method  = 'POST'
            Body    = [System.Text.Encoding]::UTF8.GetBytes($authorization_json)
            Headers = $headers
        } 

        if (-not($actionContext.DryRun -eq $true)) {
            Write-Information "Revoking $($actionContext.PermissionDisplayName) for AuthorizationBox account with accountReference: [$($actionContext.References.Account.userSecurityId)]"
            
            try {
                $null = Invoke-RestMethod @splatSendAuthorization -Verbose:$false
            }
            catch {
                $errorObj = Resolve-AuthorizationboxError -ErrorObject $_
                if ($errorObj.FriendlyMessage -match 'active requests pending') {
                    Write-Information "Pending request detected; retrying once in 5s"
                    Start-Sleep -Seconds 5
                    $null = Invoke-RestMethod @splatSendAuthorization -Verbose:$false
                }
                else {
                    throw
                }
            }
        }
        else {
            Write-Information "[DryRun] Revoking $($actionContext.PermissionDisplayName) for AuthorizationBox account with accountReference: [$($actionContext.References.Account.userSecurityId)], will be executed during enforcement"
        }

        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Message = "Revoking $($actionContext.PermissionDisplayName) was successful"
                IsError = $false
            }
        )
    }

}
catch {
    $ex = $PSItem

    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-AuthorizationboxError -ErrorObject $ex
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = "Error in proces: $($ex.Exception.Message)"
            IsError = $true
        })
}
finally { 
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }
}