############################################################
# HelloID-Conn-Prov-Target-Authorizationbox-Permissions-Dynamic
# PowerShell V2
############################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Parameters for determining the company or company group of the roles.
# When $UseCompanyGroup is $true, $DefaultCompany contains the name of the company group.
# Be sure to not change this later as this may cause bad requests in Authorizationbox
$DefaultCompany = ''
$UseCompanyGroup = $false

# Toggle to automatically process the authorization request in Authorizationbox
$ProcessRequest = $true

# Set debug logging
switch ($($actionContext.Configuration.isDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

# Define all empty objects
$subPermissions = [Collections.Generic.List[PSCustomObject]]::new()
$permissionsToGrant = [System.Collections.Generic.List[PSCustomObject]]::new()
$permissionsToRevoke = [System.Collections.Generic.List[PSCustomObject]]::new()

# Verify if there are any assigned permissions in the entitlement context object
$currentPermissions = [System.Collections.Generic.List[Object]]::new()
if ($actionContext.CurrentPermissions.Count -gt 0) {
    foreach ($entitlement in $actionContext.CurrentPermissions) {
        $currentPermission = @{
            DisplayName = $entitlement.DisplayName 
            Id          = $entitlement.Reference.Id
            Company     = $entitlement.Reference.company
            CompanyGroup = $entitlement.Reference.companyGroup
        }
        $currentPermissions.Add($currentPermission)
    }
}

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
#endregion

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

$Account = [PSCustomObject]@{
    fullName       = $($actionContext.References.Account.FullName)
    userName       = $($actionContext.References.Account.Username)
    userSecurityID = $($actionContext.References.Account.userSecurityID)
}

try {
    Write-Verbose 'Getting Access Token' -Verbose
    $accessToken = Get-AccessToken
    $headers = @{
        'Content-Type' = 'application/json;charset=utf-8'
        Accept         = 'application/json;odata.metadata=minimal;odata.streaming=true'
        Authorization  = "Bearer $($accessToken)"
    }

    #Convert databasename to ID
    $splatGetDatabase = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/api/v2.0/Database"
        Method  = 'GET'
        Headers = $headers
    }
    $DatabaseList = (Invoke-RestMethod @splatGetDatabase -Verbose:$false) | Group-Object name -AsHashTable
    $DatabaseID = $DatabaseList[$($actionContext.Configuration.Database)].id
    if ([string]::IsNullOrWhiteSpace([string]$DatabaseID)) {
        throw "DatabaseID could not be resolved for database [$($actionContext.Configuration.Database)]"
    }

    if ($UseCompanyGroup) {
        $groupName = $DefaultCompany.Replace("'", "''")
        $groupFilter = [uri]::EscapeDataString("(databaseId eq $DatabaseID and name eq '$groupName')")
        $splatGetCompanyGroups = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/odata/v2.0/CompanyGroups?`$filter=$groupFilter"
            Method  = 'GET'
            Headers = $headers
        }
        $companyGroups = @((Invoke-RestMethod @splatGetCompanyGroups -Verbose:$false).value)
        if ($companyGroups.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$companyGroups[0].key)) {
            throw "Expected one companyGroup for [$DefaultCompany] in database [$DatabaseID]"
        }
        $companyGroupId = $companyGroups[0].key
    }

    # Get user to retrieve key for user data lookup
    $filter = "?`$filter=(databaseId eq $DatabaseID and userSecurityId eq $($Account.userSecurityId))"
    $splatGetUsers = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/odata/v2.0/Users$($filter)"
        Method  = 'GET'
        Headers = $headers
    }
    $correlatedAccount = (Invoke-RestMethod @splatGetUsers -Verbose:$false).value | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace([string]$correlatedAccount.key)) {
        throw "Authorizationbox user could not be resolved for securityId [$($Account.userSecurityId)]"
    }

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
    
    ## Get roles first and fill current permissions AB, to not remove any roles that do not exist on the user
    $splatGetRoles = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/odata/v2.0/OrgRolesPerUser?`$filter=databaseID eq $DatabaseID and userCode eq $($correlatedAccount.key)"
        Method  = 'GET'
        Headers = $headers
    }

    $Roles = (Invoke-RestMethod @splatGetRoles -Verbose:$false).value

    $currentPermissionsAB = [System.Collections.Generic.List[Object]]::new()
    if ($Roles.count -gt 0) {
        foreach ($entitlement in $Roles) {
            $currentPermission = @{
                DisplayName = $entitlement.OrganizationRoleName
                Id          = $entitlement.OrganizationRoleCode
                Company     = $entitlement.company
                CompanyGroup = $entitlement.companyGroupCode
            }
            $currentPermissionsAB.Add($currentPermission)
        }
    }

    # On revoke all current permissions are removed, so the role lookup for the contracts is skipped
    $desiredPermissions = $null
    $contractsInScope = $personContext.Person.Contracts | Where-Object { $_.Context.InConditions -eq $true }
    if ($actionContext.Operation -ne 'Revoke' -and $null -ne $contractsInScope) {

        $desiredPermissions = [System.Collections.Generic.List[Object]]::new()
        foreach ($contract in $contractsInScope) {

            # Escape single quotes for OData and URL-encode the filter
            $roleName = ([string]$contract.Title.Name).Replace("'", "''")
            $roleFilter = [uri]::EscapeDataString("(DatabaseID eq $DatabaseID and Name eq '$roleName')")

            $splatGetOrganizationRoles = @{
                Uri     = "$($actionContext.Configuration.BaseUrl)/odata/v2.0/OrganizationRole?`$filter=$roleFilter"
                Method  = 'GET'
                Headers = $headers
            }

            $organizationRoles = (Invoke-RestMethod @splatGetOrganizationRoles -Verbose:$false).value

            if ($organizationRoles.count -eq 0) {
                throw "No matching role found for: $($contract.Title.Name)"
            }

            if ($organizationRoles.count -eq 1) {
                #If Title exist once, pick that
                ## First contract incondition sets the profile for now
                if ($null -eq $ProfileID) { 
                    $ProfileID = $($organizationRoles.ProfileId)
                }
           
                $desiredPermissionObject = @{
                    status               = "Assign"
                    displayname          = $($organizationRoles.Name)
                    startDate            = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                    organizationRoleCode = $($organizationRoles.Key)
                }
                if ($UseCompanyGroup) {
                    $desiredPermissionObject.companyGroup = $companyGroupId
                }
                else {
                    $desiredPermissionObject.company = $DefaultCompany
                }

                if ($desiredPermissionObject.organizationRoleCode.count -eq 0) {
                    throw "No matching role found for: $($contract.Title.Name)"
                }

                if ($desiredPermissionObject.organizationRoleCode.count -gt 1) {
                    throw "Multiple roles found with the same title / department combination: $($contract.Title.Name)"
                }

                $desiredPermissions.Add($desiredPermissionObject)
            }
            elseif ($organizationRoles.count -gt 1) {
                #Otherwise, also match on department
                                
                ## First contract incondition sets the profile for now
                if ($null -eq $ProfileID) { 
                    $ProfileID = ($organizationRoles | Where-Object { $_.Name -eq $contract.Title.Name -and $_.DeparmentName -eq $contract.Department.Displayname }).ProfileId
                }
           
                $desiredPermissionObject = @{
                    status               = "Assign"
                    displayname          = ($organizationRoles | Where-Object { $_.Name -eq $contract.Title.Name -and $_.DeparmentName -eq $contract.Department.Displayname }).Name
                    startDate            = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                    organizationRoleCode = ($organizationRoles | Where-Object { $_.Name -eq $contract.Title.Name -and $_.DeparmentName -eq $contract.Department.Displayname }).Key
                }
                if ($UseCompanyGroup) {
                    $desiredPermissionObject.companyGroup = $companyGroupId
                }
                else {
                    $desiredPermissionObject.company = $DefaultCompany
                }

                if ($desiredPermissionObject.organizationRoleCode.count -eq 0) {
                    throw "No matching role found for: $($contract.Title.Name), $($contract.Department.Displayname)"
                }

                if ($desiredPermissionObject.organizationRoleCode.count -gt 1) {
                    throw "Multiple roles found with the same title / department combination: $($contract.Title.Name), $($contract.Department.Displayname)"
                }

                $desiredPermissions.Add($desiredPermissionObject)

            }

        }

    }

    # Built up the sub-permissions object
    if ($desiredPermissions) {
        # Iterate through all desired permissions. If a desired permission is not found in the entitlementContext, add it to the 'permissionsToGrant' list.
        foreach ($permission in $desiredPermissions) {  

            $reference = @{ Id = $permission.organizationRoleCode }
            if ($permission.ContainsKey('companyGroup')) {
                $reference.CompanyGroup = $permission.companyGroup
            }
            else {
                $reference.Company = $permission.company
            }
            $subPermissions.Add([PSCustomObject]@{
                    DisplayName = $permission.displayName
                    Reference   = [PSCustomObject]$reference
                    
                })

            if ($null -eq ($currentPermissions | Where-Object {
                        $_.Id -eq $permission.organizationRoleCode -and
                        [string]$_.Company -eq [string]$permission.company -and
                        [string]$_.CompanyGroup -eq [string]$permission.companyGroup
                    })) {
                $permissionsToGrant.Add($permission)
            }
        }
    }

    # Iterate through all current permissions. If a current permission is not found in the 'desiredPermissions' or if the
    # 'desiredPermissions' object is empty, add the permission to the 'permissionsToRevoke' list.
    
    if ($desiredPermissions) {
        if ($currentPermissions) {
            foreach ($permission in $currentPermissions) {

                if ($null -eq ($desiredPermissions | Where-Object {
                            $_.organizationRoleCode -eq $permission.Id -and
                            [string]$_.company -eq [string]$permission.Company -and
                            [string]$_.companyGroup -eq [string]$permission.CompanyGroup
                        })) {
                    $RemovePermissionObject = @{
                        status               = "Revoke"
                        displayname          = $permission.displayname
                        endDate              = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                        organizationRoleCode = $permission.id
                    }
                    if (-not [string]::IsNullOrEmpty([string]$permission.CompanyGroup)) {
                        $RemovePermissionObject.companyGroup = $permission.CompanyGroup
                    }
                    else {
                        $RemovePermissionObject.company = $permission.Company
                    }
                    $permissionsToRevoke.Add($RemovePermissionObject)
                }
            }
        } 

    }
    elseif ($currentPermissions) {
        #delete all permissions
        foreach ($permission in $currentPermissions) {
            $RemovePermissionObject = @{
                status               = "Revoke"
                displayname          = $permission.displayname
                endDate              = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                organizationRoleCode = $permission.id
            }
            if (-not [string]::IsNullOrEmpty([string]$permission.CompanyGroup)) {
                $RemovePermissionObject.companyGroup = $permission.CompanyGroup
            }
            else {
                $RemovePermissionObject.company = $permission.Company
            }
            $permissionsToRevoke.Add($RemovePermissionObject)
        }
    }

    $authorization = [PSCustomObject]@{
        securityId            = $Account.userSecurityID
        databaseId            = $DatabaseID
        profileId             = $ProfileID
        processRequest        = $ProcessRequest
        organizationRoles     = @()
    }

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
        $userValueSourcesModel | Add-Member -NotePropertyName 'fullName' -NotePropertyValue $Account.fullName

        foreach ($fieldName in $userValueData.Keys) {
            $userValueSourcesModel | Add-Member -NotePropertyName $fieldName -NotePropertyValue $userValueData[$fieldName]
        }

        $authorization | Add-Member -NotePropertyName "userValueSourcesModel" -NotePropertyValue $userValueSourcesModel
    }
    else {
        Throw "No current user data available, authorization request cannot be processed"
    }

    if ($permissionsToRevoke) {
        # Remove permissions from the authorization
        foreach ($permission in $permissionsToRevoke) {

            # Revoke only the role and scope stored in the HelloID entitlement reference.
            $inABRole = $null
            if ($currentPermissionsAB -and $currentPermissionsAB.Count -gt 0) {
                $inABRole = $currentPermissionsAB | Where-Object {
                    $_.Id -eq $permission.organizationRoleCode -and (
                        (-not [string]::IsNullOrEmpty([string]$permission.companyGroup) -and [string]$_.CompanyGroup -eq [string]$permission.companyGroup) -or
                        ([string]::IsNullOrEmpty([string]$permission.companyGroup) -and [string]::IsNullOrEmpty([string]$_.CompanyGroup) -and [string]$_.Company -eq [string]$permission.company)
                    )
                } | Select-Object -First 1
            }

            if (-not $inABRole) {
                Write-Verbose "Revoke skipped; role and scope not found in AB: [$($permission.DisplayName) / $($permission.organizationRoleCode) / $($permission.company)$($permission.companyGroup)]"
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "RevokePermission"
                        Message = "Revoke skipped; role and scope not found in AB: [$($permission.DisplayName) / $($permission.company)$($permission.companyGroup)]"
                        IsError = $false
                    })
                continue
            }

            Write-Verbose "Revoking entitlement: [$($permission.DisplayName)]"

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Action  = "RevokePermission"
                    Message = "Revoked access from: [$($permission.DisplayName)]"
                    IsError = $false
                })

            $permission.Remove("displayname")
            $authorization.organizationRoles += $permission

        }
    }
    else {
        Write-Verbose "No permissions to revoke"
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Action  = "RevokePermission"
                Message = "No permissions to revoke"
                IsError = $false
            })
    }

    if ($permissionsToGrant) {
        # Add permissions to the authorization 
        foreach ($permission in $permissionsToGrant) {

            # Skip the grant if the role already exists in Authorizationbox
            $alreadyInAB = $false
            if ($currentPermissionsAB -and $currentPermissionsAB.Count -gt 0) {

                $alreadyInAB = $null -ne ($currentPermissionsAB | Where-Object {
                        $_.Id -eq $permission.organizationRoleCode -and (
                            (-not [string]::IsNullOrEmpty([string]$permission.companyGroup) -and [string]$_.CompanyGroup -eq [string]$permission.companyGroup) -or
                            ([string]::IsNullOrEmpty([string]$permission.companyGroup) -and [string]::IsNullOrEmpty([string]$_.CompanyGroup) -and [string]$_.Company -eq [string]$permission.company)
                        )
                    })
            }

            if ($alreadyInAB) {
                continue
            }

            Write-Verbose "Granting entitlement: [$($permission.DisplayName)]"

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Action  = "GrantPermission"
                    Message = "Granted access to: [$($permission.DisplayName)]"
                    IsError = $false
                }) 

            $permission.Remove("displayname")

            $authorization.organizationRoles += $permission 
        }
    }
    else {
        Write-Verbose "No permissions to grant"
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Action  = "GrantPermission"
                Message = "No permissions to grant"
                IsError = $false
            })
    }



    if ($authorization.organizationRoles.count -gt 0) {
        if (-not ($actionContext.DryRun -eq $true)) {
           
            try {
            
                #Format Auth request
                $authorization_json = ($authorization | ConvertTo-Json -Depth 10)

                #Send Auth request
                $splatUpdateAuthorization = @{
                    Uri     = "$($actionContext.Configuration.BaseUrl)/authorizationrequest/V3/Authorization"
                    Method  = 'POST'
                    Body    = [System.Text.Encoding]::UTF8.GetBytes($authorization_json)
                    Headers = $headers
                }

                # Single retry for transient "active requests pending" condition
                try {
                    $null = Invoke-RestMethod @splatUpdateAuthorization -Verbose:$false
                }
                catch {
                    $errorObj = Resolve-AuthorizationboxError -ErrorObject $_
                    $errText = $($errorObj.FriendlyMessage)
                    
                    if ($errText -match 'active requests pending') {
                        Write-Information "Pending request detected; retrying once in 10s"
                        Start-Sleep -Seconds 10
                        # Second attempt; any failure bubbles to outer catch
                        $null = Invoke-RestMethod @splatUpdateAuthorization -Verbose:$false
                    }
                    else {
                        throw
                    }
                }

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Authorization request sent successfully"
                        IsError = $false
                    })
            }
            catch {
                $errorObj = Resolve-AuthorizationboxError -ErrorObject $_
                throw "Failed to create authorization request. Error: $($errorObj.FriendlyMessage)"
            }
        }
    }
    else {
        #No call needed as everything is good as is
    }

}
catch {
    $ex = $PSItem
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = "Error in process: $($ex.Exception.Message)"
            IsError = $true
        })

    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-AuthorizationboxError -ErrorObject $ex
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
}

finally { 
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }

    # Handle case of empty defined dynamic permissions.  Without this the entitlement will error.
    if ($actionContext.Operation -match "update|grant" -AND $subPermissions.count -eq 0) {
        $subPermissions.Add([PSCustomObject]@{
                DisplayName = "No Groups Defined"
                Reference   = [PSCustomObject]@{ Id = "No Groups Defined" }
            })
    }

    $outputContext.SubPermissions = $subPermissions
}
