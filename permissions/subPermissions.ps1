############################################################
# HelloID-Conn-Prov-Target-Authorizationbox-Permissions-Dynamic
# PowerShell V2
############################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set to false at start, at the end, only when no error occurs it is set to true
$outputContext.Success = $false 
#$actionContext.DryRun = $false

# Toggle voor AB currentpermissions or HelloID currentpermissions - Do not change later
$useCurrentAuthAB = $false
$DefaultCompany = 'Mitros'

# Toggle voor het automatisch doorzetten van requests.
$ProcessRequest = $true

if ($actionContext.Operation -eq "Revoke") {
        $ProcessRequest = $true
}

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

function Escape-UrlChars {
    param (
        [string]$inputString
    )
    
    # Mapping van te vervangen waardes
    $charMap = @{
        "&" = "%26"
        "/" = "%2F"
        ":" = "%3A"
        "?" = "%3F"
        "#" = "%23"
        "=" = "%3D"
        "+" = "%2B"
    }

    # Gebruik foreach om elk teken in de hash table te vervangen
    foreach ($key in $charMap.Keys) {
        $inputString = $inputString -replace [regex]::Escape($key), $charMap[$key]
    }

    return $inputString
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

$Account = [PSCustomObject]@{
    fullName       = $($actionContext.References.Account.FullName)
    userName       = $($actionContext.References.Account.Username)
    userSecurityID = $($actionContext.References.Account.userSecurityID)
}

#write-verbose -verbose ($account | out-string)

try {
    Write-Verbose 'Getting Access Token' -Verbose
    $accessToken = Get-AccessToken
    $headers = @{
        'Content-Type' = 'application/json'
        Accept         = 'application/json;odata.metadata=minimal;odata.streaming=true'
        Authorization  = "Bearer $($accessToken)"
    }

    #write-verbose -verbose "Bearer $($accessToken)"

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

    # Get user to retrieve key for user data lookup
    $filter = "?`$filter=(databaseId eq $DatabaseID and userSecurityId eq $($Account.userSecurityId))"
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
    
    ## Get roles first and fill current permissions AB, to not remove any roles that do not exist on the user
    $splatGetRoles = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)" + '/odata/v2.0/OrgRolesPerUser?$filter=' + "databaseID eq $databaseid and userName eq '$($account.Username)'"
        Method  = 'GET'
        Headers = $headers
    }

    $Roles = (Invoke-RestMethod @splatGetRoles -Verbose:$false).value
    #write-verbose -verbose ($roles | Out-string)

    $currentPermissionsAB = [System.Collections.Generic.List[Object]]::new()
    if ($Roles.count -gt 0) {
        foreach ($entitlement in $Roles) {
            $currentPermission = @{
                DisplayName = $entitlement.OrganizationRoleName
                Id          = $entitlement.OrganizationRoleCode
                Company     = $entitlement.company
            }
            $currentPermissionsAB.Add($currentPermission)
            #write-verbose -verbose ($currentPermission | out-string)
        }
    }

    ### We can use Authorizationbox as the truth for currentpermissions but be carefull with this
    #if ($useCurrentAuthAB) {  
        #$currentPermissions = $currentPermissionsAB
    #} 
    ###

    #write-verbose -verbose "Current permissions" 
    #write-verbose -verbose ($currentPermissions | out-string)

    $contractsInScope = ($personContext.Person.Contracts | Where-Object { $_.Context.InConditions -eq $true })# 
    if ($null -ne $contractsInScope) {
    
        $desiredPermissions = [System.Collections.Generic.List[Object]]::new()
        foreach ($contract in $contractsInScope) {
            
            $filter = "(DatabaseID eq $databaseid and Name eq '$($contract.title.name)')"
            $filter = Escape-UrlChars -inputString $filter

            $splatGetOrganizationRoles = @{
                Uri     = "https://api.2-controlware.com/odata/v2.0/OrganizationRole?`$filter=$($filter)"
                Method  = 'GET'
                Headers = $headers
            }
            
            $organizationRoles = (Invoke-RestMethod @splatGetOrganizationRoles -Verbose:$false).value
            #write-verbose -verbose ($organizationRoles | out-string)

            if ($organizationRoles.count -eq 0) {
                throw "Geen match gevonden met rol: $($contract.Title.Name)"
            }

            if ($organizationRoles.count -eq 1) {
                #If Title exist once, pick that
                ## First contract incondition sets the profile for now
                if ($null -eq $ProfileID) { 
                    $ProfileID = $($organizationRoles.ProfileId)
                }
           
                # create organizationRoleObject without properties: freeFields and companyGroup because it is not required. value will automatically be set to null
                $desiredPermissionObject = @{
                    status               = "Assign"
                    displayname          = $($organizationRoles.Name)
                    startDate            = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                    #endDate              = (Get-Date "2099-12-31T23:59:59").ToString("yyyy-MM-ddTHH:mm:ssZ")
                    organizationRoleCode = $($organizationRoles.Key)
                    company              = $DefaultCompany
                }

                if ($desiredPermissionObject.organizationRoleCode.count -eq 0) {
                    throw "Geen match gevonden met rol: $($contract.Title.Name)"
                }

                if ($desiredPermissionObject.organizationRoleCode.count -gt 1) {
                    throw "Mogelijk zijn er meerdere rollen met dezelfde functie / afdeling combinatie: $($contract.Title.Name)"
                }

                $desiredPermissions.Add($desiredPermissionObject)
            }
            elseif ($organizationRoles.count -gt 1) {
                #Otherwise, also match on department
                                
                ## First contract incondition sets the profile for now
                if ($null -eq $ProfileID) { 
                    $ProfileID = ($organizationRoles | Where-Object { $_.Name -eq $contract.Title.Name -and $_.DeparmentName -eq $contract.Department.Displayname }).ProfileId
                }
           
                # create organizationRoleObject without properties: freeFields and companyGroup because it is not required. value will automatically be set to null
                $desiredPermissionObject = @{
                    status               = "Assign"
                    displayname          = ($organizationRoles | Where-Object { $_.Name -eq $contract.Title.Name -and $_.DeparmentName -eq $contract.Department.Displayname }).Name
                    startDate            = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                    #endDate              = (Get-Date "2099-12-31T23:59:59").ToString("yyyy-MM-ddTHH:mm:ssZ")
                    organizationRoleCode = ($organizationRoles | Where-Object { $_.Name -eq $contract.Title.Name -and $_.DeparmentName -eq $contract.Department.Displayname }).Key
                    company              = $DefaultCompany
                }

                if ($desiredPermissionObject.organizationRoleCode.count -eq 0) {
                    throw "Geen match gevonden met rol: $($contract.Title.Name), $($contract.Department.Displayname)"
                }

                if ($desiredPermissionObject.organizationRoleCode.count -gt 1) {
                    throw "Mogelijk zijn er meerdere rollen met dezelfde functie / afdeling combinatie: $($contract.Title.Name) , $($contract.Department.Displayname)"
                }

                $desiredPermissions.Add($desiredPermissionObject)
                
            }
            
        }

    }
    else { 
        $desiredPermissions = $null
    }

    if ($actionContext.Operation -eq "Revoke") {
        $desiredPermissions = $null
    }

    # Built up the sub-permissions object
    if ($desiredPermissions) {
        # Iterate through all desired permissions. If a desired permission is not found in the entitlementContext, add it to the 'permissionsToGrant' list.
        foreach ($permission in $desiredPermissions) {  

            $subPermissions.Add([PSCustomObject]@{
                    DisplayName = $permission.displayName
                    Reference   = [PSCustomObject]@{
                        Id      = $permission.organizationRoleCode
                        Company = $permission.company
                    }
                    
                })

            #write-verbose -verbose ($permission | out-string)

            if (-not $currentPermissions -or -not $currentPermissions.ContainsValue($($permission.organizationRoleCode))) {
                $permissionsToGrant.Add($permission)
            }
        }
    }

    # Iterate through all current permissions. If a current permission is not found in the 'desiredPermissions' or if the
    # 'desiredPermissions' object is empty, add the permission to the 'permissionsToRevoke' list.
    
    if ($desiredPermissions) {
        if ($currentPermissions) {
            foreach ($permission in $currentPermissions) {

                #write-verbose -verbose ($desiredPermissions | out-string)
                #write-verbose -verbose ($permission | out-string)

                if (-not $desiredPermissions.ContainsValue($permission.Id) ) {
                    $RemovePermissionObject = @{
                        status               = "Revoke"
                        displayname          = $permission.displayname
                        #startDate            = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                        endDate              = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                        organizationRoleCode = $permission.id
                        #company              = $permission.company
                        company              = $DefaultCompany
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
                #startDate            = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                endDate              = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                organizationRoleCode = $permission.id
                #company              = $permission.company
                company              = $DefaultCompany
            }
            $permissionsToRevoke.Add($RemovePermissionObject)
        }
    }

    $authorization = [PSCustomObject]@{
        securityId            = $Account.userSecurityID
        databaseId            = $DatabaseID
        #profileId             = $ProfileID
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

            # Check if permission exists in AB current permissions (match on Id only; stored company may be stale/mismatched)
            # Prefer the entry with DefaultCompany; a role can appear twice (once empty, once filled company)
            $inABRole = $null
            if ($currentPermissionsAB -and $currentPermissionsAB.Count -gt 0) {
                $inABRole = $currentPermissionsAB | Where-Object { $_.Id -eq $permission.organizationRoleCode -and $_.Company -eq $DefaultCompany } | Select-Object -First 1
                if (-not $inABRole) {
                    $inABRole = $currentPermissionsAB | Where-Object { $_.Id -eq $permission.organizationRoleCode } | Select-Object -First 1
                }
            }

            if (-not $inABRole) {
                Write-Verbose "Revoke skipped; role not found in AB: [$($permission.DisplayName) / $($permission.organizationRoleCode)]"
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "RevokePermission"
                        Message = "Revoke skipped; role not found in AB: [$($permission.DisplayName)]"
                        IsError = $false
                    })
                continue
            }

            # Override company with the actual value from AB to correct any stale/mismatched stored value
            $permission['company'] = $inABRole.Company

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

            Write-Verbose "Granting entitlement: [$($permission.DisplayName)]"

            # Sla grant over als de rol al in Authorization Box staat
            $alreadyInAB = $false
            if ($currentPermissionsAB -and $currentPermissionsAB.Count -gt 0) {

                $alreadyInAB = $null -ne ($currentPermissionsAB | Where-Object {
                        $_.Id -eq $permission.organizationRoleCode -and (
                            [string]::IsNullOrEmpty($permission.company) -or $_.Company -eq $permission.company
                        )
                    })
            }

            if ($alreadyInAB) {
                continue
            }

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
            
                #tmp
                $authorization_json = ($authorization | ConvertTo-Json -Depth 10)
                $headers = @{
                    'Content-Type' = 'application/json;charset=utf-8'
                    Accept         = 'application/json;odata.metadata=minimal;odata.streaming=true'
                    Authorization  = "Bearer $($accessToken)"
                }

                #Send Auth request
                $splatUpdateAuthorization = @{
                    Uri     = "$($actionContext.Configuration.BaseUrl)/authorizationrequest/V3/Authorization"
                    Method  = 'POST'
                    #Body    = ($authorization | ConvertTo-Json -Depth 10)
                    Body    = [System.Text.Encoding]::UTF8.GetBytes($authorization_json)
                    Headers = $headers
                } 

                #write-information ($authorization | ConvertTo-Json -depth 10)
                #write-information ($authorization.organizationRoles | out-string)

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
                        Message = "Authorisatie succesvol verzonden"
                        IsError = $false
                    })
            }
            catch {
                $errorObj = Resolve-AuthorizationboxError -ErrorObject $_
                throw "Mislukt om een authorisatieverzoek te maken. Error: $($errorObj.FriendlyMessage)"
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
            Message = "Error in proces: $($ex.Exception.Message)"
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