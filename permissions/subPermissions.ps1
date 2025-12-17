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
$DefaultCompany = ''
$domain = 'DOMAIN\'

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

function Remove-StringLatinCharacters {
    PARAM ([string]$String)
    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
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

    #Convert databasename to ID
    $splatGetDatabase = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/api/v2.0/Database"
        Method  = 'GET'
        Headers = $headers
    }
    $DatabaseList = (Invoke-RestMethod @splatGetDatabase -Verbose:$false) | Group-Object name -AsHashTable
    $DatabaseID = $DatabaseList[$($actionContext.Configuration.Database)].id

    ### We can use Authorizationbox as the truth for currentpermissions but be carefull with this
    if ($useCurrentAuthAB) {
        ## Get roles first and fill current permissions
        $splatGetRoles = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)" + '/odata/v2.0/OrgRolesPerUser?$filter=' + "databaseID eq $databaseid and userName eq '$($account.Username)'"
            Method  = 'GET'
            Headers = $headers
        }

        $Roles = (Invoke-RestMethod @splatGetRoles -Verbose:$false).value
        #write-verbose -verbose ($roles | Out-string)

        $currentPermissions = [System.Collections.Generic.List[Object]]::new()
        if ($Roles.count -gt 0) {
            foreach ($entitlement in $Roles) {
                $currentPermission = @{
                    DisplayName = $entitlement.OrganizationRoleName
                    Id          = $entitlement.OrganizationRoleCode
                    Company     = $entitlement.company
                }
                $currentPermissions.Add($currentPermission)
                #write-verbose -verbose ($currentPermission | out-string)
            }
        }  
    } 
    ###

    write-verbose -verbose "Current permissions" 
    #write-verbose -verbose ($currentPermissions | out-string)

    $contractsInScope = ($personContext.Person.Contracts)# | Where-Object { $_.Context.InConditions -eq $true })# 
    if ($null -ne $contractsInScope) {
    
        $filter = "(DatabaseID eq $databaseid and "
        $filter += ($contractsinscope.title.name | ForEach-Object { "Name eq '$_'" }) -join " or "
        $filter += ")"

        $filter = Escape-UrlChars -inputString $filter

        $splatGetOrganizationRoles = @{
            Uri     = "https://api.2-controlware.com/odata/v2.0/OrganizationRole?`$filter=$($filter)"
            Method  = 'GET'
            Headers = $headers
        }
            
        $organizationRoles = (Invoke-RestMethod @splatGetOrganizationRoles -Verbose:$false).value
        #write-verbose -verbose ($organizationRoles | out-string)

        $desiredPermissions = [System.Collections.Generic.List[Object]]::new()
        foreach ($contract in $contractsInScope) {
            
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
                    throw "Geen match gevonden met rol: $($contract.Title.Name), $($contract.Department.displayname) "
                }

                if ($desiredPermissionObject.organizationRoleCode.count -gt 1) {
                    throw "Mogelijk zijn er meerdere rollen met dezelfde functie / afdeling combinatie: $($contract.Title.Name) , $($contract.Department.displayname)"
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
                        company              = $permission.company
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
                company              = $permission.company
            }
            $permissionsToRevoke.Add($RemovePermissionObject)
        }
    }

    #Extra fields can be added here, make sure to match this with fieldmapping
    $ExternalEmpId = $personContext.Person.Accounts.MicrosoftActiveDirectory.Mail.split('@')[0]
    if ($ExternalEmpId.Length -gt 10) {
        $ExternalEmpId = $ExternalEmpId.Substring(0, 10)
    }

    $authorization = [PSCustomObject]@{
        securityId            = $Account.userSecurityID
        databaseId            = $DatabaseID
        profileId             = $ProfileID
        processRequest        = $true
        userValueSourcesModel = [PSCustomObject]@{
            fullName           = (Remove-StringLatinCharacters $Account.fullName)
            companyEmail       = $personContext.Person.Accounts.MicrosoftActiveDirectory.Mail
            email              = $personContext.Person.Accounts.MicrosoftActiveDirectory.Mail
            employeeNoExternal = $ExternalEmpId
            jobTitle           = (Remove-StringLatinCharacters $personContext.Person.PrimaryContract.Title.Name)
            firstName          = (Remove-StringLatinCharacters $personContext.Person.Name.NickName)
            middleName         = (Remove-StringLatinCharacters $personContext.Person.Name.FamilyNamePrefix)
            surName            = (Remove-StringLatinCharacters $personContext.Person.Name.FamilyName)
            userName           = $Account.userName
        }
        organizationRoles     = @()
    }

    if ($permissionsToRevoke) {
        # Remove permissions from the authorization
        foreach ($permission in $permissionsToRevoke) {

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

    #write-verbose -verbose $($authorization | out-string)
    if ($authorization.organizationRoles.count -gt 0) {
        if (-not ($actionContext.DryRun -eq $true)) {
           
            try {
            
                #Send Auth request
                $splatUpdateAuthorization = @{
                    Uri     = "$($actionContext.Configuration.BaseUrl)/authorizationrequest/V3/Authorization"
                    Method  = 'POST'
                    Body    = ($authorization | ConvertTo-Json -Depth 10)
                    Headers = $headers
                } 

                $null = Invoke-RestMethod @splatUpdateAuthorization -Verbose:$false

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Authorizatie succesvol verzonden"
                        IsError = $false
                    })
            }
            catch {
                $ex = $PSItem
                throw "Mislukt om een authorizatieverzoek te maken. Error: $($ex.Exception.Message)"
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