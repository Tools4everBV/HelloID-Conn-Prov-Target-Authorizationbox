############################################################
# HelloID-Conn-Prov-Target-Authorizationbox-Permissions-Dynamic
# PowerShell V2
############################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Toggle voor AB currentpermissions or HelloID currentpermissions - Do not change later
$useAB = $true
#region functions

#$actionContext.DryRun = $false

# Define all empty objects
$subPermissions = [Collections.Generic.List[PSCustomObject]]::new()
$permissionsToGrant = [System.Collections.Generic.List[PSCustomObject]]::new()
$permissionsToRevoke = [System.Collections.Generic.List[PSCustomObject]]::new()

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

try {
    #Get Account info
    $s = New-PSSession -ComputerName  $actionContext.Configuration.Applicationserver

    $NavServerInstanceName = $actionContext.Configuration.NavServerInstanceName
    $SamAccountName = $actionContext.References.Account
    $PSModulePath = $actionContext.Configuration.PSModulePath

    write-verbose -verbose $SamAccountName
    $tenant = $actionContext.Configuration.Tenant
    Invoke-Command -Session $s -ScriptBlock { $ImportModule = Import-Module $using:PSModulePath -ErrorAction SilentlyContinue }
    $result = Invoke-Command -Session $s -ScriptBlock { Get-NAVServerUser -ServerInstance $using:NavServerInstanceName -Tenant $using:tenant | Where-Object { $_.UserName -eq $using:SamAccountName } } 
    
    $Account = [PSCustomObject]@{
        fullName   = $($result.Fullname)
        userName   = $($result.Username)
        SecurityID = $($result.UserSecurityID)
    }

    $Config = $actionContext.Configuration
    $P = $personContext.Person

    <# Define userValuesModel
    $userValueSourcesModel = [PSCustomObject]@{
            userName = $Account.userName
            fullName = $Account.fullName
            #firstName = $personContext.Person.Name.NickName
            #middleName = $personContext.Person.Name.FamilyNamePrefix
            #lastName = $personContext.Person.Name.FamilyName
            #employeeNoExternal = $Account.userName.replace("WOCO\", "")
            #freeField1 = if($personContext.Person.Details.Gender -eq "MALE"){"DHR"} else {"MEVR"}
            #freeField2 = "WOCO\" + $personContext.Manager.Accounts.MicrosoftActiveDirectory.samaccountname
            #mobielPhoneNo = $personContext.Person.Contact.Business.Phone.Mobile
            #email       = $personContext.Person.Accounts.MicrosoftActiveDirectory.Mail
    } #>

    # write-verbose -verbose ($userValueSourcesModel | out-string)
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
}


try {
    $tokenHeaders = @{
        'Content-Type' = 'application/json'
        Accept         = 'application/json;odata.metadata=minimal;odata.streaming=true'
    }

    $tokenBody = @{
        'token'    = $config.token
        'username' = $config.UserName
    }

    $splatGetToken = @{
        Uri     = "$($config.BaseUrl)/api/Authenticate/AccessToken"
        Method  = 'POST'
        Body    = $tokenBody | ConvertTo-Json
        Headers = $tokenHeaders
    }
    $accessToken = (Invoke-RestMethod @splatGetToken -Verbose:$false).token

    $headers = @{
        'Content-Type' = 'application/json'
        Accept         = 'application/json;odata.metadata=minimal;odata.streaming=true'
        Authorization  = "Bearer $($accessToken)"
    }

    # Verify if there are any assigned permissions in the entitlement context object
    $currentPermissions = [System.Collections.Generic.List[Object]]::new()
    if ($eRef.CurrentPermissions.Count -gt 0) {
        foreach ($entitlement in $eRef.CurrentPermissions) {
            $currentPermission = @{
                DisplayName = $entitlement.DisplayName 
                Id          = $entitlement.Reference.Id
                Company     = $entitlement.Reference.company
                Identifier  = $entitlement.DisplayName + $entitlement.Reference.company
            }
            $currentPermissions.Add($currentPermission)
        }
    }

    if ($useAB) {
        ## Get roles first and fill current permissions
        $splatGetRoles = @{
            Uri     = "$($config.BaseUrl)" + '/odata/OrgRolesPerUser?$filter=' + "databaseConnection eq '$($config.database)' and userName eq '$($account.Username)'"
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
                    Identifier  = $entitlement.OrganizationRoleName + $entitlement.company
                }
                $currentPermissions.Add($currentPermission)
            }
        }
        
    } 

    write-verbose -verbose "Current permissions" 
    write-verbose -verbose ($currentPermissions | out-string)

    # Test purposes -> All contracts
    $contractsInScope = ($p.Contracts | Where-Object { $_.Context.InConditions -eq $true })# 
    if ($null -ne $contractsInScope) {

       
        $filter = "?`$filter=DatabaseConnection eq '$($config.Database)' and ("
        $filter += ($contractsinscope.title.name | ForEach-Object { "Name eq '$_'" }) -join " or "
        $filter += ")"

        #Would be nice if we had a function containing regex that replaces all those escapable characters.
        $filter = $filter.replace("&","%26").replace("/","%2F")
        $filter = $filter.replace("&","%26").replace("/","%2F")
        
        $splatGetOrganizationRoles = @{
            Uri     = "$($config.BaseUrl)/odata/OrganizationRole$($filter)"
            Method  = 'GET'
            Headers = $headers
        }
        $organizationRoles = (Invoke-RestMethod @splatGetOrganizationRoles -Verbose:$false).value

        #write-verbose -verbose ($organizationRoles | out-string)

        $desiredPermissions = [System.Collections.Generic.List[Object]]::new()
        foreach ($contract in $contractsInScope) {

            #Test purposes
            #$contract.Title.Name = 'helpdeskmedewerker ICT' 

            # Custom Havensteder -> Default Company
            $DefaultCompany = 'Company'

            #write-verbose -verbose "$($contract.Title.Name) , $($contract.Department.displayname)"  

            # create organizationRoleObject without properties: freeFields and companyGroup because it is not required. value will automatically be set to null
            $desiredPermissionObject = @{
                status               = "Assign"
                displayname          = ($organizationRoles | Where-Object { $_.Name -eq $contract.Title.Name -and $_.DeparmentName -eq $contract.Department.displayname }).Name
                startDate            = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                #endDate              = (Get-Date "2099-12-31T23:59:59").ToString("yyyy-MM-ddTHH:mm:ssZ")
                organizationRoleCode = ($organizationRoles | Where-Object { $_.Name -eq $contract.Title.Name -and $_.DeparmentName -eq $contract.Department.displayname }).Key
                company              = $DefaultCompany
                identifier           = ($organizationRoles | Where-Object { $_.Name -eq $contract.Title.Name -and $_.DeparmentName -eq $contract.Department.displayname }).Name + $DefaultCompany
            }

            write-verbose -verbose ($desiredPermissionObject | out-string)

            if($desiredPermissionObject.organizationRoleCode.count -eq 0){
                throw "Geen match gevonden met rol: $($contract.Title.Name), $($contract.Department.displayname) "
            }

            if($desiredPermissionObject.organizationRoleCode.count -gt 1){
                throw "Mogelijk zijn er meerdere rollen met dezelfde functie / afdeling combinatie: $($contract.Title.Name) , $($contract.Department.displayname)"
            }

            #write-verbose -verbose ($desiredPermissions | out-string)
            $desiredPermissions.Add($desiredPermissionObject)
        }

    }
    else { 
        $desiredPermissions = $null
    }

    if($actionContext.Operation -eq "Revoke"){
        $desiredPermissions = $null
    }

    # Built up the sub-permissions object
    if ($desiredPermissions) {
        foreach ($permission in $desiredPermissions) {
            $subPermissions.Add([PSCustomObject]@{
                    DisplayName = $permission.displayName
                    Reference   = [PSCustomObject]@{
                        Id      = $permission.organizationRoleCode
                        Company = $permission.company
                    }
                })
        }

        # Iterate through all desired permissions. If a desired permission is not found in the entitlementContext, add it to the 'permissionsToGrant' list.
        foreach ($permission in $desiredPermissions) {  
            #Identifier should be a mix of name and company, not name alone
            $Identifier = $($permission.displayname) + $($permission.company)

            if (-not $currentPermissions -or -not $currentPermissions.ContainsValue($Identifier)) {
                $permissionsToGrant.Add($permission)
            }
        }
    }

    # Iterate through all current permissions. If a current permission is not found in the 'desiredPermissions' or if the
    # 'desiredPermissions' object is empty, add the permission to the 'permissionsToRevoke' list.
    
    if ($desiredPermissions) {
        if ($currentPermissions) {
            foreach ($permission in $currentPermissions) {

                if (-not $desiredPermissions.ContainsValue($permission.Identifier) ) {
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

    $authorization = [PSCustomObject]@{
        securityId            = $Account.SecurityID
        databaseName          = $($config.Database)
        userValueSourcesModel = [PSCustomObject]@{
            userName = $Account.userName
            fullName = $Account.fullName
            firstName = $personContext.Person.Name.NickName
            middleName = $personContext.Person.Name.FamilyNamePrefix
            surName = $personContext.Person.Name.FamilyName
            employeeNoExternal = $Account.userName.replace("domain\", "")
            freeField1 = if($personContext.Person.Details.Gender -eq "MALE"){"DHR"} else {"MEVR"}
            freeField2 = "domain\" + $personContext.Manager.Accounts.MicrosoftActiveDirectory.samaccountname
            mobilePhoneNo = $personContext.Person.Contact.Business.Phone.Mobile
            email       = $personContext.Person.Accounts.MicrosoftActiveDirectory.Mail
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
            $permission.Remove("identifier")

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

    write-verbose -verbose "Authorization body"
    write-verbose -verbose ($authorization | ConvertTo-Json -Depth 10)

    if ($authorization.organizationRoles.count -gt 0) {
        if (-not ($actionContext.DryRun -eq $true)) {

            #Add authorization with the correct organizationRoles
            $splatUpdateAuthorization = @{
                Uri     = "$($config.BaseUrl)/authorizationrequest/Authorization"
                Method  = 'POST'
                Body    = ($authorization | ConvertTo-Json -Depth 10)
                Headers = $headers
            }
            
            try {
                $null = Invoke-RestMethod @splatUpdateAuthorization -Verbose:$false
            }
            catch {
                #If there is an open authorization this will fail.
                throw "Mislukt om een authorizatieverzoek te maken. Mogelijk staat er al een verzoek voor deze persoon klaar"
            }

            $outputContext.success = $true
        }
    }
    else {
        #No call needed as everything is good as is
        $outputContext.success = $true
    }


    <## Make sure to test with special characters and if needed; add utf8 encoding.
    foreach ($permission in $desiredPermissions) {
        $outputContext.Permissions.Add(
            @{
                DisplayName    = $permission.displayName
                Identification = @{
                    Id   = $permission.organizationRoleCode
                    Company = $permission.company
                }
            }
        )
    }#>
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
}
