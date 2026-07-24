#################################################
# HelloID-Conn-Prov-Target-Authorizationbox-Disable
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

#endregion

try {
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }

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
    if ([string]::IsNullOrWhiteSpace([string]$DatabaseID)) {
        throw "DatabaseID could not be resolved for database [$($actionContext.Configuration.Database)]"
    }

    # Check if account exists
    Write-Information 'Verifying if an Authorizationbox account exists'

    $filter = "?`$filter=(databaseId eq $DatabaseID and userSecurityId eq $($actionContext.References.Account.userSecurityId))"
    
    $splatGetUsers = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/odata/v2.0/Users$($filter)"
        Method  = 'GET'
        Headers = $headers
    }

    $correlatedAccount = (Invoke-RestMethod @splatGetUsers -Verbose:$false).value | Select-Object -First 1

    if ($null -ne $correlatedAccount) {
        $action = 'DisableAccount'
    }
    else {
        $action = 'NotFound'
    }

    # Process
    switch ($action) {
        'DisableAccount' {
            $authorization = [PSCustomObject]@{
                securityId   = $($actionContext.References.Account.userSecurityId)
                databaseId   = $DatabaseID
                activateUser = $false   #Can be toggled
                disableUserStartDate = (Get-Date).AddDays(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
                processRequest = $true
                organizationRoles     = @()
            }

            # Get current user data from Authorizationbox
            Write-Information 'Retrieving current user data from Authorizationbox'
            $splatGetUserData = @{
                Uri     = "$($actionContext.Configuration.BaseUrl)/api/v2.0/Users/($($correlatedAccount.key))/GetUserDataForUser"
                Method  = 'GET'
                Headers = $headers
            }

            try {
                $currentUserData = (Invoke-RestMethod @splatGetUserData -Verbose:$false)

                # Create Authorization
                $excludedFields = @("userSecurityId", "fullName")

                # Use all fields from currentUserData
                $userValueData = @{}
                foreach ($field in $currentUserData) {
                    if ($excludedFields -notcontains $field.type) {
                        $userValueData[$field.type] = $field.value
                    }
                }

                $userValueSourcesModel = [PSCustomObject]@{}
                $userValueSourcesModel | Add-Member -NotePropertyName 'fullName' -NotePropertyValue $($actionContext.References.Account.fullName)

                foreach ($fieldName in $userValueData.Keys) {
                    $userValueSourcesModel | Add-Member -NotePropertyName $fieldName -NotePropertyValue $userValueData[$fieldName]
                }

                $authorization | Add-Member -NotePropertyName "userValueSourcesModel" -NotePropertyValue $userValueSourcesModel
            }
            catch {
                Throw "Could not retrieve current user data: $($_.Exception.Message)."
            }

            <# Delete all roles - Example
            $splatGetRoles = @{
                Uri     = "$($actionContext.Configuration.BaseUrl)" + "/odata/v2.0/OrgRolesPerUser?`$filter=(databaseId eq $DatabaseID and userCode eq $($correlatedAccount.key))"    
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

            foreach ($permission in $currentPermissions) {
                    $RemovePermissionObject = @{
                        status               = "Revoke"
                        displayname          = $permission.displayname
                        #startDate            = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                        endDate              = (Get-Date).AddDays(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
                        organizationRoleCode = $permission.id
                        company              = $permission.company
                    }

                    $authorization.organizationRoles += $RemovePermissionObject
            }
            #>

            #write-verbose -verbose ($authorization | ConvertTo-Json -Depth 10)

            # Convert authorization object to JSON with UTF-8 encoding
            $authorization_json = ($authorization | ConvertTo-Json -Depth 10)
            $headers = @{
                'Content-Type' = 'application/json;charset=utf-8'
                Accept         = 'application/json;odata.metadata=minimal;odata.streaming=true'
                Authorization  = "Bearer $($accessToken)"
            }

            #Send Auth request
            $splatSendAuthorization = @{
                Uri     = "$($actionContext.Configuration.BaseUrl)/authorizationrequest/V3/Authorization"
                Method  = 'POST'
                #Body    = ($authorization | ConvertTo-Json -Depth 10)
                Body    = [System.Text.Encoding]::UTF8.GetBytes($authorization_json)
                Headers = $headers
            } 

            # Make sure to test with special characters and if needed; add utf8 encoding.
            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information "Disable AuthorizationBox account with accountReference: [$($actionContext.References.Account.userSecurityId)]"
                
                # Single retry for transient "active requests pending" condition
                try {
                    $null = Invoke-RestMethod @splatSendAuthorization -Verbose:$false
                }
                catch {
                    $errorObj = Resolve-AuthorizationboxError -ErrorObject $_
                    $errText = $($errorObj.FriendlyMessage)
                    
                    if ($errText -match 'active requests pending') {
                        Write-Information "Pending request detected; retrying once in 5s"
                        Start-Sleep -Seconds 5
                        # Second attempt; any failure bubbles to outer catch
                        $null = Invoke-RestMethod @splatSendAuthorization -Verbose:$false
                    }
                    else {
                        throw
                    }
                }
                
            }
            else {
                Write-Information "[DryRun] Disable AuthorizationBox account with accountReference: [$($actionContext.References.Account.userSecurityId)], will be executed during enforcement"
            }

            # Make sure to filter out arrays from $outputContext.Data (If this is not mapped to type Array in the fieldmapping). This is not supported by HelloID.
            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Disable account was successful"
                    IsError = $false
                }
            )

            break
        }


        'NotFound' {
            Write-Information "AuthorizationBox account with userSecurityId [$($actionContext.References.Account.userSecurityId)] in database [$DatabaseID] not found. It may not exist or was deleted."            
            $outputContext.Success = $false
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "AuthorizationBox account with userSecurityId [$($actionContext.References.Account.userSecurityId)] in database [$DatabaseID] not found. It may not exist or was deleted."
                    IsError = $true
                })
            break
        }
    }
} 
catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-AuthorizationboxError -ErrorObject $ex
        $auditMessage = "Could not disable Authorizationbox account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Could not disable Authorizationbox account. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}