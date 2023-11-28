#############################################################
# HelloID-Conn-Prov-Target-Authorizationbox-Entitlement-Grant
#
# Version: 1.0.0
#############################################################
# Initialize default values
$p = $person | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json
$eRef = $entitlementContext | ConvertFrom-Json
$pRef = $permissionReference | ConvertFrom-Json
$success = $false

# Define all empty objects
$auditLogs = [Collections.Generic.List[PSCustomObject]]::new()
$subPermissions = [Collections.Generic.List[PSCustomObject]]::new()
$permissionsToGrant = [System.Collections.Generic.List[object]]::new()
$permissionsToRevoke = [System.Collections.Generic.List[object]]::new()

#region functions
function Resolve-AuthorizationboxError {
    param (
        [object]
        $ErrorObject
    )
    {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }       
        if ($ErrorObject.ErrorDetails) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails
            $httpErrorObj.FriendlyMessage = $ErrorObject.ErrorDetails
        }
        try {
            $httpErrorObj.FriendlyMessage = ($httpErrorObj.FriendlyMessage | ConvertFrom-Json).error_description
        }
        catch {
            # Displaying the old message if an error occurs during an API call, as the error is related to the API call and not the conversion process to JSON.
            Write-Warning "Unexpected web-service response, Error during Json conversion: $($_.Exception.Message)"
        }
        Write-Output $httpErrorObj
    }
}
#endregion

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

    $splatGetOrganizationRoles = @{
        Uri     = "$($config.BaseUrl)/odata/OrganizationRole"
        Method  = 'GET'
        Headers = $headers
    }
    $organizationRoles = ((Invoke-RestMethod @splatGetOrganizationRoles -Verbose:$false).value | Where-Object { $_.DatabaseConnection -eq $config.Database })

    # Verify if there are any assigned permissions in the entitlement context object
    $currentPermissions = [System.Collections.Generic.List[Object]]::new()
    if ($eRef.CurrentPermissions.Count -gt 0) {
        foreach ($entitlement in $eRef.CurrentPermissions) {
            $currentPermission = @{
                DisplayName = ($organizationRoles | Where-Object { $_.Name -eq $entitlement.DisplayName }).Name
                Id          = ($organizationRoles | Where-Object { $_.Key -eq $entitlement.Reference.Id }).Id
            }
            $currentPermissions.Add($currentPermission)
        }
    }

    # Retrieving the desired permissions based on the contracts that fall within the scope of a specific business rule
    # In this case, we assume that the Department.DisplayName corresponds with a groupName in the target application
    $contractsInScope = ($p.Contracts | Where-Object { $_.Context.InConditions -eq $true })
    if ($null -ne $contractsInScope) {
        $desiredPermissions = [System.Collections.Generic.List[Object]]::new()
        foreach ($contract in $contractsInScope) {
            $desiredPermissionObject = @{
                DisplayName = $contract.Title.Name
                Id          = ($organizationRoles | Where-Object { $_.Name -eq $contract.Title.Name -and $_.DeparmentName -eq $contract.Department.displayname }).Id
            }
            $desiredPermissions.Add($desiredPermissionObject)
        }
    }
    else {
        $desiredPermissions = $null
    }

    # Built up the sub-permissions object
    if ($desiredPermissions) {
        foreach ($permission in $desiredPermissions.GetEnumerator()) {
            $subPermissions.Add([PSCustomObject]@{
                    DisplayName = $permission.DisplayName
                    Reference   = [PSCustomObject]@{
                        Id = $permission.Id
                    }
                })
        }

        # Iterate through all desired permissions. If a desired permission is not found in the entitlementContext, add it to the 'permissionsToGrant' list.
        foreach ($permission in $desiredPermissions.GetEnumerator()) {
            if (-not $currentPermissions -or -not $currentPermissions.ContainsValue($permission.DisplayName)) {
                $permissionsToGrant.Add($permission)
            }
        }
    }


    # Iterate through all current permissions. If a current permission is not found in the 'desiredPermissions' or if the
    # 'desiredPermissions' object is empty, add the permission to the 'permissionsToRevoke' list.
    if ($currentPermissions) {
        foreach ($permission in $currentPermissions.GetEnumerator()) {
            if (-not $desiredPermissions.ContainsValue($permission.DisplayName)) {
                $permissionsToRevoke.Add($permission)
            }
            elseif (-not $desiredPermissions) {
                $permissionsToRevoke.Add($permission)
            }
        }
    }

    # Process results
    if (-not ($dryRun -eq $true)) {
        $splatGetAuthorization = @{
            Uri     = "$($config.BaseUrl)/authorizationrequest/Authorization/$($aRef)"
            Method  = 'Get'
            Headers = $headers
        }
        $authorization = Invoke-RestMethod @splatGetAuthorization -Verbose:$false        

        # Add permissions to the authorization 
        foreach ($permission in $permissionsToGrant.GetEnumerator()) {
            $authorization.organizationRoles += $permission
        }

        # Remove permissions from the authorization
        foreach ($permission in $permissionsToRevoke.GetEnumerator()) {
            $authorization.organizationRoles -= $permission
        }

        #update authorization with the correct organizationRoles
        $splatUpdateAuthorization = @{
            Uri     = "$($config.BaseUrl)/authorizationrequest/$($aRef)"
            Method  = 'PATCH'
            Body    = $authorization | convertTo-json
            Headers = $headers
        }
        $null = Invoke-RestMethod @splatUpdateAuthorization -Verbose:$false


        # Add Logging when the update of the 
        foreach ($permission in $permissionsToGrant.GetEnumerator()) {
            Write-Verbose "Granting demo entitlement: [$($permission.DisplayName)]"
            $auditLogs.Add([PSCustomObject]@{
                    Action  = "GrantPermission"
                    Message = "Granted access to: [$($permission.DisplayName)]"
                    IsError = $false
                })
        }
        
        foreach ($permission in $permissionsToRevoke.GetEnumerator()) {          
            Write-Verbose "Revoking demo entitlement: [$($permission.DisplayName)]"
            $auditLogs.Add([PSCustomObject]@{
                    Action  = "RevokePermission"
                    Message = "Revoked access from: [$($permission.DisplayName)]"
                    IsError = $false
                })
        }
        $success = $true
    }
}
catch {
    $success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-AuthorizationboxError -ErrorObject $ex
        $auditMessage = "Could not update Organization roles for account: [$($aRef)]. Error: $($errorObj.FriendlyMessage)"
        Write-Verbose "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Could not update Organization roles for account: [$($aRef)]. Error: $($errorObj.FriendlyMessage)"
        Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $auditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}
finally {
    $result = [PSCustomObject]@{
        Success        = $success
        SubPermissions = $subPermissions
        AuditLogs      = $auditLogs
    }

    Write-Output $result | ConvertTo-Json -Depth 10
}
