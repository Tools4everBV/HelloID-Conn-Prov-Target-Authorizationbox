##################################################
# HelloID-Conn-Prov-Target-Authorizationbox-Update
#
# Version: 1.0.0
##################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

# Account mapping
# For additional attributes in the userValueSourcesModel see: https://api.2-control.nl/authorizationrequest/swagger/index.html
$account = [PSCustomObject]@{
    userID       = $p.ExternalId
    userName     = $p.UserName
    sid          = $p.ExternalId
    surname      = $p.Name.FamilyName
    firstName    = $p.Name.GivenName
    companyEmail = $p.Accounts.MicrosoftActiveDirectory.mail
}

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($($config.IsDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

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

# Begin
try {
    Write-Verbose 'Getting authorization token'
    $tokenHeaders = @{
        'Content-Type' = 'application/json'
        Accept         = 'application/json;odata.metadata=minimal;odata.streaming=true'
    }
    $tokenBody = @{
        'token' = $config.token
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

    Write-Verbose "Verifying if a Authorizationbox account for [$($p.DisplayName)] exists"
    $splatGetUser = @{
        Uri     = "$($config.BaseUrl)/authorizationrequest/Authorization/$($aRef)"
        Method  = 'Get'
        Headers = $headers
    }
    $currentUser = Invoke-RestMethod @splatGetUser -Verbose:$false

    # Verify if the account must be updated
    # Always compare the account against the current account in target system
    $splatCompareProperties = @{
        ReferenceObject  = @($currentUser.PSObject.Properties)
        DifferenceObject = @($account.PSObject.Properties)
    }

    $splatCompareUserValueSourcesModelProperties = @{
        ReferenceObject  = @($currentUser.userValueSourcesModel.PSObject.Properties)
        DifferenceObject = @($account.userValueSourcesModel.PSObject.Properties)
    }

    $propertiesChanged = (Compare-Object @splatCompareProperties -PassThru).Where({$_.SideIndicator -eq '=>'})
    $UserValueSourcesModelPropertiesChanged = (Compare-Object @splatCompareProperties -PassThru).Where({$_.SideIndicator -eq '=>'})


    if (({$propertiesChanged} -or {$UserValueSourcesModelPropertiesChanged}) -and ($null -ne $currentUser)) {
        $action = 'Update'
        $dryRunMessage = "Account property(s) required to update: [$($propertiesChanged.name -join ",")]"
    } elseif (-not($propertiesChanged)) {
        $action = 'NoChanges'
        $dryRunMessage = 'No changes will be made to the account during enforcement'
    } elseif ($null -eq $currentUser) {
        $action = 'NotFound'
        $dryRunMessage = "Authorizationbox account for: [$($p.DisplayName)] not found. Possibly deleted"
    }
    Write-Verbose $dryRunMessage

    # Add an auditMessage showing what will happen during enforcement
    if ($dryRun -eq $true) {
        Write-Warning "[DryRun] $dryRunMessage"
    }

    # Process
    if (-not($dryRun -eq $true)) {
        switch ($action) {
            'Update' {
                Write-Verbose "Updating Authorizationbox account with accountReference: [$aRef]"
                $patchBody = @{}
                foreach ($property in $propertiesChanged) {
                    $propertyName = $property.Name
                    $patchBody[$propertyName] = $account.$propertyName
                }

                $splatUpdateParams = @{
                    Uri         = "$($config.BaseUrl)/authorizationrequest/Authorization/$($aRef)"
                    Headers     = $headers
                    Method      = 'PATCH'
                    ContentType = 'application/json'
                    Body        = $patchBody | ConvertTo-Json
                }
                $null = Invoke-RestMethod @splatUpdateParams -Verbose:$false
                $success = $true
                $auditLogs.Add([PSCustomObject]@{
                    Message = 'Update account was successful'
                    IsError = $false
                })
                break
            }

            'NoChanges' {
                Write-Verbose "No changes to Authorizationbox account with accountReference: [$aRef]"
                $success = $true
                $auditLogs.Add([PSCustomObject]@{
                    Message = 'No changes will be made to the account during enforcement'
                    IsError = $false
                })
                break
            }

            'NotFound' {
                $success = $false
                $auditLogs.Add([PSCustomObject]@{
                    Message = "Authorizationbox account for: [$($p.DisplayName)] not found. Possibly deleted"
                    IsError = $true
                })
                break
            }
        }
    }
} catch {
    $success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException')) {
        $errorObj = Resolve-AuthorizationboxError -ErrorObject $ex
        $auditMessage = "Could not update Authorizationbox account. Error: $($errorObj.FriendlyMessage)"
        Write-Verbose "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not update Authorizationbox account. Error: $($ex.Exception.Message)"
        Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $auditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
# End
} finally {
    $result = [PSCustomObject]@{
        Success   = $success
        Account   = $account
        Auditlogs = $auditLogs
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}
