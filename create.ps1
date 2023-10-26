##################################################
# HelloID-Conn-Prov-Target-Authorizationbox-Create
#
# Version: 1.0.0
##################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$success = $false
$updatePerson = $config.updatePersonOnCorrelate
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

# Account mapping
$account = [PSCustomObject]@{

    userID = $p.ExternalId
    userName = $p.UserName
    sid = $p.ExternalId
    surname = $p.Name.FamilyName
    firstName = $p.Name.GivenName
    EmailAddress = $p.Accounts.MicrosoftActiveDirectory.mail
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

    $splatGetAuthorization= @{
        Uri     = "$($config.BaseUrl)/authorizationrequest/Authorization"
        Method  = 'GET'
        Headers = $headers
    }
    $responseUser = ((Invoke-RestMethod @splatGetAuthorization -Verbose:$false) | Where-Object { $_.DatabaseConnection -eq "Empire OO" -and $_.userValueSourcesModel.email -eq $account.EmailAddress})
    
    # Verify if a user must be either [created and correlated], [updated and correlated] or just [correlated]
    if ($null -eq $responseUser){
        throw "User not found, create account in Empire"
    }

    if ($updatePerson -eq $true) {
        $action = 'Update-Correlate'
    } else {
        $action = 'Correlate'
    }

    # Add a warning message showing what will happen during enforcement
    if ($dryRun -eq $true) {
        Write-Warning "[DryRun] $action Authorizationbox account for: [$($p.DisplayName)], will be executed during enforcement"
    }

    # Process
    if (-not($dryRun -eq $true)) {
        switch ($action) {
            'Update-Correlate' {
                Write-Verbose 'Updating and correlating Authorizationbox account'

                $splatUpdateAuthorization = @{
                    Uri     = "$($config.BaseUrl)/authorizationrequest/Authorization/$($responseuser.code)"
                    Method  = 'Patch'
                    Body    = $account | ConvertTo-Json
                    Headers = $headers
                }
                $null = Invoke-RestMethod @splatUpdateAuthorization -Verbose:$false

                $accountReference = $responseUser.securityId
                break
            }

            'Correlate' {
                Write-Verbose 'Correlating Authorizationbox account'
                $accountReference = $responseUser.securityId
                break
            }
        }

        $success = $true
        $auditLogs.Add([PSCustomObject]@{
                Message = "$action account was successful. AccountReference is: [$accountReference]"
                IsError = $false
            })
    }
} catch {
    $success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-AuthorizationboxError -ErrorObject $ex
        $auditMessage = "Could not $action Authorizationbox account. Error: $($errorObj.FriendlyMessage)"
        Write-Verbose "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not $action Authorizationbox account. Error: $($ex.Exception.Message)"
        Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $auditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
# End
} finally {
    $result = [PSCustomObject]@{
        Success          = $success
        AccountReference = $accountReference
        Auditlogs        = $auditLogs
        Account          = $account
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}
