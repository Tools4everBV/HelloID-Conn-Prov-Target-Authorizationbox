#################################################
# HelloID-Conn-Prov-Target-Authorizationbox-Create
# PowerShell V2
#################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

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

function Remove-StringLatinCharacters {
    PARAM ([string]$String)
    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
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
    
    # Initial Assignments
    $outputContext.AccountReference = 'Currently not available'
    
    # Define correlation
    $correlationField = $actionContext.CorrelationConfiguration.accountField
    $correlationValue = $actionContext.CorrelationConfiguration.personFieldValue

    #Write-Information "$correlationField - $correlationValue"

    # In V3 we need to convert the database name to a database ID
    $splatGetDatabase = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/api/v2.0/Database"
        Method  = 'GET'
        Headers = $headers
    }
    $DatabaseList = (Invoke-RestMethod @splatGetDatabase -Verbose:$false) | Group-Object name -AsHashTable        
    $DatabaseID = $DatabaseList[$($actionContext.Configuration.Database)].id

    # Validate correlation configuration
    if ($actionContext.CorrelationConfiguration.Enabled) {
        
        #Get user (If no results are returned, try getting users without the filter)
        $filter = "?`$filter=(databaseId eq $DatabaseID and $correlationField eq $correlationValue)"
        write-verbose -verbose ($filter | out-string)

        $splatGetUsers = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/odata/v2.0/Users$($filter)"
            Method  = 'GET'
            Headers = $headers
        }
    
        $User = (Invoke-RestMethod @splatGetUsers -Verbose:$false).value

        #Sometimes, users exists 2x in the DB with the same userSecurityId
        if($user.count -gt 1){
            $User = $user[0]
        }
        
    }
    else {
        Write-Error "Correlation is required, please configure this in the connector"
    }

    if ($User) {
        $action = 'CorrelateAccount'
    }
    else {
        $action = 'Not Found'
    } 

    # Add a message and the result of each of the validations showing what will happen during enforcement
    if ($actionContext.DryRun -eq $true) {
        Write-Information "[DryRun] $action Authorizationbox account for: [$($personContext.Person.DisplayName)], will be executed during enforcement"
    }

    switch ($action) {
        'Not Found' {
            
            Write-Information 'User not found in Authorizationbox, trying to send in empty authorization request & retry correlate'

            if (-not($actionContext.DryRun -eq $true)) {

                $authorization = [PSCustomObject]@{
                    securityId   = $correlationValue 
                    databaseId   = $DatabaseID
                    processRequest = $true
                }

                # Create Authorization
                $excludedFields = @("userSecurityId")

                $userValueData = $actionContext.Data | Get-Member -MemberType NoteProperty | Where-Object {
                    $excludedFields -notcontains $_.Name
                } | ForEach-Object {
                    @{ Name = $_.Name; Value = $actionContext.Data.($_.Name) }
                }

                $userValueSourcesModel = [PSCustomObject]@{}
                foreach ($item in $userValueData) {
                    $userValueSourcesModel | Add-Member -NotePropertyName $item.Name -NotePropertyValue $item.Value
                }
                $authorization | Add-Member -NotePropertyName "userValueSourcesModel" -NotePropertyValue $userValueSourcesModel

                #Send Auth request
                $splatSendAuthorization = @{
                    Uri     = "$($actionContext.Configuration.BaseUrl)/authorizationrequest/V3/Authorization"
                    Method  = 'POST'
                    Body    = ($authorization | ConvertTo-Json -Depth 10)
                    Headers = $headers
                } 

                $null = Invoke-RestMethod @splatSendAuthorization -Verbose:$false
                
                #If this doesnt return an error, correlate user again
                $filter = "?`$filter=(databaseId eq $databaseid and $correlationField eq $correlationValue)"
        
                $splatGetUsers = @{
                    Uri     = "$($actionContext.Configuration.BaseUrl)/odata/v2.0/Users$($filter)"
                    Method  = 'GET'
                    Headers = $headers
                }
            
                $User = (Invoke-RestMethod @splatGetUsers -Verbose:$false).value | Select-Object -First 1

                if ($null -ne $User) {

                    $outputContext.Data.userSecurityID = $($User.userSecurityID)
                    $outputContext.Data.fullName = $($User.fullName)
                    $outputContext.Data.userName = $($User.userName)

                    $accountRef = [PSCustomObject]@{
                        userSecurityId  = $outputContext.Data.userSecurityId
                        fullName = $outputContext.Data.fullName
                        userName    = $outputContext.Data.userName
                    }

                    $outputContext.AccountCorrelated = $false
                    $outputContext.AccountReference = $accountRef
                    $outputContext.success = $true

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = 'CorrelateAccount'
                            Message = "Correlated account by creating first authorization request for: [$($actionContext.Data.Username)]. AccountReference is: [$($outputContext.AccountReference)]"
                            IsError = $false
                        })
                }
                else {
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = 'CorrelateAccount'
                            Message = "Correlate account was unsuccessful. User has not been found in Authorizationbox"
                            IsError = $true
                        })
                } 

            }
            else {
                Write-Information 'Dryrun prevented this action'
            }
            break
        }

        'CorrelateAccount' {
            Write-Information 'Correlating Authorizationbox User'

            $outputContext.Data.userSecurityID = $($User.userSecurityID)
            $outputContext.Data.fullName = $($User.fullName)
            $outputContext.Data.userName = $($User.userName)

            $accountRef = [PSCustomObject]@{
                userSecurityId  = $outputContext.Data.userSecurityId
                fullName = $outputContext.Data.fullName
                userName    = $outputContext.Data.userName
            }

            $outputContext.AccountCorrelated = $true
            $outputContext.AccountReference = $accountRef
            $outputContext.success = $true

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Action  = 'CorrelateAccount'
                    Message = "Correlated account: [$($actionContext.Data.Username)]. AccountReference is: [$($outputContext.AccountReference)]"
                    IsError = $false
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
        $auditMessage = "Could not create or correlate Authorizationbox account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Could not create or correlate Authorizationbox account. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}