############################################################
# HelloID-Conn-Prov-Target-Authorizationbox-Permissions-Roles
# PowerShell V2
############################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set to false at start, at the end, only when no error occurs it is set to true
$outputContext.Success = $false 


#region functions
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
            Uri     = "$($actionContext.Configuration.BaseUrl)/api/Authenticate/AccessToken"
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

    # Might need paging
    $splatGetOrganizationRoles = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/odata/v2.0/OrganizationRole?`$filter=databaseID eq $databaseid"
        Method  = 'GET'
        Headers = $headers
    }
    $organizationRoles = (Invoke-RestMethod @splatGetOrganizationRoles -Verbose:$false).value

    Write-Information "Queried Roles. Result count: $(($organizationRoles | Measure-Object).Count)"
    #endregion Get Groups

    #region Send results to HelloID
    $organizationRoles | ForEach-Object {
        # Shorten DisplayName to max. 100 chars
        $displayName = "Role - $($_.Name)"
        $displayName = $displayName.substring(0, [System.Math]::Min(100, $displayName.Length))

        $outputContext.Permissions.Add(
            @{
                displayName    = $displayName
                identification = @{
                    Id = $_.Key
                    Company = $_.Company
                }
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
