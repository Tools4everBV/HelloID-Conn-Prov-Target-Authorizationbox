#################################################
# HelloID-Conn-Prov-Target-Authorizationbox-Create
# PowerShell V2
#################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#$actionContext.DryRun = $false

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
#endregion

$outputContext.success = $false

try {

    $s = New-PSSession -ComputerName  $actionContext.Configuration.Applicationserver

    #Not sure how $Using: works with object properties
    $EmailAddress = $actionContext.Data.EmailAddress
    $SamAccountName = $actionContext.Data.Username
    $DefaultCompany = $actionContext.Data.DefaultCompany
    $UserPrincipalName = $actionContext.Data.userPrincipalName
    $Displayname = $actionContext.Data.Displayname
    $NavServerInstanceName = $actionContext.Configuration.NavServerInstanceName
    $tenant = $actionContext.Configuration.Tenant
    $LanguageID = $actionContext.Configuration.LanguageID
    $Permissions = $actionContext.Configuration.Permissions

    
    #Make sure module is imported
    Invoke-Command -Session $s -ScriptBlock { $ImportModule = Import-Module "D:\Program Files\Microsoft Dynamics 365 Business Central\Service\NavAdminTool.ps1" -ErrorAction SilentlyContinue }

    # Initial Assignments
    $outputContext.AccountReference = 'Currently not available'
    
    # Validate correlation configuration
    if ($actionContext.CorrelationConfiguration.Enabled) {
        # Verify if a user must be either [created ] or just [correlated]
        $correlatedAccount = Invoke-Command -Session $s -ScriptBlock {Get-NAVServerUser -ServerInstance $using:NavServerInstanceName -Tenant $using:tenant | Where-Object {$_.UserName -eq $using:SamAccountName}} 

    }

    if ($null -ne $correlatedAccount) {
        $action = 'CorrelateAccount'
    }
    else {
        $action = 'CreateAccount'
    } 

    # Add a message and the result of each of the validations showing what will happen during enforcement
    if ($actionContext.DryRun -eq $true) {
        Write-Information "[DryRun] $action Authorizationbox account for: [$($personContext.Person.DisplayName)], will be executed during enforcement"
    }

    
    # Process
        switch ($action) {
            'CreateAccount' {
                Write-Information 'Creating Nav User'

                if (-not($actionContext.DryRun -eq $true)) {
                # Make sure to test with special characters and if needed; add utf8 encoding.
                Invoke-Command -Session $s -ScriptBlock {$CreateNavUser = New-NAVServerUser -ServerInstance $using:NavServerInstanceName -Tenant $using:tenant -WindowsAccount $using:SamAccountName -FullName $using:DisplayName -AuthenticationEmail $using:UserPrincipalName -Company $using:DefaultCompany -LanguageID $using:LanguageID -ContactEmail $using:EmailAddress -ErrorAction SilentlyContinue -Verbose}
                Invoke-Command -Session $s -ScriptBlock {$CreateNavUserPermission = New-NAVServerUserPermissionSet -ServerInstance $using:NavServerInstanceName -Tenant $using:tenant -WindowsAccount $using:SamAccountName -PermissionSetId $using:Permissions -ErrorAction SilentlyContinue -Verbose}
            
                $result = Invoke-Command -Session $s -ScriptBlock {Get-NAVServerUser -ServerInstance $using:NavServerInstanceName -Tenant $using:tenant | Where-Object {$_.UserName -eq 'WOCO\'+$using:SamAccountName}} 
           
                $outputContext.Data.SecurityID = $($result.UserSecurityID)
                $outputContext.Data.DisplayName = $($result.Fullname)
                $outputContext.Data.UserName = $($result.Username)

                $auditLogMessage = "Create account was successful. AccountReference is: [$($outputContext.AccountReference)"
                break
                } else {
                    Write-Information 'Dryrun prevented this action' 
                }
            }

            'CorrelateAccount' {
                Write-Information 'Correlating Nav User'

                $outputContext.Data.SecurityID = $($correlatedAccount.UserSecurityID)
                $outputContext.Data.DisplayName = $($correlatedAccount.Fullname)
                $outputContext.Data.UserName = $($correlatedAccount.Username)

                $outputContext.AccountCorrelated = $true
                $auditLogMessage = "Correlated account: [$($actionContext.Data.Username)]. AccountReference is: [$($outputContext.AccountReference)"
                break
            }
        }

        $accountRef = [PSCustomObject]@{
                    SecurityID = $outputContext.Data.SecurityID
                    DisplayName = $outputContext.Data.DisplayName
                    UserName     = $outputContext.Data.UserName
        }

        $outputContext.AccountReference = $accountRef
                 
        $outputContext.success = $true
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Action  = $action
                Message = $auditLogMessage
                IsError = $false
            })
    
}

catch {
    Exit-PSSession
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
