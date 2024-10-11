#################################################
# HelloID-Conn-Prov-Target-Authorizationbox-Update
# PowerShell V2
#################################################

#$actionContext.DryRun = $false

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
        } elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
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
        } catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}
#endregion

try {
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        #throw 'The account reference could not be found'
    }

    $s = New-PSSession -ComputerName  $actionContext.Configuration.Applicationserver
   
    #Not sure how $Using: works with object properties
    $SamAccountName = $actionContext.Data.Username
    $Displayname = $actionContext.Data.DisplayName
    $UserPrincipalName = $actionContext.Data.userPrincipalName
    $DefaultCompany = $actionContext.Data.DefaultCompany
    $EmailAddress = $actionContext.Data.EmailAddress
    $LanguageID = $actionContext.Configuration.LanguageID

    $NavServerInstanceName = $actionContext.Configuration.NavServerInstanceName
    $tenant = $actionContext.Configuration.Tenant
    
    #Make sure module is imported
    Invoke-Command -Session $s -ScriptBlock { $ImportModule = Import-Module "D:\Program Files\Microsoft Dynamics 365 Business Central\Service\NavAdminTool.ps1" -ErrorAction SilentlyContinue }


    <#
    Write-Information "Verifying if a Authorizationbox account for [$($personContext.Person.DisplayName)] exists"
    $correlatedAccount = 'userInfo'
    $outputContext.PreviousData = $correlatedAccount

    # Always compare the account against the current account in target system
    if ($null -ne $correlatedAccount) {
        $splatCompareProperties = @{
            ReferenceObject  = @($correlatedAccount.PSObject.Properties)
            DifferenceObject = @($actionContext.Data.PSObject.Properties)
        }  
        $propertiesChanged = Compare-Object @splatCompareProperties -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
        if ($propertiesChanged) {
            $action = 'UpdateAccount'
            $dryRunMessage = "Account property(s) required to update: $($propertiesChanged.Name -join ', ')"
        } else {
            $action = 'NoChanges'
            $dryRunMessage = 'No changes will be made to the account during enforcement'
        }
    } else {
        $action = 'NotFound'
        $dryRunMessage = "Authorizationbox account for: [$($personContext.Person.DisplayName)] not found. Possibly deleted."
    } #>

    # Compare can be made but Nav handles this
    $action = 'UpdateAccount'

    # Add a message and the result of each of the validations showing what will happen during enforcement
    if ($actionContext.DryRun -eq $true) {
        Write-Information "[DryRun] Would update account"
    }

    # Process
    if (-not($actionContext.DryRun -eq $true)) {
        switch ($action) {
            'UpdateAccount' {
                Write-Information "Updating Authorizationbox account with accountReference: [$($actionContext.References.Account)]"

                # Make sure to test with special characters and if needed; add utf8 encoding.
                Invoke-Command -Session $s -ScriptBlock {$UpdateNavUser = Set-NAVServerUser -ServerInstance $using:NavServerInstanceName -Tenant $using:tenant -WindowsAccount $using:SamAccountName -FullName $using:DisplayName -AuthenticationEmail $using:UserPrincipalName -Company $using:DefaultCompany -LanguageID $using:LanguageID -ContactEmail $using:EmailAddress -ErrorAction Inquire -Verbose -Force}
                break
            }
        }
    }
    
    $outputContext.Data.SecurityID = $($actionContext.References.Account)

    $outputContext.Success = $true
    $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Update account was successful, Account property(s) updated: [$($propertiesChanged.name -join ',')]"
                    IsError = $false
    })


} catch {
    Exit-PSSession
    $outputContext.Success  = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-AuthorizationboxError -ErrorObject $ex
        $auditMessage = "Could not update Authorizationbox account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not update Authorizationbox account. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}
