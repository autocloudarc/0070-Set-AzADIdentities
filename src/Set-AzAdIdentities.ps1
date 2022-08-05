#requires -version 5.1
#requires -RunAsAdministrator
#requires -Module Az


Using Namespace System.Net # For ServicePointmanager Class, ref: https://docs.microsoft.com/en-us/dotnet/api/system.net.servicepointmanager?view=net-5.0
Using Namespace System.Runtime.InteropServices # For Azure AD service principals marshal class

<#
.SYNOPSIS
Provisions Azure AD identities and roles for role based access control to the Azure directory and subscription resources.

.DESCRIPTION
This script creates a set of users and groups within an administrative unit, and applies roles to the new groups based on a consolidated list of identities and roles that are pre-defined in a CSV file.


PRE-REQUISITES:

1. If you already have the Az modules installed, you may still encounter the following error:
    The script 'Set-AzAdIdentities' cannot be run because the following modules that are specified by the "#requires" statements of the script are missing: Az.
    At line:0 char:0
To resolve, please run the following command to import the Az modules into your current session.
Import-Module -Name Az -AllowClobber -Force -Verbose

2. Before executing this script, ensure that you change the directory to the directory where the script is located. For example, if the script 'Set-AzAdIdentities.ps1' is in: c:\scripts\Set-AzAdIdentities.ps1, then
    change to this directory using the following command:
    Set-Location -Path c:\scripts\Set-AzAdIdentities.ps1

.PARAMETER PSModuleRepository
Online module repository for downloading required PowerShell modules.

.PARAMETER label
Header title for script.

.PARAMETER headerCharCount
Horizontal character length of header separators

.PARAMETER pathToIdentitiesFile
This is the relative path (relative to this script), to the file where the consolidated users and groups information is stored.

.PARAMETER azUsers
This is the array of user objects imported from the user information file located at $pathToIdentitiesFile.

.PARAMETER adminUserName
Placehoder username for which the secure password for all the identities that will be provisioned.

.PARAMETER defaultSubId
Used to set/reset placehoder default subscription ID value of: 11111111-1111-1111-1111-111111111111 to protect confidentiality of previous subscription id from a previously executed script.

.PARAMETER reset
Resets the directory to it's original state by removing the provisioned identities and role assignments, and is useful for dev/test scenarios or when developing or enhancing this script.

.PARAMETER adminUnitname
The name of the administrative unit that will be created to contain the new users and groups.

.PARAMETER adminUnitDescription
The description of the administrative unit that will be created to contain the new users and groups.

.EXAMPLE
. .\Set-AzIdentities.ps1 -AzureEnvironment AzureUSGovernment -Verbose
Provisions users and groups into the AzureUSGovernment cloud

.EXAMPLE
. .\Set-AzIdentities.ps1 -Verbose
Provisions users and groups into the [default] AzureCloud (commercial public cloud)

.INPUTS
See PARAMETER pathToIdentitiesFile

.OUTPUTS
The outputs generated from this script includes:
1. A transcript log file to provide the full details of script execution. It will use the name format: <ScriptName>-TRANSCRIPT-<Date-Time>.log

.NOTES

CONTRIBUTORS
1. Preston K. Parsard
2. Robert Lightner

LEGAL DISCLAIMER:
This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment. 
THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. 
We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree:
(i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded;
(ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and
(iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys' fees, that arise or result from the use or distribution of the Sample Code.
This posting is provided "AS IS" with no warranties, and confers no rights.

.LINK
1. https://www.tecklyfe.com/how-to-enable-wsl2-on-windows-10/
2. https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux?view=powershell-7.1
3. https://help.ubuntu.com/
4. https://askubuntu.com/questions/1274028/how-to-install-powershell-7-on-ubuntu-20-04
5. https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux?view=powershell-7#ubuntu-2004
6. https://docs.microsoft.com/en-us/azure/role-based-access-control/role-definitions


.COMPONENT
Azure Infrastructure, PowerShell, AzureAD

.ROLE
Automation Engineer
DevOps Engineer
Azure Engineer
Azure Administrator
Azure Architect

.FUNCTIONALITY
Provisions Azure AD Users, Groups and creates role assignments.

#>

[CmdletBinding()]
Param
(
    [string] $PSModuleRepository = "PSGallery",
    # Title for transcipt header
    [string]$label = "PROVISION AZURE AD IDENTITIES AND ROLES TO AN EXISTING TENANT WITHIN A NEW ADMINISTRATIVE UNIT",
    # Separator width in number of characters for transcript header/footer
    [int]$headerCharCount = 200,
    [string]$pathToIdentitiesFile = ".\input\identities.csv",
    [array]$azUsers = (Import-Csv -path $pathToIdentitiesFile),
    [string]$adminUserName = "adm.azure.user",
    [string]$defaultSubId = "11111111-1111-1111-1111-111111111111",
    [switch]$reset,
    [string]$adminUnitName = "poc-adu-01",
    [string]$adminUnitDescription = "PoC Administrative Unit"
) # end param

$ErrorActionPreference = 'Continue'
# Set-StrictMode -Version Latest

$BeginTimer = Get-Date -Verbose

$PSBoundParameters

$adminUnit = @{
    name = $adminUnitName
    description = $adminUnitDescription
}

Update-Module -Name Az -AllowClobber -Force -Verbose

#region Environment setup
# Use TLS 1.2 to support Nuget provider
Write-Output "Configuring security protocol to use TLS 1.2 for Nuget support when installing modules." -Verbose
[ServicePointManager]::SecurityProtocol = [SecurityProtocolType]::Tls12
#endregion

function Install-BootstrapModules
{
    # Module repository setup and configuration
    Set-PSRepository -Name $PSModuleRepository -InstallationPolicy Trusted -Verbose
    Install-PackageProvider -Name Nuget -ForceBootstrap -Force

    # Bootstrap dependent modules
    $ARMDeployModule = "ARMDeploy"
    if (Get-InstalledModule -Name $ARMDeployModule -ErrorAction SilentlyContinue)
    {
        # If module exists, update it
        [string]$currentVersionADM = (Find-Module -Name $ARMDeployModule -Repository $PSModuleRepository).Version
        [string]$installedVersionADM = (Get-InstalledModule -Name $ARMDeployModule).Version
        If ($currentVersionADM -ne $installedVersionADM)
        {
                # Update modules if required
                Update-Module -Name $ARMDeployModule -Force -ErrorAction SilentlyContinue -Verbose
        } # end if
    } # end if
    # If the modules aren't already loaded, install and import it.
    else
    {
        Install-Module -Name $ARMDeployModule -Repository $PSModuleRepository -Force -Verbose
    } #end If
    Import-Module -Name $ARMDeployModule -Verbose

    # Install updated Az modules
    Install-Module -Name Az -AllowClobber -Verbose
    # Get required PowerShellGallery.com modules.
    Get-ARMDeployPSModule -ModulesToInstall "AzureAD" -PSRepository $PSModuleRepository -Verbose 

} # end function

#region FUNCTIONS
function New-ARMDeployTranscript
{
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LogDirectory,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LogPrefix
    ) # end param

    # Get curent date and time
    $TimeStamp = (get-date -format u).Substring(0, 16)
    $TimeStamp = $TimeStamp.Replace(" ", "-")
    $TimeStamp = $TimeStamp.Replace(":", "")

    # Construct transcript file full path
    $TranscriptFile = "$LogPrefix-TRANSCRIPT" + "-" + $TimeStamp + ".log"
    $script:Transcript = Join-Path -Path $LogDirectory -ChildPath $TranscriptFile

    # Create log and transcript files
    New-Item -Path $Transcript -ItemType File -ErrorAction SilentlyContinue
} # end function

# Validate template function
function Add-AzIdentities
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory)]
        [array]$azUsers,
        [parameter(Mandatory)]
        [PSCredential]$adminCred,
        [parameter(Mandatory)]
        [string]$tenantId,
        [parameter(Mandatory)]
        [string]$subscriptionId,
        [switch]$reset,
        [parameter(Mandatory)]
        [hashtable]$adminUnit
    ) # end param

    # https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-powershell
    $scopeId = "/subscriptions/$subscriptionId"

    # http://get-cmd.com/?p=4949
    Write-Output "Connecting to AzureAD tennant $tenantId"
    Write-Warning "The web based prompt may open in a separate window, so you may have to minimize this window first to see it."
    Connect-AzureAD -TenantId $tenantId -Verbose
    $plainTextPw = $adminCred.GetNetworkCredential().Password
    $securePassword = ConvertTo-SecureString -String $plainTextPw -AsPlainText -Force
    $tenantDomain = ((Get-AzureADTenantDetail).VerifiedDomains | Where-Object {$_._Default -eq 'True'}).Name 
    $waitForSeconds = 20

    # task-item: Create administrative unit if required
    $adu = Get-AzureADMSAdministrativeUnit | Where-Object {$_.displayName -eq $adminUnit.name} 
    if ($null -eq $adu.displayName)
    {
        $adu = New-AzureADMSAdministrativeUnit -Description $adminUnit.description -DisplayName $adminUnit.name -ErrorAction SilentlyContinue -Verbose
    }
    $adminUnitId = $adu.id

    if (-not($reset))
    {
        foreach ($azUser in $azUsers)
        {        
            if ($azUser.rbacType -eq "Custom")
            {
                $rbacTypeCustom = $azUser.rbacType 
                $customRole = $azUser.rbacRole
            } # end if
            else
            {
                $rbacTypeBuiltIn = $azUser.rbacType 
            } # end else
            
            $groupCreated = $false
            # https://docs.microsoft.com/en-us/powershell/module/az.resources/new-azadgroup?view=azps-4.6.1
            do {
                if ($azUser.tenantRole -eq 'false')
                {
                    New-AzADGroup -DisplayName $azUser.aadSecurityGroup -MailNickName (($azUser.aadSecurityGroup).replace(" ","")) -Description $azUser.rbacRole -ErrorAction SilentlyContinue
                }
                else 
                {                   
                    New-AzADGroup -DisplayName $azUser.aadSecurityGroup -MailNickName (($azUser.aadSecurityGroup).replace(" ","")) -Description $azUser.rbacRole -IsAssignableToRole -SecurityEnabled -ErrorAction SilentlyContinue
                }
                $groupObjectId = (Get-AzAdGroup -SearchString $azUser.aadSecurityGroup).Id
                if (-not($null -eq $groupObjectId))
                {
                    $groupCreated = $true
                } # end if  
                Start-Sleep -Seconds $waitForSeconds           
            } until ($groupCreated)
            # task-item: Add group to administrative unit
            Add-AzureADMSAdministrativeUnitMember -Id $adminUnitId -RefObjectId $groupObjectId -Verbose

            $azAdTenantSuffix = "@" + $tenantDomain
            $upn = $azUser.userName + $azAdTenantSuffix
            # https://docs.microsoft.com/en-us/powershell/module/az.resources/new-azaduser?view=azps-4.6.1
            $userCreated = $false
            do {
                $currentUser = New-AzADUser -DisplayName $azUser.displayName -UserPrincipalName $upn -Password $securePassword -MailNickName $azUser.userName -ErrorAction SilentlyContinue
                if (-not($null -eq $currentUser.UserPrincipalName))
                {
                    $userCreated = $true
                } # end if
            } #end Do
            Until ($userCreated)
            [array]$members = (Get-AzADUser -UserPrincipalName $upn).id 

            # task-item: Add user to administrative unit
            Add-AzureADMSAdministrativeUnitMember -Id $adminUnitId -RefObjectId $currentUser.id -ErrorAction SilentlyContinue -Verbose

            # https://docs.microsoft.com/en-us/powershell/module/az.resources/add-azadgroupmember?view=azps-7.0.0
            if ($members.count -gt 0)
            {
                Add-AzADGroupMember -TargetGroupObjectId $groupObjectId -MemberObjectId $members -Verbose 
            }
            if ($azUser.tenantRole -eq 'false')
            {
                if (($azUser.rbacType -eq $rbacTypeCustom) -and ($azUser.rbacRole -eq $customRole))
                {
                    $roleDescription = $azUser.rbacRole + " Assignment"
                    $result = @{}
                    while ($result.count -eq 0)
                    {
                        $result = New-AzRoleAssignment -ObjectId $groupObjectId -RoleDefinitionName $azUser.rbacRole -Scope $scopeId -Description $roleDescription -ErrorAction SilentlyContinue
                        # Wait for $WaitForSeconds seconds
                        Write-Output "Waiting $WaitForSeconds seconds for Role Assignment - $($azUser.rbacRole) at scope: $scopeId..."
                        Start-Sleep -Seconds $WaitForSeconds -Verbose
                    }
                } # end if
                else
                {
                    $roleList = ($azUser.rbacRole).Split(',')
                    foreach ($role in $roleList)
                    {
                        $roleDescr = $role + " Assignment"
                        $result = @{}
                        while ($result.count -eq 0)
                        {
                            $result = New-AzRoleAssignment -ObjectId $groupObjectId -RoleDefinitionName $role -Scope $scopeId -Description $roleDescr -ErrorAction SilentlyContinue
                            # Wait for $WaitForSeconds seconds
                            Write-Output "Waiting $WaitForSeconds seconds for Role Assignment - $role at $scopeId..."
                            Start-Sleep -Seconds $WaitForSeconds -Verbose
                        }
                    } # end foreach
                } # end else
            } # end if
            else
            {
                $rbacRole = $azUser.rbacRole
                $roleId = (Get-AzureADMSRoleDefinition | Where-Object {$_.DisplayName -match $rbacRole}).id
                New-AzureADMSRoleAssignment -RoleDefinitionId $roleId -PrincipalId $groupObjectId -DirectoryScopeId '/' -ErrorAction SilentlyContinue -Verbose
            }
        } # end foreach
    } # end if
    else
    {
        foreach ($azUserReset in $azUsers)
        {
            $upn = $azUserReset.userName + "@" + $tenantDomain
            $groupObjectId = (Get-AzADGroup -DisplayName $azUserReset.aadSecurityGroup).id
            if ($azUserReset.rbacType -eq "Custom")
            {
                $customRoleId = (Get-AzRoleDefinition -Name $azUserReset.rbacRole).id
                do {
                    Remove-AzRoleAssignment -ObjectId $groupObjectId -RoleDefinitionName $azUserReset.rbacRole -PassThru -Confirm:$false -Verbose
                    Remove-AzRoleDefinition -Id $customRoleId -Force -Confirm:$false -PassThru -Verbose -ErrorAction SilentlyContinue
                    Write-Output "Waiting to completely remove custom role definition $($azUserReset.rbacRole)..."
                    Start-Sleep -Seconds 10 
                    $currentCustomRoleDefId = (Get-AzRoleDefinition -Name $azUserReset.rbacRole).id 
                } until ($null -eq $currentCustomRoleDefId)
            }
            $resetRoleList = ($azUserReset.rbacRole).Split(',')
            foreach ($resetRole in $resetRoleList)
            {
                if ($azUserReset.tenantRole)
                {
                    $scope = '/'
                }
                else 
                {
                    $scope = $scopeId
                }
                Remove-AzRoleAssignment -ObjectId $groupObjectId -RoleDefinitionName $resetRole -Scope $scope -PassThru -ErrorAction SilentlyContinue -Verbose
            }
            # https://docs.microsoft.com/en-us/powershell/module/az.resources/remove-azadgroup?view=azps-4.6.1
            Remove-AzADGroup -DisplayName $azUserReset.aadSecurityGroup -Verbose
            # https://docs.microsoft.com/en-us/powershell/module/az.resources/remove-azaduser?view=azps-4.6.1
            Remove-AzADUser -UserPrincipalName $upn -PassThru -Verbose
        } # end foreach
        # Removes the custom role definition from the subscription as part of cleanup.
        # Remove Administrative Unit
        Remove-AzureADMSAdministrativeUnit -Id $adminUnitId -Verbose
        # Write-Output "You must manually remove any role assignments for the $customRole as well as remove this custom role $customRole manually from the Azure Portal at https://portal.azure.com"
    } # end else
} # end function

# Ask to update Az modules
$updateAzModulesPrompt = "Would you like to update your Az modules to the latest versions? [YES/NO or [Y/N]]"
Do
{
    $updateAzModulesResponse = read-host $updateAzModulesPrompt
    $updateAzModulesResponse = $updateAzModulesResponse.ToUpper()
} # end do
Until ($updateAzModulesResponse -eq "Y" -OR $updateAzModulesResponse -eq "YES" -OR $updateAzModulesResponse -eq "N" -OR $updateAzModulesResponse -eq "NO")

# Exit if user does not want to continue
If ($openTranscriptResponse -in 'Y', 'YES')
{
    Update-Module -Name Az -Force -AllowClobber -Verbose
} #end condition

#endregion FUNCTIONS

### This PowerShell Script creates PoC Environment based on JSON Templates

#region INITIALIZE VALUES
# Create Log file
[string]$Transcript = $null

#region TRANSCRIPT
$scriptName = $MyInvocation.MyCommand.name
# Use script filename without exension as a log prefix
$LogPrefix = $scriptName.Split(".")[0]
# Uncomment below if this script is converted to use PowerShell core (v7.x)
if ($isWindows)
{
    $modulePath = "C:\Program Files\WindowsPowerShell\Modules"
} # end if
else
{
    $modulePath = "/usr/local/share/powershell/Modules"
} # end else if

$LogDirectory = Join-Path $modulePath -ChildPath $LogPrefix -Verbose
# Create log directory if not already present
If (-not(Test-Path -Path $LogDirectory -ErrorAction SilentlyContinue))
{
    New-Item -Path $LogDirectory -ItemType Directory -Verbose
} # end if

# funciton: Create log files for transcript
New-ARMDeployTranscript -LogDirectory $LogDirectory -LogPrefix $LogPrefix -Verbose

Start-Transcript -Path $Transcript -IncludeInvocationHeader -Verbose
#endregion TRANSCRIPT

# function: Create new header
$header = New-ARMDeployHeader -label $label -charCount $headerCharCount -Verbose

#endregion INITIALIZE VALUES

Write-Output $header.SeparatorDouble -Verbose
Write-Output $Header.Title -Verbose
Write-Output $header.SeparatorSingle -Verbose

# Set script path
Write-Output "Changing path to script directory..." -Verbose
Set-Location -Path $PSScriptRoot -Verbose
Write-Output "Current directory has been changed to script root: $PSScriptRoot" -Verbose

#region authenticate to subscription
Write-Output "Please see the open dialogue box in your browser to authenticate to your Azure subscription..."

# Clear any possible cached credentials for other subscriptions
Clear-AzContext -PassThru -Force -Verbose

Connect-AzAccount -Environment AzureCloud

# https://docs.microsoft.com/en-us/azure/azure-government/documentation-government-get-started-connect-with-ps
# To connect to AzureUSGovernment, use:
# Connect-AzAccount -EnvironmentName AzureUSGovernment
Do
{
    (Get-AzSubscription).Name
	[string]$Subscription = Read-Host "Please enter your subscription name, i.e. [MySubscriptionName] "
	$Subscription = $Subscription.ToUpper()
} #end Do
Until ($Subscription -in (Get-AzSubscription).Name)
Select-AzSubscription -SubscriptionName $Subscription -Verbose
$subscriptionId = (Select-AzSubscription -SubscriptionName $Subscription).Subscription.id
$tenantId = (Get-AzSubscription -SubscriptionName $Subscription).TenantId

#endregion

#region Credentials: This will use a single automatically generated, but unknown password for all users that will be provisioned, but can be changed from the portal afterwards if necessary. 
$clrStringPw = New-ARMDeployRandomPassword -IncludeUpper -IncludeLower -IncludeNumbers -IncludeSpecial
$secStringPw = ConvertTo-SecureString -String $clrStringPw -AsPlainText -Force
# Reset clear-text password to null for confidentiality
$clrStringPw = $null 

[System.Management.Automation.PSCredential]$adminCred = New-Object System.Management.Automation.PSCredential ($adminUserName,$secStringPw)
<#
$adminCred = Get-Credential -UserName $adminUserName -Message @"    
Please specify a single, initial password for all Azure AD users that will be provisioned.
This password must be complex, at least 12 characters including 3 of the following: lowercase, uppercase, numbers and special characters.
"@
#>
#endregion credentials

#region Add custom role
# https://docs.microsoft.com/en-us/azure/role-based-access-control/custom-roles-powershell

if (-not($reset))
{
    $customRolePath = ".\input\roleCustom-AdatumVmOperator.json"
    $subIdPattern = '\w{8}-\w{4}-\w{4}-\w{4}-\w{12}'
    $customRoleContent = Get-Content -Path $customRolePath
    ($customRoleContent -match $subIdPattern)[0] -match $subIdPattern
    $currentSubId = $matches[0]
    $initializedRoleContent = $customRoleContent.Replace($currentSubId,$defaultSubId)

    $targetSubId = $subscriptionId
    Write-Output "The custom role definition that will be added to the subscription is shown below"
    $initializedRoleContent
    Write-Output "Now we will update the default place-holder subscription id of $defaultSubId with your current subscription id of: $targetSubId"

    # Replace the default subscription id with the current subscription id
    $updatedRoleContent = $initializedRoleContent.Replace($defaultSubId,$targetSubId)

    # Write the updated role definition back out to the file system
    $updatedRoleContent | Out-File -FilePath $customRolePath -Force

    # Import the updated role definition to the current subscription
    New-AzRoleDefinition -InputFile $customRolePath -Verbose
    # Write the initialized role definition back out to the file system
    $initializedRoleContent | Out-File -FilePath $customRolePath -Force
    $customRoleObject = $initializedRoleContent | ConvertFrom-Json
    # Wait for 100 seconds to allow sufficient time for role to provision in Azure AD
    $s = 0
    $message = "Waiting to allow the custom $($customRoleObject.name) role to provision in Azure AD."
    $customRoleName = $customRoleObject.name 
    do {
        Start-Sleep -Seconds 5
        $s++
        $today = Get-Date
        "{0}`t{1}" -f @($today, $message)
    } until (((Get-AzRoleDefinition -Name $customRoleName).name) -eq ($customRoleName) -and ($s -eq 12))
#endregion

    # Create AD Users, Groups and Roles
    # https://docs.microsoft.com/en-us/powershell/module/azuread/new-azureadgroup?view=azureadps-2.0
    # https://docs.microsoft.com/en-us/powershell/module/azuread/new-azureaduser?view=azureadps-2.0

    Add-AzIdentities -azUsers $azUsers -adminCred $adminCred -tenantId $tenantId -subscriptionId $subscriptionId -adminUnit $adminUnit -Verbose
}
else 
{
    Write-Warning "Removing previously provisioned users and groups from Azure AD tenant $tenantId."
    Add-AzIdentities -azUsers $azUsers -adminCred $adminCred -tenantId $tenantId -subscriptionId $subscriptionId -reset -adminUnit $adminUnit -Verbose
}

$StopTimerWoFw = Get-Date -Verbose
Write-Output "Calculating elapsed time..."
$ExecutionTimeWoFw = New-TimeSpan -Start $BeginTimer -End $StopTimerWoFw
$FooterWoFw = "TOTAL SCRIPT EXECUTION TIME: $ExecutionTimeWoFW"
Write-Output ""
Write-Output $FooterWoFw

Write-Warning "Transcript logs are hosted in the directory: $LogDirectory to allow access for multiple users on this machine for diagnostic or auditing purposes."
Write-Warning "To examine, archive or remove old log files to recover storage space, run this command to open the log files location: Start-Process -FilePath $LogDirectory"
Write-Warning "You may change the value of the `$modulePath variable in this script, currently at: $modulePath to a common file server hosted share if you prefer, i.e. \\<server.domain.com>\<share>\<log-directory>"
Stop-Transcript -Verbose

# Create prompt and response objects for continuing script and opening logs.
$openTranscriptPrompt = "Would you like to open the transcript log now ? [YES/NO]"
Do
{
    $openTranscriptResponse = read-host $openTranscriptPrompt
    $openTranscriptResponse = $openTranscriptResponse.ToUpper()
} # end do
Until ($openTranscriptResponse -eq "Y" -OR $openTranscriptResponse -eq "YES" -OR $openTranscriptResponse -eq "N" -OR $openTranscriptResponse -eq "NO")

# Exit if user does not want to continue
If ($openTranscriptResponse -in 'Y', 'YES')
{
    Start-Process -FilePath notepad.exe $Transcript -Verbose
} #end condition
else
{
    # Terminate script
    Write-Output "End of Script!"
    $header.SeparatorDouble
} # end else