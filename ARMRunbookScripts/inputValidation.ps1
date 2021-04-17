<#

.DESCRIPTION
This script is ran by the inputValidationRunbook and validates the following:
 * Azure admin credentials and owner & company administrator role
 * In case of using Azure AD DS, the domain join credentials
 * If the required resource providers are registered (and if not, the script registers them)
 * If the VNet and the SubNet can be found
 * If the firewall allows the required URLs to be accessed
Additionally, this script assigns the subscription Contributor role to the WVDServicePrincipal MSI

#>

#Initializing variables from automation account
$SubscriptionId = Get-AutomationVariable -Name 'subscriptionid'
$ResourceGroupName = Get-AutomationVariable -Name 'ResourceGroupName'
$fileURI = Get-AutomationVariable -Name 'fileURI'
$existingVnetName = Get-AutomationVariable -Name 'existingVnetName'
$existingSubnetName = Get-AutomationVariable -Name 'existingSubnetName'
$identityApproach = Get-AutomationVariable -Name 'identityApproach'

# Download files required for this script from github ARMRunbookScripts/static folder
$FileNames = "msft-wvd-saas-api.zip,msft-wvd-saas-web.zip,AzureModules.zip"
$SplitFilenames = $FileNames.split(",")
foreach($Filename in $SplitFilenames){
Invoke-WebRequest -Uri "$fileURI/ARMRunbookScripts/static/$Filename" -OutFile "C:\$Filename"
}

#New-Item -Path "C:\msft-wvd-saas-offering" -ItemType directory -Force -ErrorAction SilentlyContinue
Expand-Archive "C:\AzureModules.zip" -DestinationPath 'C:\Modules\Global' -ErrorAction SilentlyContinue

# Install required Az modules and AzureAD
Import-Module Az.Accounts -Global
Import-Module Az.Resources -Global
Import-Module Az.Websites -Global
Import-Module Az.Automation -Global
Import-Module Az.Managedserviceidentity -Global
Import-Module Az.Keyvault -Global
Import-Module Az.Network -Global
Import-Module AzureAD -Global

Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope Process -Force -Confirm:$false
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force -Confirm:$false
Get-ExecutionPolicy -List

# Region check Azure AD DS credentials and membership of AAD DC administrators group
if ($identityApproach -eq 'Azure AD DS') {
	#The name of the Automation Credential Asset this runbook will use to authenticate to Azure.
	$domainCredentialsAsset = 'domainJoinCredentials'

	#Authenticate Azure
	#Get the credential with the above name from the Automation Asset store
	$domainCredentials = Get-AutomationPSCredential -Name $domainCredentialsAsset

	Write-Output "Azure AD DS is used, attempting Connect-AzureAD with the domain join credentials entered"
	Try { 
		Connect-AzureAD -Credential $domainCredentials
	}
	Catch {
		Write-Error "Invalid domain join username or password entered - Connecting to Azure AD failed."
		Throw "Invalid domain join username or password entered - Connecting to Azure AD failed."
	}

	$GroupObject = Get-AzureADGroup -Filter "DisplayName eq 'AAD DC Administrators'"  | Select-Object -First 1
	$groupMember = Get-AzureADGroupMember -ObjectId $GroupObject.ObjectId | Where-Object {$_.UserPrincipalName -eq $domainCredentials.username}
	if ($null -eq $groupMember) {
		Write-Error "Entered domain join credentials correspond to a user that is not a member of the AAD DC Administrators group."
		Throw "Entered domain join credentials correspond to a user that is not a member of the AAD DC Administrators group."
	}
	Disconnect-AzureAD
	Write-Output "Domain join user is a member of AAD DC administrators and the entered credentials are correct."
}
#endregion

#The name of the Automation Credential Asset this runbook will use to authenticate to Azure.
$AzCredentialsAsset = 'AzureCredentials'

#Authenticate Azure
#Get the credential with the above name from the Automation Asset store
$AzCredentials = Get-AutomationPSCredential -Name $AzCredentialsAsset
$AzCredentials.password.MakeReadOnly()
Connect-AzAccount -Environment 'AzureCloud' -Credential $AzCredentials
Select-AzSubscription -SubscriptionId $SubscriptionId

$context = Get-AzContext
if ($null -eq $context)
{
	Write-Error "Please authenticate to Azure & Azure AD using Login-AzAccount and Connect-AzureAD cmdlets and then run this script"
	throw "Please authenticate to Azure & Azure AD using Login-AzAccount and Connect-AzureAD cmdlets and then run this script"
}
$AADUsername = $context.Account.Id

#region connect to Azure and check if Owner
Write-Output "Try to connect AzureAD."
Connect-AzureAD -Credential $AzCredentials

Write-Output "Connected to AzureAD."

# get user object 
$userInAzureAD = Get-AzureADUser -Filter "UserPrincipalName eq `'$AADUsername`'"

$isOwner = Get-AzRoleAssignment -ObjectID $userInAzureAD.ObjectId | Where-Object { $_.RoleDefinitionId -eq "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"}

if ($null -ne $isOwner) {
	Write-Output $($AADUsername + " has Owner role assigned")        
} 
else {
	Write-Output $($AADUsername + " does not have 'Owner' role assigned")
}
#endregion

#region connect to Azure and check if admin on Azure AD 
# this depends on the previous segment completeing 
$role = Get-AzureADDirectoryRole | Where-Object {$_.roleTemplateId -eq '62e90394-69f5-4237-9190-012177145e10'}
$isMember = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId | Where-Object { $_.ObjectId -eq $userInAzureAD.ObjectId }

if ($null -ne $isMember) {
	Write-Output $($AADUsername + " has " + $role.DisplayName + " role assigned")        
} 
else {
	Write-Output $($AADUsername + " does not have 'Global Administrator' role assigned")
}
#endregion

#region check Microsoft.DesktopVirtualization resource provider has been registerred
Write-Output "Checking if required resource providers are installed..."
$wvdResourceProviderNames = "Microsoft.DesktopVirtualization","microsoft.visualstudio"
foreach ($resourceProvider in $wvdResourceProviderNames) {
	$states = (Get-AzResourceProvider -ProviderNamespace $resourceProvider).RegistrationState
	if ($states -contains 'NotRegistered' -or $states -contains 'Unregistered') {
		Write-Output "Resource provider '$resourceProvider' not registered. Registering" -Verbose
		Register-AzResourceProvider -ProviderNamespace $resourceProvider
	}
	else {
		Write-Output "Resource provider '$resourceProvider' already registered" -Verbose
	}
}
#endregion

#region check VNET
Write-Output "Validating vNet and subnet..."
$VNET = Get-AzVirtualNetwork -name $existingVnetName
if(  $null -ne $VNET ) {
	Write-Output $("Found the VNET " + $VNET.Name + " with profixes " + $VNET.AddressSpace.AddressPrefixes)   

	If (($VNET.Subnets).Name -contains $existingSubnetName) {
		Write-Output $("Found the subnet " + $existingSubnetName)   
	}
	else {
		Write-Output $("Did not find the VNET " + $existingVnetName + " with subnet " + $existingSubnetName)     
		throw  $("Did not find the VNET " + $existingVnetName + " with subnet " + $existingSubnetName)
	}
}
#endregion

#region check firewall
Write-Output ('Veryfing firewall allows connection to reguired URLs...')

$safeUrls = "rdbroker.wvdselfhost.microsoft.com","prod.warmpath.msftcloudes.com","catalogartifact.azureedge.net","wvdportalstorageblob.blob.core.windows.net","login.windows.net","catalogartifact.azureedge.net","www.msftconnecttest.com","settings-win.data.microsoft.com","fs.microsoft.com","slscr.update.microsoft.com","production.diagnostics.monitoring.core.windows.net","production.billing.monitoring.core.windows.net","production.diagnostics.monitoring.core.windows.net","firstparty.monitoring.windows.net","monitoring.windows.net"

foreach($url in $safeUrls) {
    $var = test-netconnection $url -port 443

    if ($var.TcpTestSucceeded) {
    Write-Output "$url is reachable on port 443."
    } 
    else {
        Write-Output "$url cannot be reached on por 443."   
        Throw "$url cannot be reached on por 443."   
    }    
}

$url = "kms.core.windows.net"
$var = test-netconnection $url -port 1688
if ($var.TcpTestSucceeded) {
	Write-Output "$url is reachable on port 1688."
} 
else {
    Write-Output "$url cannot be reached on port 1688."
	Throw "$url cannot be reached on port 1688."
}

Write-Output ('End verification.')
#endregion

# Grant WVDServicePrincipal managed identity contributor role on subscription level
$identity = Get-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name "WVDServicePrincipal"
if ($null -eq $identity) {
	Write-Output $($ResourceGroupName + " does not contains WVDServicePrincipal.")
	throw $($ResourceGroupName + " does not contains WVDServicePrincipal.")
}

$isContributor = Get-AzRoleAssignment -ObjectID $identity.PrincipalId | Where-Object { $_.RoleDefinitionId -eq "b24988ac-6180-42a0-ab88-20f7382dd24c"}

if ($null -ne $isContributor) {
	Write-Output "WVDServicePrincipal has Contributor role assigned"     
} 
else {
	New-AzRoleAssignment -RoleDefinitionId "b24988ac-6180-42a0-ab88-20f7382dd24c" -ObjectId $identity.PrincipalId -Scope "/subscriptions/$subscriptionId"
	Write-Output "WVDServicePrincipal has been assigned Contributor role"
	Start-Sleep -Seconds 10
}
