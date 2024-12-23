<#
####  Script: CheckDFSOnboarding.ps1
####  Description: 1) reads Azure/Def for Servers inventory 2) reads servers from Def for Endpoint
####      3) Compares the list to generate combined list and orphans lists 4) Generate HTML Output file 
####  Requirements: 
####      MDE: Permission to create and delete App Registrations and apply permissions in EntraID
####      DFS/Azure: Reader permission to Azure subscription(s)/Resource Group(s) for VMs, Scale Sets, and Arc Machines
####      Local: Rights to install PowerShell and/or PowerShell modules and libraries
#############################################################################################################
#>
$failureCount = 0
$vmResponseMachines = $null
$vmssResponseMachines = $null
$arcResponseMachines = $null
$DFSServers = @()
#-------------------
$appId = '' 
$ClientId = ''
$appSecret = ''
$MDEServers = @()

## Importing requried libraries to assure they are installed
try {
	#------------ Required Azure libraries ----------------
	Import-Module az.accounts
	Import-Module Az.Resources
	#------------ Required MS Graph libraries ----------------
	Import-Module Microsoft.Graph.Applications
	Import-Module Microsoft.Graph.Authentication
	Import-Module Microsoft.Graph.Identity.DirectoryManagement
}
catch {
	<#Do this if a terminating exception happens#>
	write-host "Please assure that the following modules are installed:"
	Write-Host "Error from response:" $_.ErrorDetails -ForegroundColor Red
	throw
}

# login:
$needLogin = $true
Try {
	$context = Get-AzContext #Az.Accounts module
	if ($context)
	{
		$needLogin = ([string]::IsNullOrEmpty($content.Account))
	}
}
Catch
{
	if ($_ -like "*Login-AzAccount to login*")
	{
		$needLogin = $true
	}
	else
	{
		throw
	}
}

if ($needLogin)
{
	Write-Host -ForegroundColor "yellow" "Need to log in now! Look for login window!"
	Connect-Azaccount 3> $null #Az.Accounts module
}
# login - end

# get token
### NEED: Convert to SecureString ###
$accessToken = Get-AzAccessToken | Select-Object -ExpandProperty token #Az.Accounts
#$expireson = Get-AzAccessToken | Select-Object -ExpandProperty expireson | Select-Object -ExpandProperty LocalDateTime

If (!($accessToken.Length -gt 0)){
	#Exit
	write-host "Unable to acquire Access Tokent. Exiting."
	exit 1
}

try {
	
	# Need Az.Accounts library for this
	$Subscriptions = get-azsubscription

}
catch {
	<#Do this if a terminating exception happens#>
	if (!($context)) {$context = Get-AzContext}
	$Subscriptions = $context.Subscription
	else {
		write-host "Unable to find an Azure Subscription with the signed-in account."
		Write-Host "Error from response:" $_.ErrorDetails -ForegroundColor Red
		throw
	}
}

Clear-Host

$Subscriptions | ForEach-Object {

$SubscriptionId = $_.Id

## Need Try/Catch
## Need the AzResources Library for this
$ResourceGroups = get-azResourceGroup #Az.Resources module

$ResourceGroups | ForEach-Object {

	$resourceGroupName = $_.ResourceGroupName
	write-host Subscription: $SubscriptionId - ResourceGroup: $resourceGroupName

	try
	{
		# Get all virtual machines, VMSSs, and ARC machines in the resource group
		$vmUrl = "https://management.azure.com/subscriptions/" + $SubscriptionId + "/resourceGroups/$resourceGroupName/providers/Microsoft.Compute/virtualMachines?api-version=2021-04-01"
		do{
			$vmResponse = Invoke-RestMethod -Method Get -Uri $vmUrl -Headers @{Authorization = "Bearer $accessToken"}
			$vmResponseMachines += $vmResponse.value 
			$vmUrl = $vmResponse.nextLink
		} while (![string]::IsNullOrEmpty($vmUrl))

		$vmssUrl = "https://management.azure.com/subscriptions/" + $SubscriptionId + "/resourceGroups/$resourceGroupName/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2021-04-01"
		do{
			$vmssResponse = Invoke-RestMethod -Method Get -Uri $vmssUrl -Headers @{Authorization = "Bearer $accessToken"}
			$vmssResponseMachines += $vmssResponse.value
			$vmssUrl = $vmssResponse.nextLink
		} while (![string]::IsNullOrEmpty($vmssUrl))
		
		$arcUrl = "https://management.azure.com/subscriptions/" + $SubscriptionId + "/resourceGroups/$resourceGroupName/providers/Microsoft.HybridCompute/machines?api-version=2022-12-27"
		do{
			$arcResponse = Invoke-RestMethod -Method Get -Uri $arcUrl -Headers @{Authorization = "Bearer $accessToken"}
			$arcResponseMachines += $arcResponse.value
			#write-host $arcUrl
			$arcUrl = $arcResponse.nextLink
		} while (![string]::IsNullOrEmpty($arcUrl))
	}
	catch 
	{
		Write-Host "Failed to Get resources! " -ForegroundColor Red
		Write-Host "Response StatusCode:" $_.Exception.Response.StatusCode.value__  -ForegroundColor Red
		Write-Host "Response StatusDescription:" $_.Exception.Response.StatusDescription -ForegroundColor Red
		Write-Host "Error from response:" $_.ErrorDetails -ForegroundColor Red
	}

} ## End of For Each ResGroup
########################################################################################
############# Finished fetching machines from Azure Inventory  #########################
########################################################################################
#Clear-Host

# Loop through each machine and update the pricing configuration
Write-Host "-------------------"
Write-Host "Processing Defender For Servers info Virtual Machines:"

########## Processing Azure VMs ############################################

foreach ($machine in $vmResponseMachines) {
	
	<#
	# Check if need to renew the token	
    $currentTime = Get-Date

    if ((get-date $currentTime) -ge (get-date $expireson)) {
		Write-host "Token expires on: $expireson - currentTime: $currentTime"
		Start-Sleep -Seconds 2
        Write-host "Token expired - refreshing token:"
        $accessToken = Get-AzAccessToken | Select-Object -ExpandProperty token | Out-Null
        $expireson = Get-AzAccessToken | Select-Object -ExpandProperty expireson | Out-Null | Select-Object -ExpandProperty LocalDateTime
    }
	#>

    $pricingUrl = "https://management.azure.com$($machine.id)/providers/Microsoft.Security/pricings/virtualMachines?api-version=2024-01-01"

	Write-Host "Processing (setting or reading) pricing configuration for VM '$($machine.name)':"

	try {
		
    $pricingResponse = Invoke-RestMethod -Method Get -Uri $pricingUrl -Headers @{Authorization = "Bearer $accessToken"} -ContentType "application/json" -TimeoutSec 120
    # Write-Host "Successfully read pricing configuration for $($machine.name): " -ForegroundColor Green
	
	if ($pricingResponse.properties.pricingTier -eq "Standard"){
		$Thiscomputer = [pscustomobject]@{
			Name = $machine.name
			DFSGUID = $machine.identity.principalID
			MachineID = $machine.properties.vmid
			OSFamily = $machine.properties.storageProfile.imageReference.sku
			Sub = $SubscriptionId
			RG = ''
			DSLocation = $machine.location
			PriceTier = $pricingResponse.properties.pricingTier
			SubPlan = $pricingResponse.properties.subPlan
			EnrEnabled = "No"
		}
		
		$SubscrEnrollStatus = $pricingResponse.properties.extensions | Where-Object {$_.name -eq "MdeDesignatedSubscription"} | select isEnabled
		if ($SubscrEnrollStatus.isEnabled){$Thiscomputer.EnrEnabled = "Yes"}
		
		if ($machine.id -match "/resourceGroups/([^/]+)/") {$Thiscomputer.RG = $matches[1]}

		$DFSServers += $Thiscomputer
	} # end of if it's a standard billing sku
	}
	catch {
		$failureCount++
		Write-Host "Failed to get pricing configuration for VM $($machine.name)" -ForegroundColor Red
		Write-Host "Response StatusCode:" $_.Exception.Response.StatusCode.value__  -ForegroundColor Red
		Write-Host "Response StatusDescription:" $_.Exception.Response.StatusDescription -ForegroundColor Red
		Write-Host "Error from response:" $_.ErrorDetails -ForegroundColor Red
	}

	Start-Sleep -Seconds 0.3
} # End of the For-each machine loop - VMs


################# Processing Scale Sets #############################################

Write-Host "Processing Defender For Server Info for Virtual Machine Scale Sets:"
foreach ($machine in $vmssResponseMachines) {
	# Check if need to renew the token
    #$currentTime = Get-Date
    
	<#
    if ((get-date $currentTime) -ge (get-date $expireson)) {
		Write-host "Token expires on: $expireson - currentTime: $currentTime"
		Start-Sleep -Seconds 2
        Write-host "Token expired - refreshing token:"
        $accessToken = Get-AzAccessToken | Select-Object -ExpandProperty token | Out-Null
        $expireson = Get-AzAccessToken | Select-Object -ExpandProperty expireson | Out-Null | Select-Object -ExpandProperty LocalDateTime
    }
	#>

    $pricingUrl = "https://management.azure.com$($machine.id)/providers/Microsoft.Security/pricings/virtualMachines?api-version=2024-01-01"

	Write-Host "Processing (setting or reading) pricing configuration for SS device '$($machine.name)':"
	try 
	{
        
        $pricingResponse = Invoke-RestMethod -Method Get -Uri $pricingUrl -Headers @{Authorization = "Bearer $accessToken"} -ContentType "application/json" -TimeoutSec 120
        #Write-Host "Successfully read pricing configuration for $($machine.name): " -ForegroundColor Green
        #Write-Host ($pricingResponse | ConvertTo-Json -Depth 100)
		### This section requires testing - 241220 DPK
		
		if ($pricingResponse.properties.pricingTier -eq "Standard"){
			$Thiscomputer = [pscustomobject]@{
				Name = $machine.name
				DFSGUID = $machine.identity.principalID
				MachineID = $machine.properties.vmid
				OSFamily = $machine.properties.storageProfile.imageReference.sku
				Sub = $SubscriptionId
				RG = ''
				DSLocation = $machine.location
				PriceTier = $pricingResponse.properties.pricingTier
				SubPlan = $pricingResponse.properties.subPlan
				EnrEnabled = "No"
			}
			
		$SubscrEnrollStatus = $pricingResponse.properties.extensions | Where-Object {$_.name -eq "MdeDesignatedSubscription"} | select isEnabled
		if ($SubscrEnrollStatus.isEnabled){$Thiscomputer.EnrEnabled = "Yes"}

		if ($machine.id -match "/resourceGroups/([^/]+)/") {$Thiscomputer.RG = $matches[1]}
	
		$DFSServers += $Thiscomputer
		} # end of if standard sku
        
	}
	catch {
		$failureCount++
		Write-Host "Failed to get pricing configuration for SS device $($machine.name)" -ForegroundColor Red
		Write-Host "Response StatusCode:" $_.Exception.Response.StatusCode.value__  -ForegroundColor Red
		Write-Host "Response StatusDescription:" $_.Exception.Response.StatusDescription -ForegroundColor Red
		Write-Host "Error from response:" $_.ErrorDetails -ForegroundColor Red
	}

	Start-Sleep -Seconds 0.3
}

###################### Processing Arc Machines###############################################

Write-Host "Processing Defender For Server Info for ARC Machines:"
foreach ($machine in $arcResponseMachines) {
	# Check if need to renew the token
    #$currentTime = Get-Date
    
	<#
    if ((get-date $currentTime) -ge (get-date $expireson)) {
		Write-host "Token expires on: $expireson - currentTime: $currentTime"
		Start-Sleep -Seconds 2
        Write-host "Token expired - refreshing token:"
        $accessToken = Get-AzAccessToken | Select-Object -ExpandProperty token | Out-Null
        $expireson = Get-AzAccessToken | Select-Object -ExpandProperty expireson | Out-Null | Select-Object -ExpandProperty LocalDateTime

    }
	#>

    $pricingUrl = "https://management.azure.com$($machine.id)/providers/Microsoft.Security/pricings/virtualMachines?api-version=2024-01-01"

	Write-Host "Processing (setting or reading) pricing configuration for Arc device '$($machine.name)':"
	try 
	{
        $pricingResponse = Invoke-RestMethod -Method Get -Uri $pricingUrl -Headers @{Authorization = "Bearer $accessToken"} -ContentType "application/json" -TimeoutSec 120
        # Write-Host "Successfully read pricing configuration for $($machine.name): " -ForegroundColor Green

		if ($pricingResponse.properties.pricingTier -eq "Standard"){
			$Thiscomputer = [pscustomobject]@{
				Name = $machine.name
				DFSGUID = $machine.identity.principalID
				MachineID = $machine.properties.vmid
				OSFamily = $machine.properties.storageProfile.imageReference.sku
				Sub = $SubscriptionId
				RG = ''
				DSLocation = $machine.location
				PriceTier = $pricingResponse.properties.pricingTier
				SubPlan = $pricingResponse.properties.subPlan
				EnrEnabled = "No"
			}
			
			$SubscrEnrollStatus = $pricingResponse.properties.extensions | Where-Object {$_.name -eq "MdeDesignatedSubscription"} | select isEnabled
			if ($SubscrEnrollStatus.isEnabled){$Thiscomputer.EnrEnabled = "Yes"}
	
			if ($machine.id -match "/resourceGroups/([^/]+)/") {$Thiscomputer.RG = $matches[1]}
	
			$DFSServers += $Thiscomputer
		} # end of if it's a standard billing sku
	}
	catch {
		$failureCount++
		Write-Host "Failed to get pricing configuration for ARC Device $($machine.name)" -ForegroundColor Red
		Write-Host "Response StatusCode:" $_.Exception.Response.StatusCode.value__  -ForegroundColor Red
		Write-Host "Response StatusDescription:" $_.Exception.Response.StatusDescription -ForegroundColor Red
		Write-Host "Error from response:" $_.ErrorDetails -ForegroundColor Red
	}

	Start-Sleep -Seconds 0.3
}


} ## End of For Each subscription

Write-Host "------------------ DFS Processing Complete -------------------"

################################################################################################
################## Getting List of MDE Machines ################################################

## Get list of MDE Servers
# Note: Need to account for AppID and ClientID as separate items
# AppID is used to call up the a registered app to make changes
# ClientID is used to get a token using the secret
# In the portal these get called by different names

try {
	#
	# Import-module Microsoft.Graph
	Connect-MgGraph -Scopes "Application.ReadWrite.All","AppRoleAssignment.ReadWrite.All","Organization.Read.All" -NoWelcome
}
catch {
	
	write-host "Failed to get connection to the Graph API"
	Write-Host "Error from response:" $_.ErrorDetails -ForegroundColor Red
	throw
}

# Get the TenantID
$tenantId = ((Get-MgOrganization).Id)
# Check to see if there is an app registered already
$MDERegApp = Get-MgApplication | Where-Object {$_.DisplayName -eq "ReadMDEDevices"}

#if not, register a new app to have read access to MDE devices list
if (!($MDERegApp)) {
    $MDERegApp = New-MgApplication -DisplayName "ReadMDEDevices" -IdentifierUris @("ReadMDEDevices")
    $appId = $MDERegApp.Id
    $ClientId = $MDERegApp.AppID

    ## Create a new app secret
    $newSecret = @{
        DisplayName   = "ReadMDEDevicesSecret"
        StartDateTime = (Get-Date).ToString("o")
        EndDateTime   = (Get-Date).AddYears(1).ToString("o")
    }

	for ($i = 0; $i -lt 3; $i++) {
		$updatedApp = Add-MgApplicationPassword -ApplicationId $appId -PasswordCredential $newSecret
    	$appSecret = $updatedApp.SecretText

		if ($appSecret.Length -gt 0){break}
		if ($i -eq 2){
			Write-Host "No App Secret after 3 tries - Delete App Reg and try again later."
			Write-Host "- Exiting"
			exit
		}
	}

    # Delegate app permission to Defender XDR
    # Create a service principal
    $sp = New-MgServicePrincipal -AppId $ClientID

    # Get the permission to be set
    $permission = Get-MgServicePrincipal -Filter "displayName eq 'WindowsDefenderATP'"
    $AppRole = $permission.approles | Where-Object {$_.Value -eq "Machine.Read.All"}

    # Assign the permission to the app
    #$appRoleAssignment = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ResourceId $permission.Id -AppRoleId "Machine.Read.All"
    $appRoleAssignment = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ResourceId $permission.Id -AppRoleId $AppRole.Id -PrincipalId $sp.Id

    # Grant the Admin Consent
    #$consent = New-MgOAuth2PermissionGrant -ClientId $sp.Id -ConsentType "AllPrincipals" -PrincipalId $sp.Id -ResourceId $permission.Id -Scope "Machine.Read.All"
    $consent = New-MgOAuth2PermissionGrant -ClientId $sp.Id -ConsentType "AllPrincipals" -ResourceId $permission.Id -Scope "Machine.Read.All"

	Start-Sleep -Seconds 5
}
else {
    ## We already have the app registered so we'll just delete and create a new secret
    $appId = $MDERegApp.Id
    $ClientId = $MDERegApp.AppID

    ## Delete all app secrects
    $NoSecrets = @{
        PasswordCredentials = @()
    }
    Update-MgApplication -ApplicationId $appId -BodyParameter $NoSecrets

    ## Create a new app secret
    $newSecret = @{
		DisplayName   = "ReadMDEDevicesSecret"
		StartDateTime = (Get-Date).ToString("o")
		EndDateTime   = (Get-Date).AddYears(1).ToString("o")
	}

	for ($i = 0; $i -lt 3; $i++) {
		$updatedApp = Add-MgApplicationPassword -ApplicationId $appId -PasswordCredential $newSecret
		$appSecret = $updatedApp.SecretText

		if ($appSecret.Length -gt 0){break}
		if ($i -eq 2){
			Write-Host "No App Secret after 3 tries - Delete App Reg and try again later."
			Write-Host "- Exiting"
			exit
		}
	}
}

try {
	
	## Connect to the new registered app to read the machine objects
	$resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
	$oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
	$authBody = [Ordered] @{
		resource = "$resourceAppIdUri"
		client_id = "$ClientId"
		client_secret = "$appSecret"
		grant_type = 'client_credentials'
	}

	Start-Sleep -seconds 2
	$authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
	$token = $authResponse.access_token

}
catch {
		
	write-host "Failed to acquire token to MDE Endpoint - Check App Registration"
	Write-Host "Error from response:" $_.ErrorDetails -ForegroundColor Red
	exit 1
}

## Setting up to call the MDE Graph endpoint
$url = "https://api.securitycenter.microsoft.com/api/machines"

# Set the WebRequest headers
$headers = @{
    'Content-Type' = 'application/json'
    Accept = 'application/json'
    Authorization = "Bearer $token"
}


try {

# Send the webrequest and get the results.
$response = Invoke-WebRequest -Method Get -Uri $url -Headers $headers

}
catch {
		
	write-host "Failed to return data from the MDE Graph Endpoint"
	Write-Host "Error from response:" $_.ErrorDetails -ForegroundColor Red
	exit 1
}

# Extract the machine objects from the results.
$MDEmachines =  ($response.Content | ConvertFrom-Json).value

$MDEmachines | ForEach-Object {

	if ($_.osPlatform.contains("Server") -or $_.osPlatform.contains("Linux")){

		$Thiscomputer = [pscustomobject]@{
			Name = $_.computerDnsName
			MDEID = $_.id
			MachineID = ''
			OSPlatform = $_.osPlatform
			OSVersion = $_.version
			onboardingStatus = $_.onboardingStatus
			lastSeen = $_.lastSeen
			Location = ''
			MDESub = ''
		}

		if (($_.vmMetadata).length -gt 0){
			$Thiscomputer.Location = $_.vmMetadata.cloudProvider
			$Thiscomputer.MDESub = $_.vmMetadata.subscriptionId
			$Thiscomputer.MachineID = $_.vmMetadata.vmId #Matching VMID to DFS
		}

		$MDEServers += $Thiscomputer

	}	## Whether this is a server object

}

#############################################################################################
### Final Section: Compare the DFS list to the MDE list and create output ###################
#############################################################################################

## Compare DFS list to MDE list

$html = ''

## create dynamic name based on date and time
$outputFile = "DFSCheck-" + (get-date).ToString("yyMMddHHmmss") + ".html"
$outputPath = $PWD.Path + "\" + $outputFile

$Comparison = Compare-Object -ReferenceObject $DFSServers -DifferenceObject $MDEServers -Property MachineID -IncludeEqual -PassThru 

# Separate the results
$matches = $comparison | Where-Object { $_.SideIndicator -eq "==" }
$onlyInLeft = $comparison | Where-Object { $_.SideIndicator -eq "<=" }
$onlyInRight = $comparison | Where-Object { $_.SideIndicator -eq "=>" }

#$mergedMatches = [PSCustomObject]@{}
#$MDEServersOrphans = [PSCustomObject]@{}
#$DFSServersOrphans = [PSCustomObject]@{}

$html = Get-Content .\htmltop.txt

if ($matches) {
#### Create a combined table of the matched ####
# Write Merged Matches to the html file
$html += "    <h2>Servers Correctly Onboarded</h2>"
$html += "    <table>"
$row = 0

$matches | ForEach-Object {

    $Thisrecord = $_
    $Combinedrecord = $DFSServers | Where-Object {$_.MachineID -eq $Thisrecord.MachineID}
	$Combinedrecord.PSObject.Properties.Remove('SideIndicator')
    $MDEMatch = $MDEServers | Where-Object {$_.MachineID -eq $Thisrecord.MachineID}
    
    $MDEMatch.PSObject.Properties | ForEach-Object {
        if ((!($_.Name.Equals("Name"))) -and (!($_.Name.Equals("MachineID"))) -and (!($_.Name.Equals("SideIndicator")))) {
            $Combinedrecord | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.Value
        }
    }

    If ($row -eq 0){
        # Create the column headers
        $html += "       <tr>"
        $Combinedrecord.PSObject.Properties | ForEach-Object {
            $html += "<td>$($_.Name)</td>"
        }
        $html += "       </tr>"
        $row++
    }
    
    $html += "       <tr>"
    $Combinedrecord.PSObject.Properties | ForEach-Object {
        $html += "<td>$($_.Value)</td>"
    }
    $html += "       </tr>"
    
    #write-host "PausePoint"
} ## FOr each matching record

$html += "    </table>"

} ## We have some matches
else {
    ## Add something to HTML to note that there are no matches
	$html += "    <table><tr><td>No Servers With Matching Onboarding</td></tr></table>"
}

if ($onlyInLeft){
    $html += "    <h2>Servers Onboarded To Defender for Servers (Azure) Only</h2>"
    $html += "    <table>"
    $row = 0

    $onlyInLeft | ForEach-Object {
        If ($row -eq 0){
            $html += "       <tr>"
            $_.PSObject.Properties | ForEach-Object {
                if (!($_.Name.Equals("SideIndicator"))) {
                    #$DFSServersOrphans | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.Value
                    # Create the column headers
                    $html += "<td>$($_.Name)</td>"
                } 
            }
            $html += "       </tr>"
            $row++
        } # if row = 0 
    
        $html += "       <tr>"
        $_.PSObject.Properties | ForEach-Object {
            if (!($_.Name.Equals("SideIndicator"))) {
                $html += "<td>$($_.Value)</td>"
            }
        } # for each attribute
        $html += "       </tr>"
    } # for each DFS Orphan
	$html += "    </table>"
} # there are DFS orphans
else {
    ## Add something to HTML to note that there are no mismatches
	$html += "    <h2></h2>"
	$html += "    <table><tr><td>No Servers Onboarded To Defender For Servers Only</td></tr></table>"
}

if ($onlyInRight){
    $html += "    <h2>Servers Onboarded To Defender For Endpoint Only</h2>"
    $html += "    <table>"
    $row = 0

    $onlyInRight | ForEach-Object {
        If ($row -eq 0){
            $html += "       <tr>"
            $_.PSObject.Properties | ForEach-Object {
                if (!($_.Name.Equals("SideIndicator"))) {
                    #$DFSServersOrphans | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.Value
                    # Create the column headers
                    $html += "<td>$($_.Name)</td>"
                } 
            }
            $html += "       </tr>"
            $row++
        } # if row = 0 
    
        $html += "       <tr>"
        $_.PSObject.Properties | ForEach-Object {
            if (!($_.Name.Equals("SideIndicator"))) {
                $html += "<td>$($_.Value)</td>"
            }
        } # for each attribute
        $html += "       </tr>"
    } # for each DFS Orphan
	$html += "    </table>"
} # there are DFS orphans
else {
    ## Add something to HTML to note that there are no mismatches
	$html += "    <h2></h2>"
	$html += "    <table><tr><td>No Servers Onboarded To Defender For Endpoint Only</td></tr></table>"
}

## TODO: add one more heading with path to the file

$html += "    <h2>Output file: " + $outputFile + "</h2>"
$html += "</body>"
$html += "</html>"


$html | Out-File -FilePath $outputPath -Encoding UTF8
## TODO: output the full file path to the console
Write-host "The output file is located here: " $outputPath
Start-Process $outputPath
