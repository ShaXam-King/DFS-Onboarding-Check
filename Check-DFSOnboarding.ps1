<#
.SYNOPSIS
    CheckDFSOnboarding.ps1 - Reads Azure/Def for Servers inventory, reads servers from Def for Endpoint, compares the lists, and generates an HTML output file.

.DESCRIPTION
    1) Reads Azure Defender for Servers inventory.
    2) Reads servers from Defender for Endpoint.
    3) Compares the lists to generate combined list and orphan lists.
    4) Generates an HTML output file.

.REQUIREMENTS
    - MDE: An Entra registered application with permissions to read MDE machines (Machines.Read.All, Machines.ReadWriteAll).
    - DFS/Azure: Reader permission to Azure subscription(s)/Resource Group(s) for VMs, Scale Sets, and Arc Machines.
    - Local: Rights to install PowerShell and/or PowerShell modules and libraries.

.PARAMETER TenantId
    The Entra Tenant ID.

.PARAMETER ClientId
    The Application ID.

.PARAMETER AppSecret
    The Application Secret.

.EXAMPLE
    .\Check-DFSOnboarding.ps1 -TenantId "your-tenant-id" -ClientId "your-client-id" -AppSecret "your-app-secret"
#>

param (
    [string] $TenantId = "",
    [string] $ClientId = "",
    [string] $ClientSecret = ""
)
$AzureContext = $null  # Initialize the Azure Context variable to null

Import-LocalizedData -BindingVariable "UserMessages" -ErrorAction SilentlyContinue -ErrorVariable langerror

if ($langerror){
Write-Host "Problem importing local language settings - Defaulting to English"
$UserMessages = Data {
    #culture="en-US"
    ConvertFrom-StringData @'
    moduleCheckInstalled = Checking if module is installed:
    moduleInstalled = Module is installed
    moduleNotInstalled = Module is not installed. Installing now
    moduleError = Please ensure that the following module(s) are installed
    azureConnectLoginRequired = Azure Login required.  Please check for a login window on your desktop
    azureConnectTokenSuccess = Retreived Azure token successfully
    azureConnectTokenFailed = Unable to acquire Access Token. Exiting
    azureSubscriptionsStart = Getting Azure Subscriptions
    azureSubscriptionException = An exception occurred while getting Azure Subscriptions
    azureSubscriptionContextNotFound = Azure Context not found - attempting refresh
    azureSubscriptionCountextFound = Azure Context found
    azureSubscriptionNotFound = Unable to find an Azure Subscription with the signed-in account
    azureResourceGroupsStart = Retrieveing Resource Groups for Subscription:
    azureResourceGroupNotFound = Unable to retrieve resources from Resource Group
    azureGetVirtualMachinesFailed = Failed to get Virtual Machines
    azureGetVirtualMachineScaleSetsFailed = Failed to get Virtual Machine Scale Sets
    azureGetArcMachinesFailed = Failed to get Arc Machines
    azureSubChoiceYN = Use only this subscription to compare onboarded servers? (Y/N)
    azureSubChoiceNums = Choose Subscriptions by number (comma separated) (e.g. 1,3,4)
    processMachinesStart = Processing (setting or reading) pricing configuration for VM 
    processMachinesError = Failed to get pricing configuration for VM
    mdeGetMachinesTokenSuccess = Retrieved Graph API for MDE machines token successfully.
    mdeGetMachinesTokenFailed = Failed to acquire token to MDE Endpoint - Check App Registration
    mdeGetMachinesFailed = Failed to retrieve machines from Defender for Endpoint
    mainError = An error occurred during the execution of the script.
    mainMidpointMessage = Defender for Servers processing complete.  Starting Defender for Endpoint processing.
    mainSkipMDE = Skipping MDE setup and query function calls per user request
    mainMDEWillBeSkipped = MDE credentials are missing. Skipping MDE search per user request
    mainAzureMachinesCountMsg = Total Defender For Servers inventoried servers found
    mainMDETotalDeviceCount = Total Defender for Endpoint onboarded devices
    mainMatchByIDMsg = Devices matched by Machine ID
    mainMatchByNameMsg = Devices matched by Name
    mainMDEUnmatchedMsg = Servers onboarded to MDE not in Defender for Servers inventory
    mainMDCUnmatchedMsg = Servers in Defender for Servers inventory not onboarded to MDE
    mainMDEComplete = MDE device list access complete - Moving to comparison process
    mainNoCompareMsg = A list has no entries - no comparison attempted 
    azureTShootMessage = Check Defender for Cloud MDE onboarding configuration
    azureTShootURL = https://learn.microsoft.com/en-us/azure/defender-for-cloud/enable-defender-for-endpoint
    mdeTShootMsg = Check MDE Direct Onboarding Configuration
    mdeTShootURL = https://learn.microsoft.com/en-us/azure/defender-for-cloud/onboard-machines-with-defender-for-endpoint
    NameMatchOnboardMessage = Servers Onboarded Having Matched Names
    NameTShootMessage = Servers have full DFS functionality but have dual onboarding - Check DFS Onboarding Config
    processNoRecordsMessage = No issues found
    correctOnboardMessage = Servers Correctly Onboarded
    correctOnboardTShootMsg = Servers have full DFS functionality with correct onboarding - Well done!
    azureOnboardOnly = Servers Onboarded To Defender for Servers (Azure) Only
    mdeOnboardOnly = Servers Onboarded To Defender For Endpoint Only
'@
}

}


function Get-RequiredParams {

    <#
    $TenantId,
    [string] $ClientId,
    [string] $ClientSecret
    #>
    if ($TenantId.length -gt 0){

    }
    if ($TenantId.length -gt 0){

    }
    if ($TenantId.length -gt 0){

    }

} # End of Get-RequiredParams function

function Import-RequiredModules {
    $modules = @("Az.Accounts", "Az.Resources")
    foreach ($module in $modules) {
        try {
            Write-Host $UserMessages.moduleCheckInstalled $module
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Host $UserMessages.moduleNotInstalled $module
            Install-Module -Name $module -Scope CurrentUser -Force
        }
        else {
            Write-Host $UserMessages.moduleInstalled $module
        }

            Import-Module $module -ErrorAction Stop
        } catch {
            Write-Host $UserMessages.moduleError $module
            Write-Host $_.ErrorDetails -ForegroundColor Red
            throw
        }
    }
}

function Connect-AzureAccount {
    $needLogin = $true
    try {
        $AzureContext = Get-AzContext
        if ($AzureContext) {
            $needLogin = ([string]::IsNullOrEmpty($content.Account))
        }
    } catch {
        if ($_ -like "*Connect-AzAccount to login*") {
            $needLogin = $true
        } else {
            throw
        }
    }

    if ($needLogin) {
        Write-Host $UserMessages.azureConnectLoginRequired -ForegroundColor Yellow
        Connect-Azaccount 3> $null
    }
        # Retrieve the current context after login
        $AzureContext = Get-AzContext

}

function Get-AzureAccessToken {
    $accessToken = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/" | Select-Object -ExpandProperty token)
    if (!($accessToken.Length -gt 0)) {
        Write-Host $UserMessages.azureConnectTokenFailed -ForegroundColor Red
        exit 1
    }
    else {
        Write-Host $UserMessages.azureConnectTokenSuccess -ForegroundColor Green
    }
    return $accessToken
}

function Get-Subscriptions {
    Try{
        if (!($AzureContext)) { 
            Write-Host $UserMessages.azureSubscriptionContextNotFound -ForegroundColor Yellow
            $AzureContext = Get-AzContext 
        }

        if ($AzureContext) {
            Clear-Host
            Write-Host $UserMessages.azureSubscriptionCountextFound - $AzureContext.Subscription.Id -ForegroundColor Green
            $response = Read-Host -Prompt $UserMessages.azureSubChoiceYN

            if ($response.ToLower() -eq "y") {
                return $AzureContext.Subscription
            }
            else {
                try {
                    Clear-Host
                    Write-Host $UserMessages.azureSubscriptionsStart -ForegroundColor Blue
                    $FoundSubscriptions = get-azsubscription
                    $num = 1
                    $FoundSubscriptions | ForEach-Object {
                        Write-host $num") Name:" $_.Name "ID:" $_.SubscriptionId
                        $num++
                    }
                    $ChosenSubscriptions = @()
                    $response = Read-Host -Prompt $UserMessages.azureSubChoiceNums
                    
                    $response.Split(",") | ForEach-Object {
                        $curNum = [int]$_
                        if ($curNum - 1 -le $FoundSubscriptions.Length){$ChosenSubscriptions += $FoundSubscriptions[$curNum -1]}
                    }

                    return $ChosenSubscriptions
            
                } 
                catch {
                    $errorMessage = $UserMessages.azureSubscriptionException
                    $errorDetails = $_.Exception.Message
                    Write-Host $errorMessage +":" $errorDetails -ForegroundColor Red
                    return $null
                }
            }
        }
        else {
            Write-Host $UserMessages.azureSubscriptionNotFound -ForegroundColor Red
            Write-Host $_.ErrorDetails -ForegroundColor Red
            throw
        }
    }
    Catch {
        $errorMessage = $UserMessages.azureSubscriptionException
        $errorDetails = $_.Exception.Message
        Write-Host $errorMessage +":" $errorDetails -ForegroundColor Red
        return $null
    }
}

function Get-AzureResourceGroups($SubscriptionId) {
    try {
        Write-Host $UserMessages.azureResourceGroupsStart + $SubscriptionId -ForegroundColor Blue
        Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop # Set the subscription context to the passed in value
        return get-azResourceGroup -ErrorAction SilentlyContinue 2>$null
    } catch {
        # Handle the error silently
        $errorMessage = $UserMessages.azureResourceGroupNotFound
        $errorDetails = $_.Exception.Message
        Write-Host $errorMessage +":" $errorDetails -ForegroundColor Red
        # Optionally log the error to a file or variable
        # Add-Content -Path "error.log" -Value "$errorMessage: $errorDetails"
        return $null
    }
}

function Get-VirtualMachines($SubscriptionId, $resourceGroupName, $accessToken) {
    $vmResponseMachines = @()
    $vmUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Compute/virtualMachines?api-version=2021-04-01"
    try{
    do {
        $vmResponse = Invoke-RestMethod -Method Get -Uri $vmUrl -Headers @{ Authorization = "Bearer $accessToken" } -ErrorAction SilentlyContinue 2> $null
        $vmResponseMachines += $vmResponse.value
        $vmUrl = $vmResponse.nextLink
    } while (![string]::IsNullOrEmpty($vmUrl))
    } catch {
        $errorMessage = $UserMessages.azureGetVirtualMachinesFailed + " Resource Group '$resourceGroupName'"
        $errorDetails = $_.Exception.Message
        # Write-Host $errorMessage +":" $errorDetails -ForegroundColor Red
        # Optionally log the error to a file
        # Add-Content -Path "error.log" -Value "Failed to retrieve virtual machines for Subscription: $SubscriptionId, ResourceGroup: $resourceGroupName. Error details: $_"
        return $null
    }
    return $vmResponseMachines
}

function Get-VirtualMachineScaleSets($SubscriptionId, $resourceGroupName, $accessToken) {
    $vmssResponseMachines = @()
    $vmssUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2021-04-01"
    try{
    do {
        $vmssResponse = Invoke-RestMethod -Method Get -Uri $vmssUrl -Headers @{ Authorization = "Bearer $accessToken" } -ErrorAction SilentlyContinue 2> $null
        $vmssResponseMachines += $vmssResponse.value
        $vmssUrl = $vmssResponse.nextLink
    } while (![string]::IsNullOrEmpty($vmssUrl))
    } catch {
        $errorMessage = $UserMessages.azureGetVirtualMachineScaleSetsFailed + " Resource Group '$resourceGroupName'"
        $errorDetails = $_.Exception.Message
        # Write-Host $errorMessage +":" $errorDetails -ForegroundColor Red
        # Optionally log the error to a file
        # Add-Content -Path "error.log" -Value "Failed to retrieve virtual machines for Subscription: $SubscriptionId, ResourceGroup: $resourceGroupName. Error details: $_"
        return $null
    }
    return $vmssResponseMachines
}

function Get-ArcMachines($SubscriptionId, $resourceGroupName, $accessToken) {
    $arcResponseMachines = @()
    $arcUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.HybridCompute/machines?api-version=2022-12-27"
    try{
    do {
        $arcResponse = Invoke-RestMethod -Method Get -Uri $arcUrl -Headers @{ Authorization = "Bearer $accessToken" } -ErrorAction SilentlyContinue 2> $null
        $arcResponseMachines += $arcResponse.value
        $arcUrl = $arcResponse.nextLink
    } while (![string]::IsNullOrEmpty($arcUrl))
    } catch {
        $errorMessage = $UserMessages.azureGetArcMachinesFailed + " Resource Group '$resourceGroupName'"
        $errorDetails = $_.Exception.Message
        # Write-Host $errorMessage +":" $errorDetails -ForegroundColor Red
        # Optionally log the error to a file
        # Add-Content -Path "error.log" -Value "Failed to retrieve virtual machines for Subscription: $SubscriptionId, ResourceGroup: $resourceGroupName. Error details: $_"
        return $null
    }
    return $arcResponseMachines
}

function Get-OSFamily {
    param (
        [pscustomobject] $machine
    )

    # Initialize variables
    $osFamily = "Unknown"
    $osDiskPublisher = $null
    $imageReferencePublisher = $null

    # Check if the machine has a storage profile
    if ($machine.properties -and $machine.properties.storageProfile) {
        # Check if the machine has an OS disk
        if ($machine.properties.storageProfile.osDisk) {
            $osDiskPublisher = $machine.properties.storageProfile.osDisk.osType
        }

        # Check if the machine has an image reference
        if ($machine.properties.storageProfile.imageReference) {
            $imageReferencePublisher = $machine.properties.storageProfile.imageReference.publisher
        }
    }

    # Determine the OS family based on the publisher values
    # Is there a publisher for the image reference?
    if ($imageReferencePublisher) {
        if ($imageReferencePublisher -eq "MicrosoftWindowsServer") {
            $osFamily = "Windows"
        } elseif ($imageReferencePublisher -match "Canonical|RedHat|SUSE|Debian|Oracle|CentOS|Fedora|kali-linux") { # Add more Linux publishers as needed
            $osFamily = "Linux"
        } 
            # Windows Desktop OS
            elseif ($imageReferencePublisher -match "MicrosoftWindowsDesktop") {
            $osFamily = "Windows - Desktop"
            }
        else {
            # Everything else
            Add-Content -Path "notWindowsOrLinux.log" -Value ($machine | ConvertTo-Json -Depth 20)
            $osFamily = $machine.properties.storageProfile.imageReference.sku
        }
    }
    # Is there a publisher for the OS disk?
    elseif ($osDiskPublisher) {
        if ($osDiskPublisher -eq "Windows") {
            $osFamily = "Windows"
        } elseif ($osDiskPublisher -eq "Linux") {
            $osFamily = "Linux"
        } else {
            Add-Content -Path "notWindowsOrLinux.log" -Value ($machine | ConvertTo-Json -Depth 20)
            $osFamily = $osDiskPublisher
        }
    } 
    # If no publisher is found, check the OS disk name / format
    elseif ($machine.properties -and $machine.properties.osName) {
        # This is an Arc-enabled machine
        if ($machine.properties.osName -match "Windows") {
            $osFamily = "Windows"
        } elseif ($machine.properties.osName -match "Linux") {
            $osFamily = "Linux"
        } else {
            $osFamily = $machine.properties.osName
        }
    }

    return $osFamily
}

function Invoke_VirtualMachineConfiguration ($machines, $SubscriptionId, $accessToken) {
    $DefenderForCloudServers = @()
    foreach ($machine in $machines) {
        $pricingUrl = "https://management.azure.com$($machine.id)/providers/Microsoft.Security/pricings/virtualMachines?api-version=2024-01-01"
        Write-Host $UserMessages.processMachinesStart + $($machine.name) -ForegroundColor Blue
        try {
            # Get the pricing configuration for the Virtual Machine from Azure
            $pricingResponse = Invoke-RestMethod -Method Get -Uri $pricingUrl -Headers @{ Authorization = "Bearer $accessToken" } -ContentType "application/json" -TimeoutSec 120 -ErrorAction SilentlyContinue
            if ($pricingResponse.properties.pricingTier -eq "Standard") {
                $currentComputer = [pscustomobject]@{
                    Name = $machine.name
                    DFSGUID = $machine.identity.principalID
                    MachineID = $machine.properties.vmid
                    OSFamily = Get-OSFamily -machine $machine
                    Sub = $SubscriptionId
                    RG = ''
                    DSLocation = $machine.location
                    PriceTier = $pricingResponse.properties.pricingTier
                    SubPlan = $pricingResponse.properties.subPlan
                    EnrEnabled = "No"
                }
                $subscriptionEnrollmentStatus = $pricingResponse.properties.extensions | Where-Object { $_.name -eq "MdeDesignatedSubscription" } | Select-Object isEnabled
                if ($subscriptionEnrollmentStatus.isEnabled) { $currentComputer.EnrEnabled = "Yes" }
                if ($machine.id -match "/resourceGroups/([^/]+)/") { $currentComputer.RG = $matches[1] }
                $DefenderForCloudServers += $currentComputer
            }
        } catch {
            Write-Host $UserMessages.processMachinesError + $($machine.name) -ForegroundColor Red
            Write-Host "Response StatusCode:" $_.Exception.Response.StatusCode.value__  -ForegroundColor Red
            Write-Host "Response StatusDescription:" $_.Exception.Response.StatusDescription -ForegroundColor Red
            Write-Host "Error from response:" $_.ErrorDetails -ForegroundColor Red
        }
        Start-Sleep -Seconds 0.3
    }
    return $DefenderForCloudServers
}

function Get-MDEAccessToken {
    try {
        $resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
        $oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
        $authBody = [Ordered] @{
            resource      = "$resourceAppIdUri"
            client_id     = "$ClientId"
            client_secret = "$ClientSecret"
            grant_type    = 'client_credentials'
        }

        #Start-Sleep -seconds 2
        $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody
        Write-Host $UserMessages.mdeGetMachinesTokenSuccess -ForegroundColor Green

        return $authResponse.access_token
    } catch {
        Write-Host $UserMessages.mdeGetMachinesTokenFailed -ForegroundColor Red
        Write-Host "Error from response:" $_.Exception.Message -ForegroundColor Red
        return $null
    }
}

# Get the machines from Defender for Endpoint
function Get-MDEMachines ($MDEAccessToken){

    $headers = @{
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
        Authorization  = "Bearer $MDEAccessToken"
    }

    $url = "https://api.securitycenter.microsoft.com/api/machines"

    $allResults = @()

    do {
        try {
            $response = Invoke-RestMethod -Method Get -Uri $url -Headers $headers

        } catch {
            Write-Host $UserMessages.mdeGetMachinesFailed -ForegroundColor Red
            Write-Host "Error from response:" $_.ErrorDetails -ForegroundColor Red
            exit 1
        }     

        # Append the current page of data to the allData array
        $allResults += $response.value

        # Check if there is a nextLink
        $url = $response.'@odata.nextLink'
    } while ($url)
    
    return $allResults
}

function Set-MDEMachineAttribs {
    param (
        [array] $MDEmachines
    )

    $MDEAll = @()
    $MDEmachines | ForEach-Object {
            $currentMachine = [pscustomobject]@{
                Name             = $_.computerDnsName
                MDEID            = $_.id
                MachineID        = ''
                OSPlatform       = $_.osPlatform
                OSVersion        = $_.version
                onboardingStatus = $_.onboardingStatus
                lastSeen         = $_.lastSeen
                Location         = ''
                MDESub           = ''
            }

            if (($_.vmMetadata).length -gt 0) {
                $currentMachine.Location = $_.vmMetadata.cloudProvider
                $currentMachine.MDESub = $_.vmMetadata.subscriptionId
                $currentMachine.MachineID = $_.vmMetadata.vmId #Matching VMID to DFS
            }

            $MDEAll += $currentMachine
        
    }
    return $MDEAll
}

function Get-MDEServers {
    param (
        [array] $MDEmachines
    )

    $MDEServers = @()
    $MDEmachines | ForEach-Object {
        if ($_.osPlatform.contains("Server") -or $_.osPlatform.contains("Linux")) {
            $MDEServers += $currentMachine
        }
    }
    return $MDEServers
}

function Compare-ByMachID {
    param (
        [array] $DefenderForCloudServers,
        [array] $MDEDevices
    )

    $Comparison = Compare-Object -ReferenceObject $DefenderForCloudServers -DifferenceObject $MDEDevices -Property MachineID -IncludeEqual -PassThru 

    $IDmatches = $Comparison | Where-Object { $_.SideIndicator -eq "==" }
    $onlyInLeft = $Comparison | Where-Object { $_.SideIndicator -eq "<=" }
    $onlyInRight = $Comparison | Where-Object { $_.SideIndicator -eq "=>" }

    return $IDmatches, $onlyInLeft, $onlyInRight
}

function Compare-ByName {
    param (
        [array] $DefenderForCloudServers,
        [array] $MDEDevices
    )

    $Comparison = Compare-Object -ReferenceObject $DefenderForCloudServers -DifferenceObject $MDEDevices -Property Name -IncludeEqual -PassThru 

    $NameMatches = $Comparison | Where-Object { $_.SideIndicator -eq "==" }
    $onlyInLeft = $Comparison | Where-Object { $_.SideIndicator -eq "<=" }
    $onlyInRight = $Comparison | Where-Object { $_.SideIndicator -eq "=>" }

    return $NameMatches, $onlyInLeft, $onlyInRight
}

function Get-JoinedList {
    param (
        [array] $DFSMatches,
        [array] $MDECandidates,
        [string] $MatchAttrib = "MachineID"
    )
        
    $locComboRecords = @()
    $DFSMatches | ForEach-Object {
        $Combinedrecord = $_
            
        $Combinedrecord.PSObject.Properties.Remove('SideIndicator')
        $MDEMatch = $MDECandidates | Where-Object { $_.$($MatchAttrib) -eq $Combinedrecord.$($MatchAttrib) }

        $MDEMatch.PSObject.Properties | ForEach-Object {
            if ((!($_.Name.Equals("Name"))) -and (!($_.Name.Equals("MachineID"))) -and (!($_.Name.Equals("SideIndicator")))) {
                $Combinedrecord | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.Value
            }
        }

        # Always remove the SideIndicator property if it exists
        if ($Combinedrecord.PSObject.Properties.Match('SideIndicator')) {
            $Combinedrecord.PSObject.Properties.Remove('SideIndicator')
        }

        $locComboRecords += $Combinedrecord
    }

    return $locComboRecords
}

function New-HTMLSection {
    param (
        [array] $Records,
        [string] $Title,
        [string] $TSmsg,
        [string] $TSURL,
        [string] $ItemCount,
        [string] $CountMsg
    )

    $htmlSection = ""
    if ($Records) {
        $htmlSection += "    <h2>$Title</h2>"
        $htmlSection += "    <table>"
        $row = 0

        $Records | ForEach-Object {

            if ($row -eq 0) {
                $htmlSection += "       <tr>"
                $_.PSObject.Properties | ForEach-Object {
                    $htmlSection += "<td>$($_.Name)</td>"
                }
                $htmlSection += "       </tr>"
                $row++
            }

            $htmlSection += "       <tr>"
            $_.PSObject.Properties | ForEach-Object {
                $htmlSection += "<td>$($_.Value)</td>"
            }
            $htmlSection += "       </tr>"
        }
        $htmlSection += "    </table>"
        $htmlSection += "<table>"
        #$htmlSection += "<tr><td> </td></tr>"
        $htmlSection += "<tr>"
        if ($TSURL){
            $htmlSection += "<td><a href=" + [char]34 + $TSURL + [char]34 + ">" + $TSmsg + "</a></td>"
        }
        else {$htmlSection += "<td>" + $TSmsg + "</td>"}
        $htmlSection += "<td>" + $ItemCount + " " + $CountMsg + "</td>"
        $htmlSection += "</tr>"
        $htmlSection += "</table>"
        
    } else {
        $htmlSection += "    <h2>" + $Title + "</h2>"
        $htmlSection += "    <table><tr><td>" + $UserMessages.processNoRecordsMessage + "</td></tr></table>"
    }

    return $htmlSection
}

function Get-DefaultHTML {
    $htmltop = "<!DOCTYPE html>
<html>
<head>
    <title>Defender for Servers Onboarding Check Output</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
        }
        h2 {
            color: #333;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
            color: #333;
        }
        tr:nth-child(even) {
            background-color: #f9f9f8;
        }
        tr:hover {
            background-color: #f1f1f1;
        }
    </style>
</head>
<body>"
    
    return $htmltop
}

function Export-HTMLReport {
    param (
        [array] $IDmatches,
        [array] $NameMatches,
        [array] $onlyInDFS,
        [array] $onlyInMDE,
        [string] $outputFile
    )

    if (Test-Path -Path .\htmltop.txt) {$html = Get-Content .\htmltop.txt}
    else {
        $html = Get-DefaultHTML
    }

    $html += New-HTMLSection -Records $IDmatches -Title $UserMessages.correctOnboardMessage -TSmsg $UserMessages.correctOnboardTShootMsg -ItemCount $IDmatches.Length -CountMsg $UserMessages.mainMatchByIDMsg
    $html += New-HTMLSection -Records $Namematches -Title $UserMessages.NameMatchOnboardMessage -TSmsg $UserMessages.NameTShootMessage -ItemCount $NameMatches.length -CountMsg $UserMessages.mainMatchByNameMsg
    $html += New-HTMLSection -Records $onlyInDFS -Title $UserMessages.azureOnboardOnly  -TSmsg $UserMessages.azureTShootMessage -TSURL $UserMessages.azureTShootURL -ItemCount $onlyInDFS.Length -CountMsg $UserMessages.mainMDCUnmatchedMsg
    $html += New-HTMLSection -Records $onlyInMDE -Title $UserMessages.mdeOnboardOnly  -TSmsg $UserMessages.mdeTShootMsg -TSURL $UserMessages.mdeTShootURL -ItemCount $onlyInMDE -CountMsg $UserMessages.mainMDEUnmatchedMsg

    $html += "    <h2>Output file: " + $outputFile + "</h2>"
    $html += "</body>"
    $html += "</html>"

    $html | Out-File -FilePath $outputFile -Encoding UTF8
    Write-Host "The output file is located here: " $outputFile
    Start-Process $outputFile
}

function Main {

    try {
    #Get-RequiredParams
    Import-RequiredModules # Import required modules
    Connect-AzureAccount # Connect to Azure account
    $AZaccessToken = Get-AzureAccessToken # Get Azure access token

    if (($TenantId.length -gt 0) -And ($ClientId.length -gt 0) -And ($ClientSecret.length -gt 0)){
        $MDEAccessToken = Get-MDEAccessToken -TenantId $TenantId -ClientId $ClientId -AppSecret $ClientSecret
    }

    if($AZaccessToken.length -gt 0){
        $Subscriptions = Get-Subscriptions # Get all of the Azure subscriptions this user has access to

        $DefenderForCloudServers = @() # Initialize the array to store Defender for Cloud Servers

        foreach ($Subscription in $Subscriptions) { # Loop through each subscription TODO: Add a check for the subscription status
            $SubscriptionId = $Subscription.Id # Get the subscription ID
            $ResourceGroups = Get-AzureResourceGroups $SubscriptionId # Get the resource groups for the subscription
            foreach ($resourceGroup in $ResourceGroups) { # Loop through each resource group
                $resourceGroupName = $resourceGroup.ResourceGroupName # Get the resource group name
                Write-Host "Subscription: $SubscriptionId - ResourceGroup: $resourceGroupName" # Display the subscription and resource group
                $vmResponseMachines = Get-VirtualMachines $SubscriptionId $resourceGroupName $AZaccessToken # Get the virtual machines in the resource group
                $vmssResponseMachines = Get-VirtualMachineScaleSets $SubscriptionId $resourceGroupName $AZaccessToken # Get the virtual machine scale sets in the resource group
                $arcResponseMachines = Get-ArcMachines $SubscriptionId $resourceGroupName $AZaccessToken # Get the Arc machines in the resource group
                $DefenderForCloudServers += Invoke_VirtualMachineConfiguration $vmResponseMachines $SubscriptionId $AZaccessToken # Process the virtual machines
                $DefenderForCloudServers += Invoke_VirtualMachineConfiguration $vmssResponseMachines $SubscriptionId $AZaccessToken # Process the virtual machine scale sets
                $DefenderForCloudServers += Invoke_VirtualMachineConfiguration $arcResponseMachines $SubscriptionId $AZaccessToken # Process the Arc machines
            }
            Write-Host $DefenderForCloudServers.length $UserMessages.mainAzureMachinesCountMsg  -ForegroundColor Magenta # number of Azure machines in plan found
        }
    }

    Write-Host $UserMessages.mainMidpointMessage -ForegroundColor Green # Show the midpoint message and display it in green as a marker of success

    if ($MDEAccessToken.length -gt 0){
        $MDEmachines = Get-MDEMachines $MDEAccessToken # Get the machines from Defender for Endpoint (MDE)
        $MDEAll = Set-MDEMachineAttribs -MDEmachines $MDEmachines # Refine MDE list to have only required attributes 
    }

    Write-Host $MDEAll.length $UserMessages.mainMDETotalCount -ForegroundColor Magenta # number of MDE devices found
    Write-Host $UserMessages.mainMDEComplete -ForegroundColor Green 

    $outputFile = "DFSCheck-" + (Get-Date).ToString("yyyyMMddHHmmss") + ".html" # Generate the output file name

    if (($DefenderForCloudServers.length -gt 0) -and ($MDEAll.length -gt 0)){ # We need at least 1 server in both sides to compare

        # First Check - By ID
        $MachIDmatches, $MachIDonlyInMDC, $MachIDonlyInMDE = Compare-ByMachID -DefenderForCloudServers $DefenderForCloudServers -MDEDevices $MDEAll # Compare the lists by VMID
        $ComboIDMatches = Get-JoinedList -DFSMatches $MachIDmatches -MDECandidates $MDEAll -MatchAttrib "MachineID" # Create ByID combined list
        Write-Host $ComboIDMatches.length $UserMessages.mainMatchByIDMsg -ForegroundColor Magenta
        $MDEAll = @() # No longer need entire MDE list


        # Second Check - By Name
        $NameMatches, $NameonlyInMDC, $NameonlyInMDE = Compare-ByName -DefenderForCloudServers $MachIDonlyInMDC -MDEDevices $MachIDonlyInMDE # Compare the lists by name
        # Create ByName combined list
        $ComboNameMatches = Get-JoinedList -DFSMatches $NameMatches -MDECandidates $MachIDonlyInMDE -MatchAttrib "Name"
        Write-Host $ComboNameMatches.length $UserMessages.mainMatchByNameMsg -ForegroundColor Magenta 
        $MachIDonlyInMDE = @() # No longer need entire MDE list

        # Narrow down remaining MDE list to only Servers
        if ($NameonlyInMDE.length -gt 0){
            $MDEServers = Get-MDEServers -MDEmachines $NameonlyInMDE
            Write-Host $MDEServers.length $UserMessages.mainMDEUnmatchedMsg -ForegroundColor Magenta 
            $NameonlyInMDE = @() # No longer need entire MDE endpoint list
        }

        Write-Host $NameonlyInMDC.length $UserMessages.mainMDCUnmatchedMsg -ForegroundColor Magenta
        Export-HTMLReport -IDmatches $ComboIDMatches -NameMatches $ComboNameMatches -onlyInDFS $NameonlyInMDC -onlyInMDE $MDEServers -outputFile $outputFile # Generate the HTML report
    }
    else { # We will generate the report having only the list where servers were found
        Write-Host $UserMessages.mainNoCompareMsg -ForegroundColor Green
        if ($DefenderForCloudServers.length -eq 0){
            if ($MDEAll.length -gt 0){
                $MDEServers = Get-MDEServers -MDEmachines $MDEAll
                Write-Host $MDEServers.length $UserMessages.mainMDEUnmatchedMsg -ForegroundColor Magenta
                Export-HTMLReport -IDmatches $null -NameMatches $null -onlyInDFS $null -onlyInMDE $MDEServers -outputFile $outputFile # Generate the HTML report
            }
        }
        else {
            Write-Host $DefenderForCloudServers.length $UserMessages.mainMDCUnmatchedMsg -ForegroundColor Magenta
            Export-HTMLReport -IDmatches $null -NameMatches $null -onlyInDFS $DefenderForCloudServers -onlyInMDE $null -outputFile $outputFile # Generate the HTML report
        }
    }

    } catch {
        Write-Host $UserMessages.mainError -ForegroundColor Red
        Write-Host "Error details: $_" -ForegroundColor Red
        # Optionally log the error to a file
        # Add-Content -Path "error.log" -Value "Error details: $_"
    }
    
}

Main