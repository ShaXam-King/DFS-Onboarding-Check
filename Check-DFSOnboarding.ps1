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
    [string] $AppSecret = ""
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
    azureTShootMessage = Check Defender for Cloud MDE Onboarding Configuration
    azureTShootURL = https://learn.microsoft.com/en-us/azure/defender-for-cloud/enable-defender-for-endpoint
    mdeTShootMsg = Check MDE Direct Onboarding Configuration
    mdeTShootURL = https://learn.microsoft.com/en-us/azure/defender-for-cloud/onboard-machines-with-defender-for-endpoint
    processNoRecordsMessage = No records found
    correctOnboardMessage = Servers Correctly Onboarded
    azureOnboardOnly = Servers Onboarded To Defender for Servers (Azure) Only
    mdeOnboardOnly = Servers Onboarded To Defender For Endpoint Only
'@
}

}


function Get-RequiredParams {

    <#
    $TenantId,
    [string] $ClientId,
    [string] $AppSecret
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

function Invoke_VirtualMachineConfiguration ($machines, $SubscriptionId, $accessToken) {
    $DefenderForCloudServers = @()
    foreach ($machine in $machines) {
        $pricingUrl = "https://management.azure.com$($machine.id)/providers/Microsoft.Security/pricings/virtualMachines?api-version=2024-01-01"
        Write-Host $UserMessages.processMachines + $($machine.name) -ForegroundColor Blue
        try {
            # Get the pricing configuration for the Virtual Machine from Azure
            $pricingResponse = Invoke-RestMethod -Method Get -Uri $pricingUrl -Headers @{ Authorization = "Bearer $accessToken" } -ContentType "application/json" -TimeoutSec 120 -ErrorAction SilentlyContinue
            if ($pricingResponse.properties.pricingTier -eq "Standard") {
                $currentComputer = [pscustomobject]@{
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
            client_secret = "$AppSecret"
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

    $url = "https://api.securitycenter.microsoft.com/api/machines"
    $headers = @{
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
        Authorization  = "Bearer $MDEAccessToken"
    }

    try {
        $response = Invoke-WebRequest -Method Get -Uri $url -Headers $headers
    } catch {
        Write-Host $UserMessages.mdeGetMachinesFailed -ForegroundColor Red
        Write-Host "Error from response:" $_.ErrorDetails -ForegroundColor Red
        exit 1
    }

    return ($response.Content | ConvertFrom-Json).value
}

function Invoke_MDEMachinesProcessing {
    param (
        [array] $MDEmachines
    )

    $MDEServers = @()
    $MDEmachines | ForEach-Object {
        if ($_.osPlatform.contains("Server") -or $_.osPlatform.contains("Linux")) {
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

            $MDEServers += $currentMachine
        }
    }
    return $MDEServers
}

function Compare-Lists-ByMachID {
    param (
        [array] $DefenderForCloudServers,
        [array] $MDEServers
    )

    $Comparison = Compare-Object -ReferenceObject $DefenderForCloudServers -DifferenceObject $MDEServers -Property MachineID -IncludeEqual -PassThru 

    $matches = $Comparison | Where-Object { $_.SideIndicator -eq "==" }
    $onlyInLeft = $Comparison | Where-Object { $_.SideIndicator -eq "<=" }
    $onlyInRight = $Comparison | Where-Object { $_.SideIndicator -eq "=>" }

    return $matches, $onlyInLeft, $onlyInRight
}

function Compare-Lists-ByName {
    param (
        [array] $DefenderForCloudServers,
        [array] $MDEServers
    )

    $Comparison = Compare-Object -ReferenceObject $DefenderForCloudServers -DifferenceObject $MDEServers -Property Name -IncludeEqual -PassThru 

    $matches = $Comparison | Where-Object { $_.SideIndicator -eq "==" }
    $onlyInLeft = $Comparison | Where-Object { $_.SideIndicator -eq "<=" }
    $onlyInRight = $Comparison | Where-Object { $_.SideIndicator -eq "=>" }

    return $matches, $onlyInLeft, $onlyInRight
}

function CreateHTMLSection {
    param (
        [string] $Title,
        [array] $Records,
        [bool] $IncludeProperties = $false,
        [string] $TSmsg,
        [string] $TSURL
    )

    $htmlSection = ""
    if ($Records) {
        $htmlSection += "    <h2>$Title</h2>"
        $htmlSection += "    <table>"
        $row = 0

        $Records | ForEach-Object {
            $currentRecord = $_
            if ($IncludeProperties) {
                $Combinedrecord = $DefenderForCloudServers | Where-Object { $_.MachineID -eq $currentRecord.MachineID }
                $Combinedrecord.PSObject.Properties.Remove('SideIndicator')
                $MDEMatch = $MDEServers | Where-Object { $_.MachineID -eq $currentRecord.MachineID }

                $MDEMatch.PSObject.Properties | ForEach-Object {
                    if ((!($_.Name.Equals("Name"))) -and (!($_.Name.Equals("MachineID"))) -and (!($_.Name.Equals("SideIndicator")))) {
                        $Combinedrecord | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.Value
                    }
                }
            } else {
                $Combinedrecord = $currentRecord
            }
            
            # Always remove the SideIndicator property if it exists
            if ($Combinedrecord.PSObject.Properties.Match('SideIndicator')) {
                $Combinedrecord.PSObject.Properties.Remove('SideIndicator')
            }

            if ($row -eq 0) {
                $htmlSection += "       <tr>"
                $Combinedrecord.PSObject.Properties | ForEach-Object {
                    $htmlSection += "<td>$($_.Name)</td>"
                }
                $htmlSection += "       </tr>"
                $row++
            }

            $htmlSection += "       <tr>"
            $Combinedrecord.PSObject.Properties | ForEach-Object {
                $htmlSection += "<td>$($_.Value)</td>"
            }
            $htmlSection += "       </tr>"
        }
        $htmlSection += "    </table>"
        if (!($IncludeProperties)){
            $htmlSection += "<table>"
            $htmlSection += "<tr><td> </td></tr>"
            $htmlSection += "<tr><td><a href=" + [char]34 + $TSURL + [char]34 + ">" + $TSmsg + "</a></td></tr>"
            $htmlSection += "</table>"
        }
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
            table {
                width: 100%;
                border-collapse: collapse;
            }
            table, th, td {
                border: 1px solid black;
            }
            th, td {
                padding: 8px;
                text-align: left;
            }
            th {
                background-color: #f2f2f2;
            }
        </style>
    </head>
    <body>"
    
    return $htmltop
}

function Export-HTMLReport {
    param (
        [array] $matches,
        [array] $onlyInLeft,
        [array] $onlyInRight,
        [string] $outputFile
    )

    if (Test-Path -Path .\htmltop.txt) {$html = Get-Content .\htmltop.txt}
    else {
        $html = Get-DefaultHTML
    }

    $html += CreateHTMLSection -Title $UserMessages.correctOnboardMessage -Records $matches -IncludeProperties $true
    $html += CreateHTMLSection -Title $UserMessages.azureOnboardOnly -Records $onlyInLeft -TSmsg $UserMessages.azureTShootMessage -TSURL $UserMessages.azureTShootURL
    $html += CreateHTMLSection -Title $UserMessages.mdeOnboardOnly -Records $onlyInRight -TSmsg $UserMessages.mdeTShootMsg -TSURL $UserMessages.mdeTShootURL

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

    if (($TenantId.length -gt 0) -And ($ClientId.length -gt 0) -And ($AppSecret.length -gt 0)){
        $MDEAccessToken = Get-MDEAccessToken -TenantId $TenantId -ClientId $ClientId -AppSecret $AppSecret
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
        }
    }

    Write-Host $UserMessages.mainMidpointMessage -ForegroundColor Green # Show the midpoint message and display it in green as a marker of success

    if ($MDEAccessToken.length -gt 0){
        $MDEmachines = Get-MDEMachines $MDEAccessToken # Get the machines from Defender for Endpoint
        $MDEServers = Invoke_MDEMachinesProcessing -MDEmachines $MDEmachines # Process the machines from Defender for Endpoint
    }

    $outputFile = "DFSCheck-" + (Get-Date).ToString("yyyyMMddHHmmss") + ".html" # Generate the output file name

    if (($DefenderForCloudServers.length -gt 0) -and ($MDEServers.length -gt 0)){ # We need at least 1 server in both sides to compare

        $MachIDmatches, $MachIDonlyInMDC, $MachIDonlyInMDE = Compare-Lists-ByMachID -DefenderForCloudServers $DefenderForCloudServers -MDEServers $MDEServers # Compare the lists
        #Namematches, $NameonlyInLeft, $NameonlyInRight = Compare-Lists-ByName -DefenderForCloudServers $DefenderForCloudServers -MDEServers $MDEServers # Compare the lists

        Export-HTMLReport -matches $MachIDmatches -onlyInLeft $MachIDonlyInMDC -onlyInRight $MachIDonlyInMDE -outputFile $outputFile # Generate the HTML report
    }
    else { # We will generate the report having only the list where servers were found
        if ($DefenderForCloudServers.length -eq 0){
            Export-HTMLReport -matches $null -onlyInLeft $null -onlyInRight $MDEServers -outputFile $outputFile # Generate the HTML report
        }
        else {
            Export-HTMLReport -matches $null -onlyInLeft $DefenderForCloudServers -onlyInRight $null -outputFile $outputFile # Generate the HTML report
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