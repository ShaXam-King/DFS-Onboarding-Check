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
azureResourceGroupsStart = Retrieving Resource Groups for Subscription:
azureResourceGroupNotFound = Unable to retrieve resources from Resource Group
azureGetVirtualMachinesFailed = Failed to get Virtual Machines
azureGetVirtualMachineScaleSetsFailed = Failed to get Virtual Machine Scale Sets
azureGetArcMachinesFailed = Failed to get Arc Machines
azureSubscriptionChoiceMsg1 = Choosing Y will process only current subscription in logged-in context
azureSubscriptionChoiceMsg2 = Choosing N will prompt for a choice of All or a list of subscriptions to process
azureSubChoiceYN = Use only this subscription to compare onboarded servers? (Y/N)
azureSubChoiceAll = Process All Subscriptions (A) or Choose individual subscriptions (C)
azureSubChoiceNums = Provide a comma-separated list of subscription numbers (e.g. 1,3,4)
azureSubInvalidInput = Invalid input. Processing all associated subscriptions.
processMachinesStart = Processing (setting or reading) pricing configuration for VM 
processMachinesError = Failed to get pricing configuration for VM
mdeGetMachinesTokenSuccess = Retrieved Graph API for MDE machines token successfully.
mdeGetMachinesTokenFailed = Failed to acquire token to MDE Endpoint - Check App Registration
mdeGetMachinesFailed = Failed to retrieve machines from Defender for Endpoint
mainError = An error occurred during the execution of the script.
mainMidpointMessage = Defender for Servers processing complete.  Starting Defender for Endpoint processing.
mainAzureMachinesCountMsg = Total Defender For Servers inventoried servers found
mainMDETotalCount = Total Defender for Endpoint onboarded devices
mainMatchByIDMsg = Devices have matched by Machine ID
mainMatchByNameMsg = Devices matched by Name
mainMDEUnmatchedMsg = Servers onboarded to MDE not in Defender for Servers inventory
mainMDCUnmatchedMsg = Servers in Defender for Servers inventory not onboarded to MDE
mainMDEComplete = MDE device list access complete - Moving to comparison process
mainNoCompareMsg = A list has no entries - no comparison attempted
azureTShootMessage = Check Defender for Cloud MDE Onboarding Configuration
azureTShootURL = https://learn.microsoft.com/en-us/azure/defender-for-cloud/enable-defender-for-endpoint
mdeTShootMsg = Check MDE Direct Onboarding Configuration
mdeTShootURL = https://learn.microsoft.com/en-us/azure/defender-for-cloud/onboard-machines-with-defender-for-endpoint
NameMatchOnboardMessage = Servers Onboarded Having Matched Names
NameTShootMessage = Servers have full Defender for Servers functionality but were not onboarded by the service - Check DFS Onboarding Config
processNoRecordsMessage = No issues found
correctOnboardMessage = Servers Correctly Onboarded
correctOnboardTShootMsg = Servers have full DFS functionality with correct onboarding - Well done!
azureOnboardOnly = Servers Onboarded To Defender for Servers (Azure) Only
mdeOnboardOnly = Servers Onboarded To Defender For Endpoint Only
'@