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
azureSubscriptionContextNotFound = Azure Context not found
azureSubscriptionCountextFound = Azure Context found
azureSubscriptionNotFound = Unable to find an Azure Subscription with the signed-in account
azureResourceGroupsStart = Retrieveing Resource Groups for Subscription:
azureResourceGroupNotFound = Unable to retrieve resources from Resource Group
azureGetVirtualMachinesFailed = Failed to get Virtual Machines
azureGetVirtualMachineScaleSetsFailed = Failed to get Virtual Machine Scale Sets
azureGetArcMachinesFailed = Failed to get Arc Machines
processMachinesStart = Processing (setting or reading) pricing configuration for VM 
processMachinesError = Failed to get pricing configuration for VM
mdeGetMachinesTokenSuccess = Retrieved Graph API for MDE machines token successfully.
mdeGetMachinesTokenFailed = Failed to acquire token to MDE Endpoint - Check App Registration
mdeGetMachinesFailed = Failed to retrieve machines from Defender for Endpoint
mainError = An error occurred during the execution of the script.
mainMidpointMessage = Defender for Servers processing complete.  Starting Defender for Endpoint processing.
'@