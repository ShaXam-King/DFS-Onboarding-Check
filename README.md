# Defender for Server Onboarding Check Tool

## Setup and Usage Instructions

### Introduction
The Defender for Server Onboarding Check Tool is a PowerShell script that will connect to Defender for Cloud in Azure, query Defender for Server to generate a list of onboarded servers, query Defender for Endpoint returning the list of onboarded servers, and create a reconciliation of the two lists in an HTML file format.

### Requirements and Set Up Steps

#### Prerequisites
- PowerShell 7 is recommended but PowerShell 5 or greater is required.
- Access to query the Azure subscription hosting Defender for Cloud as well as any subscriptions where onboarded server objects may exist.
- As a one-time setup step, permission to create an App Registration in the Entra ID instance connected to the Defender for Endpoint service. This includes the permission to delegate Graph permissions to the Defender XDR endpoint.
- Endpoint permission to run PowerShell scripts and create output files.
- Permissions in the PowerShell session to install PowerShell modules if they are not yet installed. Pre-installation of Az.Accounts and Az.Resources is highly recommended along with running the script with standard (non-elevated) local permissions.

#### Graph Endpoint App Registration
1. **Create App Registration**: In the Entra ID Console, in the App Registrations panel, create a New registration specifically named “ReadMDEDevices”.
2. In the ReadMDEDevices configuration settings, navigate to Certificates & secrets, and create a New client secret. Provide an appropriate name for the secret. Set a lifetime value for the new secret. Recommendation: 90 days. **IMPORTANT**: copy the new secret value immediately and store it in a secure location. As soon as this panel is closed there will be no way to retrieve the secret. **REMEMBER**: protect the secret and change it whenever possible. **NOTE**: if the tool will only be run once then the App registration can, and should, be removed when the check is complete.
3. Next, navigate to API permissions. Choose Add a permission, switch to the APIs my organization uses tab, click on the search window and type “WindowsDefender”, and select WindowsDefenderATP from the list. Choose Application permissions. In the search box on the resulting panel type “machine” and select only the “Machine.Read.All” permission. Click the Add Permissions box. Lastly, Click the Grant admin consent for {your organization} link. Close out of the ReadMDEDevices app registration.
4. In the App registrations pane, copy the Application (client) ID for the ReadMDEDevices registration.
5. Change to the Overview of the Entra ID tenant and copy the Tenant ID – keeping it with the App ID and the new app secret.

### Script Components and Associated Files
The onboarding check tool can be accessed from GitHub. In addition to the PowerShell script, the following files and folders are recommended, but not required, to run the tool:
- `.\Check-DFSOnboarding.ps1`
- `.\htmltop.txt`
- `.\en-us\Check-DFSOnboarding.psd1`
- `.\fr-ca\Check-DFSOnboarding.psd1`
- Note: other language files may be included as required

### Launching the Script

#### Set Up Home Folder
Create a folder on the Windows file system to host the script files and any output files that are generated.

#### Launch PowerShell
Open PowerShell command session and change the current directory to the new script home folder.

#### Running the Script
Execute the script by typing the following command:
```powershell
.\Check-DFSOnboarding.ps1 -TenantId {TenantID} -ClientId {ClientID} -AppSecret {YourSecret}
```
The script will perform setup steps and check for, and assure, the installation of required PowerShell modules. You will be prompted for authentication to Azure. Sign in with an account having read access to Azure servers and Defender for Cloud inventory. Next, the script will prompt for the subscription where Defender for Cloud is hosted. The first prompt will suggest the Subscription in your current Azure sign-in context. Choosing “Y” will continue to the onboarding check. Choosing “N” to the above prompt will result in a printed list of subscription names and IDs associated with the current sign-in. Multiple Subscriptions can be chosen by typing a comma-separated list of the chosen Subscriptions and pressing Enter. The script will iterate through all chosen Subscriptions.

### Description of the Output

#### Output Overview
The script creates an HTML file in the current folder (i.e., the home folder) and will also launch the file with the default browser. The HTML file is unique to the data and time the tool was run enabling comparison to previous or future runs of the tool as needed.

#### Interpreting the Output
The HTML file contains 3 sections:
1. The top section lists servers that are onboarded to both Defender for Servers and Defender for Endpoint services where each object has the ID of the device in Defender for Servers. The presence of this attribute in Defender for Endpoint indicates correct onboarding and that the two services are connected for each individual server.
2. The second section lists servers that only exist in Defender for Cloud and do not match a device in Defender for Endpoint.
3. The third section lists servers that are onboarded to Defender for Endpoint and are not present in Defender for Servers. In the case where a Defender for Endpoint for Server license has been purchased for this server then this may be a correctly configured state.

The presence of objects in the latter two sections indicates some investigation and reconfiguration may be required. When a server is only onboarded to Defender for Servers the server owner is missing the Operating System protection that is an important component of Defender for Servers. Likewise, a Server only onboarded to Defender for Endpoint is missing key threat indicators and surface-area analysis that are available via Azure Policy and other Azure features. If Plan 2 of Defender for Servers is desired then the server owner is missing very key elements of the platform like Just-in-time access, File integrity monitoring, event log ingestion, and others! From a licensing compliance standpoint, the presence in Defender for Servers is the means for the license to be counted and charged. Consult Microsoft licensing guidelines for details. While per-hour billing is recommended, the hourly charge does not apply when a Defender for Endpoint for Server license has been purchased. The MDE for Server license is only intended for MDE onboarded servers and does not include Defender for Cloud features.

### Cleanup Steps
If the tool will be leveraged infrequently it is recommended to perform cleanup of the one-time setup steps:
- Delete the App Registration in Entra ID. (The Client ID and App Secret will be invalidated at this point)
- Delete the script and all associated files from the Windows devices where it was hosted.
- If the tool is automated or run often, cleanup of output files should be part of the maintenance and upkeep.

### Troubleshooting
- **Azure Processing**: If there are issues accessing Subscriptions or Resource Groups, re-check proper delegation of permissions in Azure RBAC.
- **Azure Access Token**: If there are issues with the Azure Access Token, assure you can reach the Azure endpoints and be sure that the tool is run within a reasonable amount of time from the time of authentication.
- **MS Graph Access Token**: If there are issues generating the Access token re-check the App Registration, tenant ID, Client ID.
- **MS Graph Access Token**: If there are issues accessing the MDE (WindowsDefenderATP) endpoint, check the app secret and that the full delegation of permissions has been completed in the App registration. Assure that Machine.Read.All is granted in the App Registration.
- **Missing files**: The script will run without associated files but will be limited to English and the HTML output will be simple black on white background.

### Customization and Internationalization
The `htmltop.txt` file contains a very simple setup for an HTML file. The file contains a simplified Style section to add a small amount of flair to the output. When the file is present in the home folder the HTML output is driven by the content in this file. The `htmltop.txt` file can be edited to add additional sections at the top of the output file, hyperlinks to pictures, more advanced Style directives, or even the ability to leverage a separate CSS file if desired. The script is set up to provide messaging and output in local languages. Additional languages can be supported by creating a language-specific folder in the home folder and adding a `Check-DFSOnboarding.psd1` file with translated messaging.
```
