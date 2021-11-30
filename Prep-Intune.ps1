#region Description
<#     
       .NOTES
       ==============================================================================
       Created on:         2021/09/08 
       Created by:         Drago Petrovic | Dominic Manning
       Organization:       MSB365.blog
       Filename:           Prep-Intune.ps1
       Current version:    V1.00     

       Find us on:
             * Website:         https://www.msb365.blog
             * Technet:         https://social.technet.microsoft.com/Profile/MSB365
             * LinkedIn:        https://www.linkedin.com/in/drago-petrovic/
             * MVP Profile:     https://mvp.microsoft.com/de-de/PublicProfile/5003446
       ==============================================================================

       .DESCRIPTION
       This script can be executed without prior customisation.
       This script is used to create on-premise and Azure users and groups so that an Intune configuration can be standardised.
       All variables that are required are queried by the script.
       This script creates the following elements:
            - On-premise default user
            - Azure admin user with the onmicrosoft domain and the Intune administrator authorisation
            - On-premise groups for Intune administration and licence assignment
            - Dynamic Azure AD groups for device assignment. (Lenovo, HP, Surface and Intel)
            - Dynamic Azure AD group for Autopilot Devices.            
       

       .NOTES
       The following PowerShell modules are required:
            - MSOnline (Automatic check in the script. Module will be installed if not available)
            - ActiveDirectory (Automatic check in the script. Module will be installed if not available)
            - GroupPolicy (Automatic check in the script. Module will be installed if not available)
            - AzureAD (Automatic check in the script. Module will be installed if not available)
            - AzureADPreview (Automatic check in the script. Module will be installed if not available)
            - AzureADLicensing (Automatic check in the script. Module will be installed if not available)
        
        The executing account needs following permissions on-premise:
            - Create Active Directory groups
            - Create Active Directory Organizational Units
            - Create Active Directory Group Policy Objects
        
        The executing account needs following permissions in AzureAD:
            - Create groups
            - Assign licenses




       .EXAMPLE
       .\Prep-Intune.ps1 
             

       .COPYRIGHT
       Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
       to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
       and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

       The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

       THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
       FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
       WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
       ===========================================================================
       .CHANGE LOG
             V0.10, 2021/09/08 - DrPe - Initial version
             V0.20, 2021/09/13 - DrPe - New dynamic Group for Dell devices added
             V0.21, 2021/09/13 - DrPe - Version information added for the Script start added
             V0.30, 2021/09/14 - DrPe - Modified License Groups to be created, configured Azure AD sync
             V0.40, 2021/09/14 - DrPe - Added M365 Licensing module and assigning main licenses
             V0.50, 2021/10/26 - DrPe - Added the creating and linking of GPO's for MDM enrollment and AutoPilot
             V0.60, 2021/10/27 - DoMa - Added functions "write-log" and "checkModule"
             V0.70, 2021/10/28 - DoMa - Enhanced error handling and logging
             V0.80, 2021/11/09 - DoMa - Enhanced error handling. Tables for groups
             V0.90, 2021/11/09 - DoMa - Div. enhancements. Tables for license assignments
			 V0.91, 2021/11/25 - DrPe - Bugfixing: Create License Groups
			 V0.92, 2021/11/25 - DrPe - Bugfixing: Configure GPO's
			 V0.93, 2021/11/25 - DrPe - Bugfixing: AADSync Module recognition
			 V0.94, 2021/11/25 - DrPe - Bugfixing: Creating dynamic Groups on Azure
			 V0.95, 2021/11/25 - DoMa - Bugfixing: License assignments
             V1.00, 2021/12/01 - DrPe - Finalising "Go Live" Version of the Intune preperation Script
			 




--- keep it simple, but significant ---


--- by MSB365 Blog ---

#>
#endregion

#region functions

#check for module function
Function CheckModule($modulename){
    #Check if module is already imported
    $LoadedModule = Get-Module -Name $modulename
    if ($LoadedModule -ne $null) {
        Write-Host "$modulename Module is installed and loaded" -ForegroundColor Green
        Write-Log -type SUCCESS -Message "$modulename Module is installed and loaded"
        Return 0
    }Elseif (
        #Check if module is available for import
        Get-Module -ListAvailable -Name $modulename
        ) {
        Write-Log -type SUCCESS -Message "$modulename Module is installed"
    } 
    else {
        #if module is not installed, install it for the current user
        Write-Log -type WARNING -Message "$modulename Module not Installed. Installing module in user scope now........."
            try {
                Install-Module -Name $modulename -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                Write-Log -type SUCCESS -Message "$modulename Module was successfully installed"
            }
            catch{
                Write-Log -Type ERROR -Message "Module $modulename could not be installed. $_"
                throw $_
                Return 1
            }
    }
    #import the module
    if ($LoadedModule -eq $null) {
        Try {
            Import-Module $modulename -ErrorAction stop
            Write-Log -type SUCCESS -Message "$modulename Module imported"
            Return 0
        }catch{
            Write-Log -Type ERROR -Message "Module $modulename could not be imported. $_"
            throw $_
            Return 2
        }
        
    }

}

#Write Log function
function Write-Log
{
    Param(
        [ValidateSet("INFO",“SUCCESS”,”WARNING”,”ERROR”)]
        [String]
        $type
    ,
        [STRING]
        $Message
    ,
        [SWITCH]
        $logOnly
    )
    Process
    {
        if (!(Test-path $log)){
            "Date       " + "Time     " + "Status  " + "Message" | Out-File $Log -Append
        }
        switch ($type){
            INFO {$spacer = "    "}
            ERROR {$spacer = "   "}
            Default {$spacer = " "}
        }
        (Get-Date -Format G) + " " + $type + $spacer + $Message | Out-File $Log -Append

        if (!$logonly.IsPresent)
        {
            Switch ($type){
                INFO {Write-host (Get-Date -Format G) $type $Message -ForegroundColor Magenta }
                SUCCESS {Write-host (Get-Date -Format G) $type $Message -ForegroundColor Green }
                WARNING {Write-host (Get-Date -Format G) $type $Message -ForegroundColor Yellow }
                ERROR {Write-host (Get-Date -Format G) $type $Message -ForegroundColor Red }
            }
            
        }
    }
	
}
#endregion

#region Set variables
write-host "PowerShell Script for Intune preparation by Drago Petrovic" -ForegroundColor White -BackgroundColor Magenta
Start-Sleep -s 2
write-host "Script version V1.00" -ForegroundColor White -BackgroundColor Magenta
Start-Sleep -s 3
write-host "Before we start, we need some core information:" -ForegroundColor Magenta
Start-Sleep -s 3
$domain = $(Write-Host "Enter the main Domain Name. Example: " -NoNewLine) + $(Write-Host """" -NoNewline) +$(Write-Host "contoso.com" -ForegroundColor Yellow -NoNewline; Read-Host """")
$OUPath = $(Write-Host "Enter the OU Path where the SVC User should be created. Example: " -NoNewLine) + $(Write-Host """" -NoNewline) + $(Write-Host "OU=Users-Standard,OU=Users,OU=MSB01,DC=contoso,DC=local" -ForegroundColor Yellow -NoNewline; Read-Host """")
$MDMOU = $(Write-Host "Enter the OU Path where the Device MDM GPO's should be created. Example: " -NoNewLine) + $(Write-Host """" -NoNewline) + $(Write-Host "OU=Users-Standard,OU=Users,OU=MSB01,DC=contoso,DC=local" -ForegroundColor Yellow -NoNewline; Read-Host """")
$GroupOUpath1 = $(Write-Host "Enter the OU Path where the Licensing Groups should be created. Example: " -NoNewLine) + $(Write-Host """" -NoNewline)  + $(Write-Host "OU=Licenses,OU=Groups,OU=MSB01,DC=contoso,DC=local" -ForegroundColor Yellow -NoNewline; Read-Host """")
$GroupOUpath2 = $(Write-Host "Enter the OU Path where the Intune Groups should be created. Example: " -NoNewLine) + $(Write-Host """" -NoNewline) + $(Write-Host "OU=Intune,OU=Groups,OU=MSB01,DC=contoso,DC=local" -ForegroundColor Yellow -NoNewline; Read-Host """")
$adomain = $(Write-Host "Enter the Onmicrosoft Domain. Example: " -NoNewLine) + $(Write-Host """" -NoNewline) + $(Write-Host "contoso.onmicrosoft.com" -ForegroundColor Yellow -NoNewline; Read-Host """") 
$TenantID = $(Write-Host "Enter the Azure Tenant ID. Example: " -NoNewLine) + $(Write-Host """" -NoNewline) + $(Write-Host "e0d6g9fb-01b3-4bd6-M365-7a9795a023f7f" -ForegroundColor Yellow -NoNewline; Read-Host """") 
write-host "All variables are set!" -ForegroundColor Green
Start-Sleep -s 3
#endregion

#region create Log file for logging
$mdmdirectory = "C:\MDM\"
If ((Test-Path -Path $mdmdirectory) -eq $false)
{
    try{
        New-Item -Path $mdmdirectory -ItemType directory -ErrorAction Stop
    }catch{
        throw "Could not create folder ""$mdmdirectory"" for logs. " + $_
        Return
    }
        
}
$timestamp = get-date -Format yyyy-MM-dd_HHmmss
$Log = “C:\MDM\CreateGlobalSecurityGroups_” + $timestamp + “.log”
$ErrorActionPreference=”SilentlyContinue”

Start-Sleep -s 1
#endregion

#region Create on-prem account and groups

#Check if module ActiveDirectory is installed
$admodule = CheckModule ActiveDirectory
if ($admodule -ne 0){
    Write-Log -type ERROR -Message "Script execution aborted"
    return
}


#########################################################################################################################################################################
#Create AD User for DWP
Write-Log -Message "Creating new on-premise Active Directory Account - SVC_DW_USER" -type INFO
try {
    New-ADUser -Name "SVC_DW_USER" -GivenName "IT" -Surname "Testuser" -SamAccountName "SVC_DW_USER" -UserPrincipalName "SVC_DW_USER@$domain" -Path $OUPath -AccountPassword(Read-Host -AsSecureString "Input Password") -Enabled $true -ErrorAction Stop
    Write-Log -Message "Account created" -type SUCCESS
}catch{
    Write-Log -Type ERROR -Message "AD account ""SVC_DW_USER"" could not be created. $_" -logOnly
    #throw "AD account could not be created " + $_
    return
}
write-host "Done!" -ForegroundColor Green
Start-Sleep -s 3

#########################################################################################################################################################################
#Create Active Directory Groups
Write-Log -type INFO -Message "Creating new on-premise Active Directory Security Groups for Licensing"

#Create hashtable for group names and description
$grouptableIntuneL = @{
"_Licensing_Teams_PhoneSystems" = "Assigns the phone system License"
"_Licensing_M365_E3_Base" = "Assigns Microsoft 365 E3 License with the default apps"
"_Licensing_O365_E3_Base" = "Assigns Office 365 E3 License with the default apps"
"_Licensing_M365_E3_exclEXO" = "Assigns Microsoft 365 E3 License without Exchange online option"
"_Licensing_O365_E3_exclEXO" = "Assigns Office 365 E3 License without Exchange online option"
"_Licensing_EMS_E3_Base" = "Assigns the ENTERPRISE MOBILITY + SECURITY E3 License"
"_Licensing_EMS_E5_Base" = "Assigns the ENTERPRISE MOBILITY + SECURITY E5 License"
"_Licensing_O365_E5_Base" = "Assigns Office 365 E5 License with the default apps"
"_Licensing_M365_BP_Base" = "Assigns Microsoft 365 Business Premium License with the default apps"
"_Licensing_ATP_P1_Base" = "Assigns Microsoft Defender for Office 365 (Plan 1) License"
"_Licensing_M365_E5_Base" = "Assigns Microsoft 365 E5 License with the default apps"
"_Licensing_Win365_Business_Basic" = "Assigns Windows 365 Business Basic License with the default apps"
"_Licensing_Win365_Business_Standard" = "Assigns Windows 365 Business Standard License with the default apps"
"_Licensing_Win365_Business_Premium" = "Assigns Windows 365 Business Premium License with the default apps"
"_Licensing_Win365_Enterprise_Basic" = "Assigns Windows 365 Enterprise Basic License with the default apps"
"_Licensing_Win365_Enterprise_Standard" = "Assigns Windows 365 Enterprise Standard License with the default apps"
"_Licensing_Win365_Enterprise_Premium" = "Assigns Windows 365 Enterprise Premium License with the default apps"
}


$grpsnotcreatedInt = @()
$grouptableIntuneL.GetEnumerator().ForEach({
    try {
        $grpname = $_.key
        New-ADGroup -Name $_.key –groupscope Global -Path $GroupOUpath1 -Description $_.Value -ErrorAction Stop
        Write-Host "Created AD group $grpname"
    }catch{
        Write-Log -Type ERROR -Message "AD group $grpname could not be created. $_" -logOnly
        Write-Warning "Could not create AD group $grpname"
        $grpsnotcreatedInt += $grpname
    }
})


Start-Sleep -s 3
write-host "Done!" -ForegroundColor Green
Start-Sleep -s 1
Write-Host "Following groups were created:"
$grouptableIntuneL.GetEnumerator().where({ !$grpsnotcreatedInt.Contains($_.Key)}) | ft -HideTableHeaders
Start-Sleep -s 2


#########################################################################################################################################################################
Write-Log -type INFO -Message "Creating new on-premise Active Directory Security Groups for Intune"

#Create hashtable for group names and description
$grouptableIntune = @{
"Intune_PROD_BASE" = "Group for all Users that are managed by Intune - The base Software Group is automatically included"
"Intune_PROD_Update_R1" = "Assigned Windows Update Ring for Admins and Superuser"
"Intune_PROD_Update_R2" = "Assigned Windows Update Ring for Users"
"Intune_PROD_App_Adobe" = "Permission for the Application Adobe"
"Intune_PROD_App_CitrixReciver" = "Permission for the Application CitrixReciver"
"Intune_PROD_Windows365" = "Permission for the Application Windows365"
"Intune_PROD_BASE_MAM" = "Base configuration for Application management only (Windows without MDM)"
"Intune_PROD_OneDrive_KFM" = "Permission for OneDrive Modern Roming Profile"
"Intune_MOBILE_BASE" = "Group for all Users that are managed by Intune - Mobile Devices"
"Intune_MOBILE_BASE_MAM" = "Base configuration for Application management only (Android/Apple without MDM)"
"Intune_PROD_Pilot" = "Group for new App-, Configuration- etc. Testing with Pilot Users - Windows"
"Intune_MOBILE_Pilot" = "Group for new App-, Configuration- etc. Testing with Pilot Users - Mobile"
}


$grpsnotcreatedInt = @()
$grouptableIntune.GetEnumerator().ForEach({
    try {
        $grpname = $_.key
        New-ADGroup -Name $_.key –groupscope Global -Path $GroupOUpath2 -Description $_.Value -ErrorAction Stop
        Write-Host "Created AD group $grpname"
    }catch{
        Write-Log -Type ERROR -Message "AD group $grpname could not be created. $_" -logOnly
        Write-Warning "Could not create AD group $grpname"
        $grpsnotcreatedInt += $grpname
    }
})


Start-Sleep -s 3
write-host "Done!" -ForegroundColor Green
Start-Sleep -s 1
Write-Host "Following groups were created:"
$grouptableIntune.GetEnumerator().where({ !$grpsnotcreatedInt.Contains($_.Key)}) | ft -HideTableHeaders
Start-Sleep -s 2
write-host "NOTE: You need to configure the AAD Sync so that all created groups will be available in the Azure Active Directory!" -ForegroundColor Black -BackgroundColor Yellow
Start-Sleep -s 2
#endregion
#########################################################################################################################################################################

#region OUs and Group Policies
Write-Log -Message "Setting up GPO tasks for MDM..." -type INFO
#Check if GroupPolicy module is installed

if ((Get-Module GroupPolicy) -eq $null -and (Get-Module -ListAvailable GroupPolicy) -eq $null)
{
	Write-Log -type WARNING -Message 'Group Policy Management is not istalled'
	Write-Log -type INFO -Message 'Trying to install Group Policy Management feature'
	try
	{
		Install-WindowsFeature GPMC -ErrorAction Stop
	}
	catch
	{
		Write-Log -type ERROR -Message "Could not install Group Policy Management. $_"
		Write-Log -type ERROR -Message "Script execution aborted"
		Return
	}
}


Start-Sleep -s 2
# Create Organizational Unit for MDM enrolled and unmanaged Devices
Write-Log -Message "Creating Organizational Unit for MDM..." -type INFO
Start-Sleep -s 1


#store OU names to array
$intuneOUNames = @("Intune_Enrolled","Intune_Unmanaged","AutoPilotDomainJoin")
$intOUsCreated = @()

#create OUs
foreach ($ou in $intuneOUNames)
{
    try{
        $nOU = New-ADOrganizationalUnit -Name $ou -Path $MDMOU -ProtectedFromAccidentalDeletion $True -PassThru -ErrorAction Stop
        $intOUsCreated += $nOU.DistinguishedName
        Write-Log -type SUCCESS -Message "Created OU $ou"
    }catch{
        Write-Log -type ERROR -Message "Could not create OU $ou. $_"
    }
}


write-host "Done!" -ForegroundColor Green
Start-Sleep -s 3

# Create GPO for Intune enrolled Organizational Unit
# Create hashtable with GPO name and description
$intuneGPOs =@{
"Intune_SCP_Tenant_Information" = "Sets the Tenant ID and Tenant Name on Enduser Devices in the Registry"
"Intune_Automatic_MDM_enrollment" = "Sets the MDM enrollmend policy"
"Intune_Automatic_MDM_unenrollment" = "Disables the MDM enrollmend policy"
}


Write-Log -type INFO -Message "Creating empty GPO's for MDM..."
Start-Sleep -s 1
#create GPOs
$GPOsNotCreated =@()
$intuneGPOs.GetEnumerator().ForEach({
    try{
        $GPOName = $_.Key
        New-GPO -Name $GPOName -Comment $_.Value -ErrorAction Stop
    }catch{
        Write-Log -type ERROR -Message "Could not create GPO $GPOName. $_" 
        $GPOsNotCreated += $GPOName
    }
})


write-host "Done!" -ForegroundColor Green
Start-Sleep -s 1
Write-Host "Following OUs were created:"
$intuneGPOs.GetEnumerator().where({ !$GPOsNotCreated.Contains($_.Key)}) | ft -HideTableHeaders
Start-Sleep -s 3

# Set values for the GPOs
Write-Log -type INFO -Message "Setting values for MDM GPO's..."
Start-Sleep -s 1
try{
    Set-GPPrefRegistryValue -Name "Intune_SCP_Tenant_Information" -Context Computer -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD" -ValueName "TenantID" -Value $TenantID -Type String -Action Update -ErrorAction Stop
    Write-Log -type SUCCESS -Message "Set registry key Intune_SCP_Tenant_Information wit tenant ID" -logOnly
}catch{
    Write-Log -type ERROR -Message "could not set registry key Intune_SCP_Tenant_Information wit tenant ID. $_"
}
try{
    Set-GPPrefRegistryValue -Name "Intune_SCP_Tenant_Information" -Context Computer -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD" -ValueName "TenantName" -Value $adomain -Type String -Action Update -ErrorAction Stop
    Write-Log -type SUCCESS -Message "Set registry key Intune_SCP_Tenant_Information wit tenant name" -logOnly
}catch{
	Write-Log -type ERROR -Message "could not set registry key Intune_SCP_Tenant_Information wit tenant name. $_"
}
## Disable MDM Enrollment
try{
    Set-GPPrefRegistryValue -Name "Intune_Automatic_MDM_unenrollment" -Action Update -Context Computer -Key "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\MDM" -Type DWord -ValueName "AutoEnrollMDM" -Value 0 -ErrorAction Stop
    Write-Log -type SUCCESS -Message "Set registry key Intune_SCP_Tenant_Information wit tenant name" -logOnly
}catch{
	Write-Log -type ERROR -Message "could not set registry key HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\MDM --> DisableRegistration. $_"
}


Start-Sleep -s 1
## Enable MDM Enrollment
try{
    Set-GPPrefRegistryValue -Name "Intune_Automatic_MDM_enrollment" -Action Update -Context Computer -Key "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\MDM" -Type DWord -ValueName "AutoEnrollMDM" -Value 1 -ErrorAction Stop
    Set-GPPrefRegistryValue -Name "Intune_Automatic_MDM_enrollment" -Action Update -Context Computer -Key "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\MDM" -Type DWord -ValueName "UseAADCredentialType" -Value 1 -ErrorAction Stop
    Set-GPPrefRegistryValue -Name "Intune_Automatic_MDM_enrollment" -Context Computer -Key "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\MDM" -ValueName "MDMApplicationId" -Value "" -Type String -Action Update -ErrorAction Stop
    Write-Log -type SUCCESS -Message "Set registry key Intune_SCP_Tenant_Information wit tenant name" -logOnly
}catch{
	Write-Log -type ERROR -Message "could not set registry key HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\MDM --> DisableRegistration. $_"
}
Write-Log -type SUCCESS -Message "All registry keys were set"
write-host "Done!" -ForegroundColor Green
Start-Sleep -s 3



# Link GPO with Organizational Unit
Write-Log -Message "Linking GPO rules with Organizational Units..." -type INFO

#Set distinguished name for the OUs
$MDMOUplus = "OU=Intune_Enrolled,$MDMOU"
$MDMOU2plus = "OU=AutoPilotDomainJoin,$MDMOU"
$MDMOU3plus = "OU=Intune_Unmanaged,$MDMOU"

#create hashtable for gpo links (OU + GPO)
$GPOlinks = @{
   $MDMOUplus  = "Intune_Automatic_MDM_enrollment"
   $MDMOU2plus = "Intune_SCP_Tenant_Information"
   $MDMOU3plus = "Intune_Automatic_MDM_unenrollment"
}

#link the GPOs to OUs
foreach ($gpolink in $GPOlinks.GetEnumerator())
{
    try{
        $gpolinkname = $gpolink.Value
        New-GPLink -Name $gpolinkname -Target $gpolink.Key -ErrorAction Stop
        Write-Log -type SUCCESS -Message "Linked GPO $gpolinkname" -logOnly
    }catch{
		Write-Log -type ERROR -Message "Could not link GPO $gpolinkname. $_"
    }    
}

Write-Log -type SUCCESS -Message "All GPOs were linked"


write-host "Done!" -ForegroundColor Green
Start-Sleep -s 3
write-host "All GPO's for MDM are set!" -ForegroundColor Green
Start-Sleep -s 3
write-host "All on-prem tasks are done..." -ForegroundColor White -ForegroundColor Magenta
Start-Sleep -s 2
#endregion
#####################################################################################################################################
#region AAD Sync 
#Sync on-premise created groups to Azure Active Directory                                                                           
write-host "Preparing ADSync tasks..." -BackgroundColor Magenta
#check if AAD Sync is installed

write-host "Checking if $Folder exists..." -ForegroundColor White -ForegroundColor Magenta
sleep -Seconds 2 
$FolderExIsts = Test-Path 'C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync'

#If AADSync is not installed, offer the option to start the AADSync cycle on a remote machine
if ($FolderExIsts -eq $false)
{
	Write-Host "ADSync is not installed on this machine" -ForegroundColor Yellow
	$remoteAADSync = "Do you want to connect to a remote machine to start the AAD sync? [y/n] (default is no)"
	Switch ($remoteAADSync)
	{
		y { $AADSyncServer = Read-Host "Enter name of AADC server" }
		n { Write-Host "AAD Sync will not be started manually. You have to wait for the next sync cycle" -ForegroundColor Yellow }
		default{ Write-Host "AAD Sync will not be started manually. You have to wait for the next sync cycle" -ForegroundColor Yellow}
	}#if a server name was specified, try to start the sync on that machine
	if ($AADSyncServer -ne $null)
	{
		try
		{
			#establish remote session 
			$session = New-PSSession -ComputerName $AADSyncServer -ErrorAction Stop
			Write-Log -type INFO -Message "Syncing on-premise objects to Azure Active Directory..."
			#invoke commands to start the sync in remote session
			Invoke-Command -Session $session { Import-Module ADSync; Start-ADSyncSyncCycle -PolicyType Delta } -ErrorAction Stop
			Write-Log -type SUCCESS -Message "Sync started"
			sleep -s 30
			#wait till sync is completed
			Do
			{
				$aadsyncstatus = Invoke-Command -Session $session { Get-ADSyncConnectorRunStatus }
				sleep -s 6
			}
			until ($aadsyncstatus -eq $null)
			Write-Log -type SUCCESS -Message "Sync is completed."
			
			Remove-PSSession $session
		}
		catch
		{
			Write-Log -type WARNING -Message "Could not start AADSync. Objects may not be synced to AAD yet. $_"
		}
	}
}
Else
{
	#Start local AADSync
	write-host "Syncing on-premise objects to Azure Active Directory..." -ForegroundColor Magenta #
	Try
	{
		Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync" -ErrorAction Stop
		$aadsyncstatusinit = Get-ADSyncConnectorRunStatus
		if ($aadsyncstatusinit -ne $null)
		{
			Write-Log -type INFO -Message "AADSync currently already running. Waiting until it is finished."
			#wait till sync is completed
			Do
			{
				$aadsyncstatusinit = Get-ADSyncConnectorRunStatus
				sleep -s 15
			}
			until ($aadsyncstatusinit -eq $null)
		}
		Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop
		Write-Log -type SUCCESS -Message "Sync started"
		sleep -s 30
		#wait till sync is completed
		Do
		{
			$aadsyncstatus = Get-ADSyncConnectorRunStatus
			sleep -s 6
		}
		until ($aadsyncstatus -eq $null)
		Write-Log -type SUCCESS -Message "Sync is completed."
	}
	Catch
	{
		Write-Log -type WARNING -Message "Could not start AADSync. Objects may not be synced to AAD yet. $_"
	}
}


<# Old version
if (Test-Path -Path $Folder) {
    write-host "Path exists!" -ForegroundColor Green
} else {
    "Path doesn't exist."
}

Start-Sleep -s 1

if (Test-Path -Path $Folder) {
write-host "Checking if $Folder exists..." -ForegroundColor White -ForegroundColor Magenta
Start-Sleep -s 2
Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync" -Verbose
Start-Sleep -s 10                                                                                                                  
    write-host "Syncing on-premise objects to Azure Active Directory..." -ForegroundColor Magenta                                      
    Try {
            Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop
            sleep -s 30
            Do {
                $aadsyncstatus = Get-ADSyncConnectorRunStatus
                sleep -s 6
                } 
                until($aadsyncstatus -eq $null)
                write-host "Done!" -ForegroundColor Green
        }
        Catch{
        Write-Log -type WARNING -Message "Could not start AADSync. Objects may not be synced to AAD yet"
    }   
                    

} else {
Write-Host "ADSync is not installed on this machine" -ForegroundColor Yellow
Switch ($remoteAADSync) {
        y {$AADSyncServer = Read-Host "Enter name of AADC server"}
        n {"AAD Sync will not be started manually. You have to wait for the next sync cycle"}
        default{"AAD Sync will not be started manually. You have to wait for the next sync cycle"}
}
}#>
#endregion
#####################################################################################################################################
#region Create cloud only admin account
#####################################################################################################################################
write-host "Connectig to the Microsoft 365 Tenant" -ForegroundColor Magenta -NoNewline
write-host " - Please enter the credentials..." -ForegroundColor Yellow
$cloudCreds = Get-Credential
Start-Sleep -s 5
if (Get-Module -ListAvailable -Name MSOnline) {
    Write-Host "MSOnline Module Already Installed" -ForegroundColor Green
} 
else {
    Write-Host "MSOnline Module Not Installed. Installing........." -ForegroundColor Red
        Install-Module -Name MSOnline -AllowClobber -Force
    Write-Host "MSOnline Module Installed" -ForegroundColor Green
}
Import-Module MSOnline
Connect-MSOlService -Credential $cloudCreds
Start-Sleep -s 2

#########################################################################################################################################################################
#Create Azure AD (Admin) User for DWP
write-host "Creating new Azure Active Directory Account - SVC_DW_ADMIN" -ForegroundColor Magenta -NoNewline
write-host " - Please enter the credentials..." -ForegroundColor Yellow 
$pw = Read-Host "Enter a password for the new account" -AsSecureString
Start-Sleep -s 2

Write-Log -type INFO -Message "Creating AAD account for Intune admin"
Try{
    $DWPAdmin = New-MsolUser -DisplayName "SVC_DW_ADMIN" -FirstName IT -LastName IntuneAdmin -UserPrincipalName SVC_DW_ADMIN@$adomain -Password $pw -ErrorAction Stop
    Write-Log -type SUCCESS -Message "New user was created. UserPrincipalName: $($DWPAdmin.UserPrincipalname)"   
    write-host "Done!" -ForegroundColor Green 
}catch{
	Write-Log -type ERROR -Message "Could not create Intune admin AAD account. Aborting script execution. $_"
    $_
    Return
}


Start-Sleep -s 3
#endregion
#########################################################################################################################################################################
#region Assign AAD role
#Assign Intune Administrator Role to Admin Account
$dispName = $DWPAdmin.DisplayName
$roleName="Intune Administrator"
Write-Log -type INFO -Message "Assigning $rolename to account $dispName"
Start-Sleep -s 1
Try{
    Add-MsolRoleMember -RoleMemberEmailAddress $DWPAdmin.UserPrincipalName -RoleName $roleName -ErrorAction Stop
    Write-Log -type SUCCESS -Message "Role was assigned"
}catch{
	Write-Log -type ERROR -Message "Could not assign $role to account. $_"
    $_
}


Start-Sleep -s 3
#endregion
#########################################################################################################################################################################
#region Create Dynamic Azure Active Directory Groups
#Load Azure Active Directory PowerShell Module

write-host "Connectig Azure Active Directory" -ForegroundColor Magenta -NoNewline
#write-host " - Please enter the credentials..." -ForegroundColor Yellow 
Start-Sleep -s 5
if (Get-Module -ListAvailable -Name AzureADPreview) {
    Write-Host "AzureADPreview Module Already Installed" -ForegroundColor Green
} 
else {
    Write-Host "AzureADPreview Module Not Installed. Installing........." -ForegroundColor Red
        Install-Module -Name AzureADPreview -AllowClobber -Force
    Write-Host "AzureADPreview Module Installed" -ForegroundColor Green
}
Import-Module AzureADPreview
Connect-AzureAD -Credential $cloudCreds
Start-Sleep -s 2

#########################################################################################################################################################################
# Create Dynamic Azure Active Directory Group filtered to Devices
Write-Log -type INFO -Message "Creating Azure Active Directory dynamic Groups for Intune"

#create array for group info
$dyngroupArray1 = @{
    Surface = @{
        Name = "Microsoft Surface"
        Manufacturer = "Microsoft Corporation"
        MailNickName = "Surface"
        OSType = "Windows"

    }
    Lenovo = @{
        Name = "Lenovo"
        Manufacturer = "LENOVO"
        MailNickName = "Lenovo"
        OSType = "Windows"

    }
    HP = @{
        Name = "HP"
        Manufacturer = "HP","Hewlett-Packard"
        MailNickName = "HP"
        OSType = "Windows"

    }
     Intel = @{
        Name = "Intel"
        Manufacturer = "Intel"
        MailNickName = "Intel"
        OSType = "Windows"

    }
     Dell = @{
        Name = "Dell"
        Manufacturer = "Dell"
        MailNickName = "Dell"
        OSType = "Windows"

    }
}


foreach ($item in $dyngroupArray1.GetEnumerator()) {
    if ($dyngroupArray1[$item.Name].Manufacturer.GetType().UnderlyingSystemType.BaseType.name -eq "Array"){
        $manfactquery = @()
        foreach ($manf in $dyngroupArray1[$item.Name].Manufacturer)
        {
            $manfactquery += "(device.deviceManufacturer -match ""$manf"")"
        }

        $manfactqueryString = $manfactquery -join " or "

    }
    Else{
    $manf = $dyngroupArray1[$item.Name].Manufacturer
        $manfactqueryString = "(device.deviceManufacturer -match ""$manf"")"
    }
    $osType = $dyngroupArray1[$item.Name].OSType    

    #create membership rule based on info in array
    $MembershipRule = "$manfactqueryString and (device.deviceOSType -match ""$osType"")"
    #create display name of group
    $grpdisplayname = “Intune_Prod_Devices_$($dyngroupArray1[$item.Name].Name)”

    #create new dynamic group 
    try{
        New-AzureADMSGroup -Description “Dynamic Group for $($dyngroupArray1[$item.Name].Name) device specific configurations” -DisplayName $grpdisplayname -MailEnabled $false -GroupTypes “DynamicMembership” -MembershipRule $MembershipRule -MembershipRuleProcessingState “On” -SecurityEnabled $true -MailNickname $dyngroupArray1[$item.Name].MailNickName -ErrorAction Stop

    Write-Log -type SUCCESS -Message "Group $grpdisplayname created"

    }catch{
        Write-Log -type ERROR -Message "Could not create group $grpdisplayname. " + $_
    }

}


#create dynamic group for autopilot devices
try{
    New-AzureADMSGroup -Description “Group for Autopilot devices deployed with intune” -DisplayName “Intune_Prod_Autopilot_Devices” -MailEnabled $false -GroupTypes “DynamicMembership” -MembershipRule '(device.devicePhysicalIDs -any _ -contains "[ZTDId]")' -MembershipRuleProcessingState “On” -SecurityEnabled $true -MailNickname “AutoPilotDevices” -ErrorAction Stop
    Write-Log -type SUCCESS -Message "Group Intune_Prod_Autopilot_Devices created"
}catch{
    Write-Log -type ERROR -Message "Could not create group Intune_Prod_Autopilot_Devices. " + $_
}

Start-Sleep -s 3


#Get Microsoft Graph API for Intune


#endregion
#########################################################################################################################################################################
#region Assign licenses to groupss
#Assign M365 Licenses to Azure Active Directory Groups
write-host "Assigning Licenses to synced Azure Groups..." -ForegroundColor Magenta


#####################################################################################################################################
<# LICENSE CODE OVERVIEW                                                                                                            #
MICROSOFT 365 BUSINESS PREMIUM                        SPB                                                                           #
MICROSOFT 365 E3                                             SPE_E3                                                                 #
MICROSOFT 365 E5                                             SPE_E5                                                                 #
Microsoft Defender for Office 365 (Plan 1)     ATP_ENTERPRISE                                                                       #
Office 365 E3                                                ENTERPRISEPACK                                                         #
Office 365 E5                                                ENTERPRISEPREMIUM                                                      #
ENTERPRISE MOBILITY + SECURITY E3              EMS                                                                                  #
ENTERPRISE MOBILITY + SECURITY E5              EMSPREMIUM                                                                           #
MICROSOFT 365 PHONE SYSTEM                            MCOEV                                                                         #
                                                                                                                                    #
-----                                                                                                                               #
More information: https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference         #
-----                                                                                                                               #
                                                                                                                                    #
Customer:                                                                                                                           #
_Licensing_Teams_PhoneSystems           reseller-account:MCOEV                                                                      #
_Licensing_M365_E3_Base                        reseller-account:SPE_E3                                                              #
_Licensing_O365_E3_Base                        reseller-account:ENTERPRISEPACK                                                      #
_Licensing_M365_E3_exclEXO                                                                                                          #
_Licensing_O365_E3_exclEXO                                                                                                          #
_Licensing_EMS_E3_Base                         reseller-account:EMS                                                                 #
_Licensing_EMS_E5_Base                         reseller-account:EMSPREMIUM                                                          #
_Licensing_O365_E5_Base                        reseller-account:ENTERPRISEPREMIUM                                                   #
_Licensing_M365_BP_Base                        reseller-account:SPB                                                                 #
_Licensing_ATP_P1_Base                         reseller-account:ATP_ENTERPRISE                                                      #
_Licensing_M365_E5_Base                        reseller-account:SPE_E5                                                              #
#>                                                                                                                                  #
#####################################################################################################################################

write-host "Connectig to the Microsoft 365 License Service Module" -ForegroundColor Magenta -NoNewline

#check if module is installed
$aadlicmodule = CheckModule AzureADLicensing
if ($aadlicmodule -ne 0){
    Write-Log -type ERROR -Message "Script execution aborted"
    return
}


#connect to Azure
try{
    Connect-AzAccount -Credential $cloudCreds
    Write-Log -type SUCCESS -Message "Connected to Azure AD through ""Connect-AzACcount""" -logOnly
}catch{
	Write-Log -type ERROR -Message "Could not connect to AzureAD through ""Connect AzACcount""" + $_
	Write-Log -type ERROR -Message "Script execution aborted"
	return
}

#Getting created License Groups
$licgrpscreated = $grouptableIntuneL.GetEnumerator().where({ !$grpsnotcreatedInt.Contains($_.Key) }) | ft -HideTableHeaders

#getting available licenses
Write-Log -type INFO -Message 'Getting available licenses'
$SKUs = Get-AADLicenseSku

#create mapping table for licenses and groups
$groupsAndLicenses = @{
"_Licensing_Teams_PhoneSystems" = ($SKUs | where { $_.AccountSKuID -like "*:MCOEV" }).AccountSkuID #"reseller-account:MCOEV"
"_Licensing_M365_E3_Base" = ($SKUs | where { $_.AccountSKuID -like "*:SPE_E3" }).AccountSkuID #"reseller-account:SPE_E3"
"_Licensing_O365_E3_Base" = ($SKUs | where { $_.AccountSKuID -like "*:ENTERPRISEPACK" }).AccountSkuID #"reseller-account:ENTERPRISEPACK"
"_Licensing_M365_E3_exclEXO" = ($SKUs | where { $_.AccountSKuID -like "*:SPE_E3" }).AccountSkuID #"reseller-account:SPE_E3" # --> EXO exclusion done through disabled service plans
"_Licensing_O365_E3_exclEXO" = ($SKUs | where { $_.AccountSKuID -like "*:ENTERPRISEPACK" }).AccountSkuID #"reseller-account:ENTERPRISEPACK" # --> EXO exclusion done through disabled service plans
"_Licensing_EMS_E3_Base" = ($SKUs | where { $_.AccountSKuID -like "*:EMS" }).AccountSkuID #"reseller-account:EMS"
"_Licensing_EMS_E5_Base" = ($SKUs | where { $_.AccountSKuID -like "*:EMSPREMIUM" }).AccountSkuID #"reseller-account:EMSPREMIUM"
"_Licensing_O365_E5_Base" = ($SKUs | where { $_.AccountSKuID -like "*:ENTERPRISEPREMIUM" }).AccountSkuID #"reseller-account:ENTERPRISEPREMIUM"
"_Licensing_M365_BP_Base" = ($SKUs | where { $_.AccountSKuID -like "*:SPB" }).AccountSkuID #"reseller-account:SPB"
"_Licensing_ATP_P1_Base" = ($SKUs | where { $_.AccountSKuID -like "*:ATP_ENTERPRISE" }).AccountSkuID #"reseller-account:ATP_ENTERPRISE"
"_Licensing_M365_E5_Base" = ($SKUs | where { $_.AccountSKuID -like "*:SPE_E5" }).AccountSkuID #"reseller-account:SPE_E5"
}

Write-Log -type INFO -Message 'Done getting licenses'

$licsnotFound = ($groupsAndLicenses.GetEnumerator().Where({ $_.Value -eq $null })).name
if ($licsnotFound.Count > 0)
{
	Write-Log -type WARNING -Message 'licenses for the following groups were not found: ' + $licsnotFound -join ', '
}
$groupsAndIds = @{}

#create mapping table for groups and IDs
foreach ($item in $grouptableIntuneL.getEnumerator()){
    $ID = (Get-MsolGroup | where-object { $_.DisplayName -eq $item.Key}).ObjectID
    $groupsAndIds.add($item.Key,$ID)
}

#Assign licenses to groups
Write-Log -type INFO -Message "Assigning available licenses to groups..."
foreach ($i in $groupsAndIds.GetEnumerator()){
    #get license to assign from the mapping table $groupsAndLicenses
	$lic = $groupsAndLicenses.$($i.key)
	if ($lic -ne $null)
	{
		try
		{
			if ($i.key.EndsWith("exclEXO"))
			{
				#Assignment with Exchange Online Plan exclusion
				Add-AADGroupLicenseAssignment -groupId $i.value -accountSkuId $lic -disabledServicePlans @("EXCHANGE_S_ENTERPRISE") -ErrorAction Stop
				Write-Log -type SUCCESS -Message "Assigned license $lic to group $($i.key) without Exchange Online Plan"
			}
			Else
			{
				#license assignment
				Add-AADGroupLicenseAssignment -groupId $i.value -accountSkuId $lic -ErrorAction Stop
				Write-Log -type SUCCESS -Message "Assigned license $lic to group $($i.key)"
			}
		}
		catch
		{
			Write-Log -type ERROR -Message "Could not assign license $lic to group $($i.key). $_"
		}
	}
}

Write-Log -type SUCCESS -Message "License assignment done!"

#endregion
#########################################################################################################################################################################
#Finish prep
write-host "All preparation Tasks for Intune configuration are done..." -ForegroundColor White -BackgroundColor Magenta 
Write-Log -type SUCCESS -Message "Finished" -logOnly
