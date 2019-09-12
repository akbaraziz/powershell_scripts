<#
.SYNOPSIS
    Pre SQL install script
.PARAMETER ServerName
    Server that needs pre install 
.PARAMETER DoNotFormatDrives
    Include this if you don't want to format the L, S, and T drives
#>
param(
    [string]$ServerName= $(throw 'Must provide a server name'),
    [switch]$DoNotFormatDrives,
    [string]$svcAccount = $(throw 'Must provide the service account SQL will run under'),
    [string]$workingDirectory = 'C:\SQLInstall'
)

# set timezone to central
try {
    write-host "Setting timezone to Central Standard Time..." -ForegroundColor Green
    Invoke-Command -ComputerName $ServerName -ScriptBlock {Set-TimeZone -Name "Central Standard Time"}
}
catch {
    write-host "Failed to set timezone to central..." -ForegroundColor Yellow
}

# format drives if required
if(!$DoNotFormatDrives){
    write-host "Formatting S, L, and T drives..." -ForegroundColor Green
    Invoke-Command -ComputerName $ServerName -ScriptBlock { `
        Format-Volume -DriveLetter T -FileSystem NTFS -AllocationUnitSize 65536 -force
        Format-Volume -DriveLetter L -FileSystem NTFS -AllocationUnitSize 65536 -force
        Format-Volume -DriveLetter S -FileSystem NTFS -AllocationUnitSize 65536 -force
    }
}
else{
    write-host "Skipping formatting the drives..." -ForegroundColor Yellow
}

# change power setting to high performance
try{
    write-host "Setting the power option to High Performance..." -ForegroundColor Green
    Invoke-Command -ComputerName $ServerName -ScriptBlock { 
        $HighPerf = powercfg -l | ForEach-Object{if($_.contains("High performance")) {$_.split()[3]}} 
        $CurrPlan = $(powercfg -getactivescheme).split()[3] 
        if ($CurrPlan -ne $HighPerf) { 
            powercfg -setactive $HighPerf -ForegroundColor Green
        } 
    }
}
catch{
    write-host "Failed to set power option..." -ForegroundColor Yellow
}

# Set page file to 3GB
try{
    Write-Host "Setting the page file to 3GB..." -ForegroundColor Green
    Invoke-Command -ComputerName $ServerName -ScriptBlock { 
        $ComputerSystem = $null 
        $CurrentPageFile = $null 
        $modify = $false 
        $Path = "C:\pagefile.sys" 
        $InitialSize = 3000 
        $MaximumSize = 3000 

        # Disables automatically managed page file setting first 
        $ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem -EnableAllPrivileges 
        if ($ComputerSystem.AutomaticManagedPagefile) { 
            $ComputerSystem.AutomaticManagedPagefile = $false 
            $ComputerSystem.Put() 
        } 
    
        $CurrentPageFile = Get-WmiObject -Class Win32_PageFileSetting 
        if ($CurrentPageFile.Name -eq $Path) { 
            # Keeps the existing page file
            if ($CurrentPageFile.InitialSize -ne $InitialSize) { 
                $CurrentPageFile.InitialSize = $InitialSize 
                $modify = $true 
            } 
            if ($CurrentPageFile.MaximumSize -ne $MaximumSize) { 
                $CurrentPageFile.MaximumSize = $MaximumSize 
                $modify = $true 
            } 
            if ($modify) { $CurrentPageFile.Put() } 
        } 
        else { 
            # Creates a new page file
            $CurrentPageFile.Delete() 
            Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{Name=$Path; InitialSize = $InitialSize; MaximumSize = $MaximumSize} 
        } 
    }
}
catch{
    write-host "Failed to set the page file..." -ForegroundColor Yellow
}

write-host "Adding $svcAccount to local security groups..." -ForegroundColor Green
# add user to local security policy
function Add-LoginToLocalPrivilege
{
<#
.SYNOPSIS
Adds the provided login to the local security privilege that is chosen. Must be run as Administrator in UAC mode.
Returns a boolean $true if it was successful, $false if it was not.
.DESCRIPTION
Uses the built in secedit.exe to export the current configuration then re-import
the new configuration with the provided login added to the appropriate privilege.
The pipeline object must be passed in a DOMAIN\User format as string.
This function supports the -WhatIf, -Confirm, and -Verbose switches.
.PARAMETER DomainAccount
Value passed as a DOMAIN\Account format.
.PARAMETER Privilege
The name of the privilege you want to be added.
This must be one in the following list:
SeManageVolumePrivilege
SeLockMemoryPrivilege
.PARAMETER TemporaryFolderPath
The folder path where the secedit exports and imports will reside. 
The default if this parameter is not provided is $env:USERPROFILE
#>

    #Specify the default parameterset
[CmdletBinding(DefaultParametersetName="JointNames", SupportsShouldProcess=$true, ConfirmImpact='High')]
param (
    [string] $DomainAccount = $(Throw "Must provide domain\username"),
    [ValidateSet("SeManageVolumePrivilege", "SeLockMemoryPrivilege")]
    [string] $Privilege,
    [string] $TemporaryFolderPath = $(throw "Provide path for temporary files")
        
)

#Created simple function here so I didn't have to re-type these commands
    function Remove-TempFiles
    {
        #Evaluate whether the ApplyUserRights.inf file exists
        if(Test-Path $TemporaryFolderPath\ApplyUserRights.inf)
        {
            #Remove it if it does.
            Write-Verbose "Removing $TemporaryFolderPath`\ApplyUserRights.inf"
            Remove-Item $TemporaryFolderPath\ApplyUserRights.inf -Force -WhatIf:$false
        }

        #Evaluate whether the UserRightsAsTheyExists.inf file exists
        if(Test-Path $TemporaryFolderPath\UserRightsAsTheyExist.inf)
        {
            #Remove it if it does.
            Write-Verbose "Removing $TemporaryFolderPath\UserRightsAsTheyExist.inf"
            Remove-Item $TemporaryFolderPath\UserRightsAsTheyExist.inf -Force -WhatIf:$false
        }
    }

 #   foreach($Privilege in $Privileges)


    Write-Verbose "Adding $DomainAccount to $Privilege"

    Write-Verbose "Verifying that export file does not exist."
    #Clean Up any files that may be hanging around.
    Remove-TempFiles
    
    Write-Verbose "Executing secedit and sending to $TemporaryFolderPath"
    #Use secedit (built in command in windows) to export current User Rights Assignment
    $SeceditResults = secedit /export /areas USER_RIGHTS /cfg $TemporaryFolderPath\UserRightsAsTheyExist.inf 

    #Make certain export was successful
    if($SeceditResults[$SeceditResults.Count-2] -eq "The task has completed successfully.")
    {
        Write-Verbose "Secedit export was successful, proceeding to re-import"
        #Save out the header of the file to be imported
        Write-Verbose "Save out header for $TemporaryFolderPath`\ApplyUserRights.inf"
        
"[Unicode]
Unicode=yes
[Version]
signature=`"`$CHICAGO`$`"
Revision=1
[Privilege Rights]" | Out-File $TemporaryFolderPath\ApplyUserRights.inf -Force -WhatIf:$false
                                    
        #Bring the exported config file in as an array
        Write-Verbose "Importing the exported secedit file."
        $SecurityPolicyExport = Get-Content $TemporaryFolderPath\UserRightsAsTheyExist.inf

        #enumerate over each of these files, looking for the Perform Volume Maintenance Tasks privilege
        [Boolean]$isFound = $false
        foreach($line in $SecurityPolicyExport)
        {
            if($line -like "$Privilege`*")
            {
                Write-Verbose "Line with the $Privilege found in export, appending $DomainAccount to it"
                #Add the current domain\user to the list
                $line = $line + ",$DomainAccount"
                #output line, with all old + new accounts to re-import
                $line | Out-File $TemporaryFolderPath\ApplyUserRights.inf -Append -WhatIf:$false
                $isFound = $true
            }
        } 
        if($isFound -eq $false)
        {
            #If the particular command we are looking for can't be found, create it to be imported.
            Write-Verbose "No line found for $Privilege - Adding new line for $DomainAccount"
            "$Privilege`=$DomainAccount" | Out-File $TemporaryFolderPath\ApplyUserRights.inf -Append -WhatIf:$false
        }

        #Import the new .inf into the local security policy
        Write-Verbose "Importing $TemporaryfolderPath\ApplyUserRighs.inf"
        $SeceditApplyResults = SECEDIT /configure /db secedit.sdb /cfg $TemporaryFolderPath\ApplyUserRights.inf 

        #Verify that update was successful (string reading, blegh.)
        if($SeceditApplyResults[$SeceditApplyResults.Count-2] -eq "The task has completed successfully.")
        {
#               Success, return true
            Write-Verbose "Import was successful."
            Write-Output "$DomainAccount added to $Privilege..." -ForegroundColor Green
        }
        else
        {
            #Import failed for some reason
            Write-Verbose "Import from $TemporaryFolderPath\ApplyUserRights.inf failed."
            Write-Output "Failure adding $DomainAccount to $Privilege..." -ForegroundColor Red
            Write-Error -Message "The import from$TemporaryFolderPath\ApplyUserRights using secedit failed. Full Text Below:
$SeceditApplyResults)"
        }
        
    }
    else
    {
        #Export failed for some reason.
        Write-Verbose "Export to $TemporaryFolderPath\UserRightsAsTheyExist.inf failed."
        Write-Output "Failure adding $DomainAccount to $Privilege..." -ForegroundColor Red
        Write-Error -Message "The export to $TemporaryFolderPath\UserRightsAsTheyExist.inf from secedit failed. Full Text Below:
$SeceditResults)"
        
    }
    
    Write-Verbose "Cleaning up temporary files that were created."
    #Delete the two temp files we created.
    Remove-TempFiles
}
Invoke-Command -ComputerName $ServerName -ScriptBlock ${Function:Add-LoginToLocalPrivilege} -ArgumentList "$svcAccount", "SeManageVolumePrivilege","$workingDirectory" -Verbose 
Invoke-Command -ComputerName $ServerName -ScriptBlock ${Function:Add-LoginToLocalPrivilege} -ArgumentList "$svcAccount", "SeLockMemoryPrivilege","$workingDirectory" -Verbose 


