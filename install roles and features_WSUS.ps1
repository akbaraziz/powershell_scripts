<#
# Installs WSUS role, 2018/3/31 Niall Brady, https://www.windows-noob.com
#
# This script:            Installs WSUS role for ConfigMgr
# Before running:         Ensure the Server 2016 CD is in the location specified in the variables.
# Usage:                  Run this script on the ConfigMgr Primary Server as a user with local Administrative permissions on the server
#>
  If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltInRole] “Administrator”))

    {
        Write-Warning “You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!”
        Break
    }
  If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltInRole] “Administrator”))

    {
        Write-Warning “You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!”
        Break
    }
$WSUSFolder = "D:\WSUS"
$SourceFiles = "E:\Sources\SXS"
$ScriptsFolder = "C:\Scripts"
$servername="CM01"
# create WSUS folder
if (Test-Path $WSUSFolder){
 write-host "The WSUS folder already exists."
 } else {

New-Item -Path $WSUSFolder -ItemType Directory
}
if (Test-Path $SourceFiles){
 write-host "Windows Server 2016 source files found"
 } else {

write-host "Windows Server 2016 source files not found, aborting"
break
}

Write-Host "Installing roles and features, please wait... "  -nonewline
Install-WindowsFeature -ConfigurationFilePath "$ScriptsFolder\Part 2\CM01\DeploymentConfigTemplate_WSUS.xml" -Source $SourceFiles
Start-Sleep -s 10
& ‘C:\Program Files\Update Services\Tools\WsusUtil.exe’ postinstall SQL_INSTANCE_NAME=$servername CONTENT_DIR=$WSUSFolder |out-file Null
write-host "All done !"