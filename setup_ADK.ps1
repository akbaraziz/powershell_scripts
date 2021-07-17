<#
# Install ADK and WDS for ConfigMgr, 2018/3/31 Niall Brady, https://www.windows-noob.com
#
# This script:            Downloads and installs Windows ADK 1709, then installs WDS for ConfigMgr https://docs.microsoft.com/en-us/sccm/core/plan-design/configs/site-and-site-system-prerequisites
# Before running:         Modify the ADK download path source variable (line 17), if you have already downloaded the ADK manually copy the content of "Windows Kits" to the source folder
# Usage:                  Run this script on the ConfigMgr Primary Server as a user with local Administrative permissions on the server
#>

function TestPath($Path) {
if ( $(Try { Test-Path $Path.trim() } Catch { $false }) ) {
   write-host "Path OK"
 }
Else {
   write-host "$Path not found, please fix and try again."
   break
 }}
$SourcePath = "C:\Source"

    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltInRole] “Administrator”))

    {
        Write-Warning “You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!”
        Break
    }

# create Source folder if needed
if (Test-Path $SourcePath){
 write-host "The Source folder already exists."
 } else {

New-Item -Path $SourcePath -ItemType Directory
}
# These 2 lines with help from Trevor !
$ADKPath = '{0}\Windows Kits\10\ADK' -f $SourcePath;
$ArgumentList1 = '/layout "{0}" /quiet' -f $ADKPath;


# Check if these files exists, if not, download them
 $file1 = $SourcePath+"\adksetup.exe"

if (Test-Path $file1){
 write-host "The file $file1 exists."
 } else {
 
# Download Windows Assessment and Deployment Kit (ADK 10)
		Write-Host "Downloading Adksetup.exe " -nonewline
		$clnt = New-Object System.Net.WebClient
		$url = "https://go.microsoft.com/fwlink/p/?linkid=859206"
		$clnt.DownloadFile($url,$file1)
		Write-Host "done!" -ForegroundColor Green
 }

if (Test-Path $ADKPath){
 Write-Host "The folder $ADKPath exists, skipping download"
 } else{

Write-Host "Downloading Windows ADK 10 which is approx 3.8GB in size, please wait..."  -nonewline
Start-Process -FilePath "$SourcePath\adksetup.exe" -Wait -ArgumentList $ArgumentList1
Write-Host "done!" -ForegroundColor Green
 }
 
Start-Sleep -s 10

# This installs Windows Deployment Service
Write-Host "Installing Windows Deployment Services"  -nonewline
Import-Module ServerManager
Install-WindowsFeature -Name WDS -IncludeManagementTools
Start-Sleep -s 10

# Install ADK Deployment Tools,  Windows Preinstallation Enviroment
Write-Host "Installing Windows ADK 10"
Start-Process -FilePath "$ADKPath\adksetup.exe" -Wait -ArgumentList " /Features OptionId.DeploymentTools OptionId.WindowsPreinstallationEnvironment OptionId.ImagingAndConfigurationDesigner OptionId.UserStateMigrationTool /norestart /quiet /ceip off"
Start-Sleep -s 20
Write-Host "Done !"
