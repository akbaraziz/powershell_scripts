<#
# Installs SQL Server 2017, 2018/4/5 Niall Brady, https://www.windows-noob.com
#
# This script:            Installs SQL Server 2017, CU5, SSMS and RS
# Before running:         Edit the variables as necessary (lines 17-79). Copy the SQL Service Management Studio (SSMS-Setup-ENU.exe) and Reporting Services (SQLServerReportingServices.exe) files to $folderpath\ in advance if you don't want the script to download the exe's
# Usage:                  Run this script on the ConfigMgr Primary Server as a user with local Administrative permissions on the server
#>
  If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltInRole] “Administrator”))

    {
        Write-Warning “You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!”
        Break
    }

# below variables are customizable
$folderpath="C:\Scripts"
$inifile="$folderpath\ConfigurationFile.ini"
# next line sets user as a SQL sysadmin
$yourusername="windowsnoob\niall"
# path to the SQL media
$SQLsource="E:"
$SQLInstallDrive = "D:"
# SQL memory
$SqlMemMin = 8192
$SqlMemMax = 8192
# configurationfile.ini settings https://msdn.microsoft.com/en-us/library/ms144259.aspx
$ACTION="Install"
$ASCOLLATION="Latin1_General_CI_AS"
$ErrorReporting="False"
$SUPPRESSPRIVACYSTATEMENTNOTICE="False"
$IACCEPTROPENLICENSETERMS="False"
$ENU="True"
$QUIET="True"
$QUIETSIMPLE="False"
$UpdateEnabled="True"
$USEMICROSOFTUPDATE="False"
$FEATURES="SQLENGINE,RS,CONN,IS,BC,SDK"
$UpdateSource="MU"
$HELP="False"
$INDICATEPROGRESS="False"
$X86="False"
$INSTANCENAME="MSSQLSERVER"
$INSTALLSHAREDDIR="$SQLInstallDrive\Program Files\Microsoft SQL Server"
$INSTALLSHAREDWOWDIR="$SQLInstallDrive\Program Files (x86)\Microsoft SQL Server"
$INSTANCEID="MSSQLSERVER"
$RSINSTALLMODE="DefaultNativeMode"
$SQLTELSVCACCT="NT Service\SQLTELEMETRY"
$SQLTELSVCSTARTUPTYPE="Automatic"
$ISTELSVCSTARTUPTYPE="Automatic"
$ISTELSVCACCT="NT Service\SSISTELEMETRY130"
$INSTANCEDIR="$SQLInstallDrive\Program Files\Microsoft SQL Server"
$AGTSVCACCOUNT="NT AUTHORITY\SYSTEM"
$AGTSVCSTARTUPTYPE="Automatic"
$ISSVCSTARTUPTYPE="Disabled"
$ISSVCACCOUNT="NT AUTHORITY\System"
$COMMFABRICPORT="0"
$COMMFABRICNETWORKLEVEL="0"
$COMMFABRICENCRYPTION="0"
$MATRIXCMBRICKCOMMPORT="0"
$SQLSVCSTARTUPTYPE="Automatic"
$FILESTREAMLEVEL="0"
$ENABLERANU="False"
$SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
$SQLSVCACCOUNT="NT AUTHORITY\System"
$SQLSVCINSTANTFILEINIT="False"
$SQLSYSADMINACCOUNTS="$yourusername"
$SQLTEMPDBFILECOUNT="1"
$SQLTEMPDBFILESIZE="8"
$SQLTEMPDBFILEGROWTH="64"
$SQLTEMPDBLOGFILESIZE="8"
$SQLTEMPDBLOGFILEGROWTH="64"
$ADDCURRENTUSERASSQLADMIN="True"
$TCPENABLED="1"
$NPENABLED="1"
$BROWSERSVCSTARTUPTYPE="Disabled"
$RSSVCACCOUNT="NT AUTHORITY\System"
$RSSVCSTARTUPTYPE="Automatic"
$IAcceptSQLServerLicenseTerms="True"

# do not edit below this line

$conffile= @"
[OPTIONS]
Action="$ACTION"
ErrorReporting="$ERRORREPORTING"
Quiet="$Quiet"
Features="$FEATURES"
InstanceName="$INSTANCENAME"
InstanceDir="$INSTANCEDIR"
SQLSVCAccount="$SQLSVCACCOUNT"
SQLSysAdminAccounts="$SQLSYSADMINACCOUNTS"
SQLSVCStartupType="$SQLSVCSTARTUPTYPE"
AGTSVCACCOUNT="$AGTSVCACCOUNT"
AGTSVCSTARTUPTYPE="$AGTSVCSTARTUPTYPE"
RSSVCACCOUNT="$RSSVCACCOUNT"
RSSVCSTARTUPTYPE="$RSSVCSTARTUPTYPE"
ISSVCACCOUNT="$ISSVCACCOUNT" 
ISSVCSTARTUPTYPE="$ISSVCSTARTUPTYPE"
ASCOLLATION="$ASCOLLATION"
SQLCOLLATION="$SQLCOLLATION"
TCPENABLED="$TCPENABLED"
NPENABLED="$NPENABLED"
IAcceptSQLServerLicenseTerms="$IAcceptSQLServerLicenseTerms"
"@


# Check for Script Directory & file
if (Test-Path "$folderpath"){
 write-host "The folder '$folderpath' already exists, will not recreate it."
 } else {
mkdir "$folderpath"
}
if (Test-Path "$folderpath\ConfigurationFile.ini"){
 write-host "The file '$folderpath\ConfigurationFile.ini' already exists, removing..."
 Remove-Item -Path "$folderpath\ConfigurationFile.ini" -Force
 } else {

}
# Create file:
write-host "Creating '$folderpath\ConfigurationFile.ini'..."
New-Item -Path "$folderpath\ConfigurationFile.ini" -ItemType File -Value $Conffile

# Configure Firewall settings for SQL

write-host "Configuring SQL Server 2017 Firewall settings..."

#Enable SQL Server Ports

New-NetFirewallRule -DisplayName "SQL Server" -Direction Inbound –Protocol TCP –LocalPort 1433 -Action allow
New-NetFirewallRule -DisplayName "SQL Admin Connection" -Direction Inbound –Protocol TCP –LocalPort 1434 -Action allow
New-NetFirewallRule -DisplayName "SQL Database Management" -Direction Inbound –Protocol UDP –LocalPort 1434 -Action allow
New-NetFirewallRule -DisplayName "SQL Service Broker" -Direction Inbound –Protocol TCP –LocalPort 4022 -Action allow
New-NetFirewallRule -DisplayName "SQL Debugger/RPC" -Direction Inbound –Protocol TCP –LocalPort 135 -Action allow

#Enable SQL Analysis Ports

New-NetFirewallRule -DisplayName "SQL Analysis Services" -Direction Inbound –Protocol TCP –LocalPort 2383 -Action allow
New-NetFirewallRule -DisplayName "SQL Browser" -Direction Inbound –Protocol TCP –LocalPort 2382 -Action allow

#Enabling related Applications

New-NetFirewallRule -DisplayName "HTTP" -Direction Inbound –Protocol TCP –LocalPort 80 -Action allow
New-NetFirewallRule -DisplayName "SQL Server Browse Button Service" -Direction Inbound –Protocol UDP –LocalPort 1433 -Action allow
New-NetFirewallRule -DisplayName "SSL" -Direction Inbound –Protocol TCP –LocalPort 443 -Action allow

#Enable Windows Firewall
Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast True

Write-Host "done!" -ForegroundColor Green

# start the SQL installer
Try
{
if (Test-Path $SQLsource){
 write-host "about to install SQL Server 2017..." -nonewline
$fileExe =  "$SQLsource\setup.exe"
$CONFIGURATIONFILE = "$folderpath\ConfigurationFile.ini"
& $fileExe  /CONFIGURATIONFILE=$CONFIGURATIONFILE
Write-Host "done!" -ForegroundColor Green
 } else {
write-host "Could not find the media for SQL Server 2017..."
break
}}
catch
{write-host "Something went wrong with the installation of SQL Server 2017, aborting."
break}

# start the SQL Server 2017 CU5 downloader
$filepath="$folderpath\SQLServer2017-KB4092643-x64.exe"
if (!(Test-Path $filepath)){
write-host "Downloading SQL Server 2017 CU5..." -nonewline
$URL = "https://download.microsoft.com/download/C/4/F/C4F908C9-98ED-4E5F-88D5-7D6A5004AEBD/SQLServer2017-KB4092643-x64.exe"
$clnt = New-Object System.Net.WebClient
$clnt.DownloadFile($url,$filepath)
Write-Host "done!" -ForegroundColor Green
}
 else {
write-host "found the SQL Server 2017 CU5 Installer, no need to download it..."
}
# start the SQL Server 2017 CU5 installer
write-host "about to install SQL Server 2017 CU5..." -nonewline
$Parms = " /quiet /IAcceptSQLServerLicenseTerms /Action=Patch /AllInstances"
$Prms = $Parms.Split(" ")
& "$filepath" $Prms | Out-Null
Write-Host "done!" -ForegroundColor Green

# start the SQL SSMS downloader
$filepath="$folderpath\SSMS-Setup-ENU.exe"
if (!(Test-Path $filepath)){
write-host "Downloading SQL Server 2017 SSMS..." -nonewline
$URL = "https://go.microsoft.com/fwlink/?linkid=870039"
$clnt = New-Object System.Net.WebClient
$clnt.DownloadFile($url,$filepath)
Write-Host "done!" -ForegroundColor Green
}
 else {
write-host "found the SQL SSMS Installer, no need to download it..."
}
# start the SQL SSMS installer
write-host "about to install SQL Server 2017 SSMS..." -nonewline
$Parms = " /Install /Quiet /Norestart /Logs SQLServerSSMSlog.txt"
$Prms = $Parms.Split(" ")
& "$filepath" $Prms | Out-Null
Write-Host "done!" -ForegroundColor Green


# start the SQL RS downloader
$filepath="$folderpath\SQLServerReportingServices.exe"
if (!(Test-Path $filepath)){
write-host "Downloading SQL Server 2017 Reporting Services..." -nonewline
$URL = "https://download.microsoft.com/download/E/6/4/E6477A2A-9B58-40F7-8AD6-62BB8491EA78/SQLServerReportingServices.exe"
$clnt = New-Object System.Net.WebClient
$clnt.DownloadFile($url,$filepath)
Write-Host "done!" -ForegroundColor Green
}
 else {
write-host "found the SQL RS Installer, no need to download it..."
}
# start the SQL RS installer
write-host "about to install SQL Server 2017 Reporting Services..." -nonewline
$Parms = "  /IAcceptLicenseTerms True /Quiet /Norestart /Log SQLServerReportingServiceslog.txt"
$Prms = $Parms.Split(" ")
& "$filepath" $Prms | Out-Null
Write-Host "done!" -ForegroundColor Green

# Configure SQL memory (thanks Skatterbrainz)
write-host "Configuring SQL memory..." -nonewline

[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | Out-Null
$SQLMemory = New-Object ('Microsoft.SqlServer.Management.Smo.Server') ("(local)")
$SQLMemory.Configuration.MinServerMemory.ConfigValue = $SQLMemMin
$SQLMemory.Configuration.MaxServerMemory.ConfigValue = $SQLMemMax
$SQLMemory.Configuration.Alter()
Write-Host "done!" -ForegroundColor Green
write-host ""

# exit script
write-host "Exiting script, goodbye."

