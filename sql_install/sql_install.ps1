<#
.SYNOPSIS
    Use to install SQL Server components
.PARAMETER installFileLocation
    Location of install file
.PARAMETER FEATURES
	Specifies features to install, uninstall, or upgrade. eg. "SQLEngine,Replicaton,FullText"
.PARAMETER INSTANCENAME
    Specify a default or named instance. MSSQLSERVER is the default instance for non-Express editions and SQLExpress for Express editions.
.PARAMETER INSTALLSHAREDDIR
    Specify the root installation directory for shared components.  This directory remains unchanged after shared components are already installed.
.PARAMETER INSTALLSHAREDWOWDIR
    Specify the root installation directory for the WOW64 shared components.  This directory remains unchanged after WOW64 shared components are already installed. 
.PARAMETER INSTANCEDIR
    Specify the installation directory.
.PARAMETER AGTSVCACCOUNT
    Agent account name.
.PARAMETER SQLSVCSTARTUPTYPE
    Startup type for the SQL Server service. 
.PARAMETER FILESTREAMLEVEL
    Level to enable FILESTREAM feature at (0, 1, 2 or 3). 
.PARAMETER SQLCOLLATION
    Specifies a Windows collation or an SQL collation to use for the Database Engine.
.PARAMETER SQLSVCACCOUNT
    Account for SQL Server service: Domain\User or system account.
.PARAMETER SQLSYSADMINACCOUNTS
    Windows account(s) to provision as SQL Server system administrators separated by a space. eg. "domain\act1", "domain\act2"
.PARAMETER SECURITYMODE
    The default is Windows Authentication. Use "SQL" for Mixed Mode Authentication.
.PARAMETER SQLTEMPDBFILECOUNT
    The number of Database Engine TempDB files. 
.PARAMETER SQLTEMPDBFILESIZE
    Specifies the initial size of a Database Engine TempDB data file in MB. 
.PARAMETER SQLTEMPDBFILEGROWTH
    Specifies the automatic growth increment of each Database Engine TempDB data file in MB.
.PARAMETER SQLTEMPDBLOGFILESIZE
    Specifies the initial size of the Database Engine TempDB log file in MB. 
.PARAMETER SQLTEMPDBLOGFILEGROWTH
    Specifies the automatic growth increment of the Database Engine TempDB log file in MB.
.PARAMETER SQLBACKUPDIR
    Default directory for the Database Engine backup files. 
.PARAMETER SQLUSERDBDIR
    Default directory for the Database Engine user databases.
.PARAMETER SQLUSERDBLOGDIR
    Default directory for the Database Engine user database logs. 
.PARAMETER SQLTEMPDBDIR
    Directories for Database Engine TempDB files.
.PARAMETER NPENABLED
    Specify 0 to disable or 1 to enable the Named Pipes protocol.
.PARAMETER BROWSERSVCSTARTUPTYPE
    Startup type for Browser Service.
.Parameter SAPWD
    SA password, only needed if SECURITYMODE = SQL
#>

# List of variables that we might want to chnage. More can be added. List of options located here https://docs.microsoft.com/en-us/sql/database-engine/install-windows/install-sql-server-from-the-command-prompt?view=sql-server-2017
[CmdletBinding()]
PARAM(
     [STRING]$serverName              = $(throw 'You must provide the Server name')  
    ,[STRING]$installFileLocation     = "C:\SQLInstall"
    ,[STRING]$FEATURES                = $(Throw 'You must select which features to install. Common options include SQLEngine, Replicaton, FullText
    Here is a full list:
    https://docs.microsoft.com/en-us/sql/database-engine/install-windows/install-sql-server-from-the-command-prompt?view=sql-server-2017#Feature
    ')
    ,[STRING]$INSTANCENAME            = 'MSSQLSERVER'
    ,[STRING]$INSTALLSHAREDDIR        = 'C:\Program Files\Microsoft SQL Server'
    ,[STRING]$INSTALLSHAREDWOWDIR     = 'C:\Program Files (x86)\Microsoft SQL Server'
    ,[STRING]$INSTANCEDIR             = 'C:\Program Files\Microsoft SQL Server'
    ,[STRING]$AGTSVCACCOUNT           = $(throw 'You must provide an agent account')
    ,[STRING]$SQLSVCSTARTUPTYPE       = 'Automatic'
    ,[ValidateSet('0','1','2','3')]
      [STRING]$FILESTREAMLEVEL        = '0'
    ,[STRING]$SQLCOLLATION            = 'SQL_Latin1_General_CP1_CI_AS'
    ,[STRING]$SQLSVCACCOUNT           = $(throw 'You must provide a service account')
    ,[array]$SQLSYSADMINACCOUNTS      = $(throw 'You must provide an admin group')
    ,[int]$SQLTEMPDBFILECOUNT         = $(throw 'You must provide number of tempdbs to include')
    ,[int]$SQLTEMPDBFILESIZE          = $(throw 'You must provide initial size of tempdbs in MB')
    ,[int]$SQLTEMPDBFILEGROWTH        = $(throw 'You must provide growth increment of tempdbs in MB')
    ,[int]$SQLTEMPDBLOGFILESIZE       = $(throw 'You must provide initial size of the log file in MB')
    ,[int]$SQLTEMPDBLOGFILEGROWTH     = $(throw 'You must provide growth increment of the log file in MB')
    ,[STRING]$SQLBACKUPDIR            = 'S:\MSSQL'
    ,[STRING]$SQLUSERDBDIR            = 'S:\MSSQL\Data'
    ,[STRING]$SQLUSERDBLOGDIR         = 'L:\MSSQL\Data'
    ,[STRING]$SQLTEMPDBDIR            = 'T:\MSSQL\Data'
    ,[Switch]$NPENABLED               = $false
    ,[STRING]$BROWSERSVCSTARTUPTYPE   = 'Disabled'
    ,[SWITCH]$SECURITYMODE            
    ,[string]$SAPWD
    ,[string]$SQLSVCPASSWORD = $(throw 'Must provide the service account password')
    ,[string]$AGTSVCPASSWORD = $(throw 'Must provide the agent account password')
)

$ErrorActionPreference = "Stop"

try{

    # check that we are providing the sa password if required
    if ($SECURITYMODE){
        if ($SAPWD -eq ''){
            throw 'You must provide a password for sa account or remove -SECURITYMODE'
        }
    }

    # make passwords secure
    # $SQLSVCPASSWORD = ConvertTo-SecureString $SQLSVCPASSWORD -AsPlainText -Force
    # $AGTSVCPASSWORD = ConvertTo-SecureString $AGTSVCPASSWORD -AsPlainText -Force

    Write-Host "Creating configuration file from parameters..." -ForegroundColor Green

    # This is the basic file that the parameters above will apply to.
    # There are values in this that are not parameters because they always have the same value. 
    # There are also parameters that aren't in this ini file that we need in the rest of the script.
    # UIMODE is commentted out or it will fail with quiet mode
    $iniBase = @"
;SQL Server 2016 Configuration File
[OPTIONS]
ACTION="Install"
SUPPRESSPRIVACYSTATEMENTNOTICE="False"
IACCEPTROPENLICENSETERMS="True"
IACCEPTSQLSERVERLICENSETERMS="True"
ENU="True"
QUIET="True"
QUIETSIMPLE="False"
;UIMODE="Normal" 
UpdateEnabled="False"
USEMICROSOFTUPDATE="False"
FEATURES=SQLENGINE
UpdateSource="MU"
HELP="False"
INDICATEPROGRESS="True"
X86="False"
INSTANCENAME="MSSQLSERVER"
INSTALLSHAREDDIR="C:\Program Files\Microsoft SQL Server"
INSTALLSHAREDWOWDIR="C:\Program Files (x86)\Microsoft SQL Server"
INSTANCEID="MSSQLSERVER"
SQLTELSVCACCT="NT Service\SQLTELEMETRY"
SQLTELSVCSTARTUPTYPE="Automatic"
INSTANCEDIR="C:\Program Files\Microsoft SQL Server"
AGTSVCACCOUNT="SUBZEROCOM\"
AGTSVCSTARTUPTYPE="Automatic"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL="0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False"
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SUBZEROCOM\"
SQLSVCINSTANTFILEINIT="True"
SQLSYSADMINACCOUNTS="SUBZEROCOM\SEC_Database Administrator"
SQLTEMPDBFILECOUNT="2"
SQLTEMPDBFILESIZE="1024"
SQLTEMPDBFILEGROWTH="64"
SQLTEMPDBLOGFILESIZE="1024"
SQLTEMPDBLOGFILEGROWTH="64"
SQLBACKUPDIR="S:\MSSQL"
SQLUSERDBDIR="S:\MSSQL\Data"
SQLUSERDBLOGDIR="L:\MSSQL\Data"
SQLTEMPDBDIR="T:\MSSQL\Data"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="0"
BROWSERSVCSTARTUPTYPE="Disabled"
"@

    # Turn the ini variable into an array so we can search it more easily
    $iniList = $iniBase.Split("`n`r")

    # The following gets us the name of the parameters so that we can search for them in the ini that we create. 
    $CommandName = $PSCmdlet.MyInvocation.InvocationName;
    # Get the list of parameters for the command
    $ParameterList = (Get-Command -Name $CommandName).Parameters;

    # Grab each parameter value, using Get-Variable
    foreach ($Parameter in $ParameterList) {
        $fullParamList = Get-Variable -Name $Parameter.Values.Name -ErrorAction SilentlyContinue;
        # This is required to get the name of one parameter at a time, the above line gets all of them as one object
        foreach ($param in $fullParamList) {
            # If there are true/false values we don't want to change to 1/0, alterations will need to be made to the section below

            # checking for the SECUIRTYMODE variable because if it is true we will need to add it to the ini file. 
            # when false, there should be no SECURITYMODE row in the ini file (default).
            if($param.Name -eq 'SECURITYMODE')
            {
                if($SECURITYMODE){
                    # add a new item in the array for SECURITYMODE
                    $iniList.Add("SECURITYMODE=""SQL""")
                    # SECURITYMODE="SQL"
                    # add a new item in the array for the SAPWD (sa password)
                    $iniList.Add("SAPWD=""$SAPWD""")
                    # SAPWD
                }
                # else
                # SECURITYMODE is false so we don't need to do anything 
            }
            # checking for param because there could be one or many
            elseif($param.Name -eq 'SQLSYSADMINACCOUNTS'){
                # string to append to
                $build = ""
                # loop through each value in array and add to $build
                foreach($p in $param.Value){
                    $build = "$build ""$p"""
                }
                foreach($row in $iniList){
                    if ($row.StartsWith($param.Name)){
                        $iniList[$iniList.IndexOf($row)] = "SQLSYSADMINACCOUNTS=$build"
                    }
                }
            }
            # Change powershell $true into 1
            elseif ($param.Value -eq $true){
                # Then search the lines of ini to update the correct record
                foreach($row in $iniList){
                    if ($row.StartsWith($param.Name)){
                        $iniList[$iniList.IndexOf($row)] = "$($param.Name)=""1"""
                    }
                }
            }
            # Change powershell $false into 0
            elseif($param.Value -eq $false){
                foreach($row in $iniList){
                    # Then search the lines of ini to update the correct record
                    if ($row.StartsWith($param.Name)){
                        $iniList[$iniList.IndexOf($row)] = "$($param.Name)=""0"""
                    }
                }
            }
            # string values
            else{
                foreach($row in $iniList){
                    # Search the lines of ini to update the correct record
                    if ($row.StartsWith($param.Name)){
                        $iniList[$iniList.IndexOf($row)] = "$($param.Name)=""$($param.Value)"""
                    }
                }   
            }
        }
        # create the ini file on remote server
        $installFileLocationRemote = "\\$serverName\$($installFileLocation.Replace(":","$"))"
        $iniList | Out-File -FilePath "$installFileLocationRemote\sqlInstallConfig.ini"
    }

    write-host "$installFileLocationRemote\sqlInstallConfig.ini has been created..." -ForegroundColor Green

    # mount the iso to the E drive
    write-host "Mounting iso file..." -ForegroundColor Green
    Invoke-Command -ComputerName $serverName  -ScriptBlock { 
        set-location $using:installFileLocation
        $isoFile = Get-ChildItem -Filter *.iso
        Mount-DiskImage -ImagePath "$using:installFileLocation\$isoFile" 
        # wait a moment for the mount to finish
        Start-Sleep -s 10
        # this is where the exe is located
        Set-Location "E:\"
    
        write-host "Beginning SQL install..." -ForegroundColor Green
        $command = "cmd.exe /C e:\setup.exe /SQLSVCPASSWORD=""$using:SQLSVCPASSWORD"" /AGTSVCPASSWORD=""$using:AGTSVCPASSWORD"" /ConfigurationFile=$using:installFileLocation\sqlInstallConfig.ini"
        Invoke-Expression -Command:$command
    } -Verbose 
} 
catch{
    write-host $_ -ForegroundColor Red
}



