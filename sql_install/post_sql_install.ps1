<#

#>

param(
    [string]$ServerName = $(throw 'Must include server name'),
    [string]$StartupParameters = "-T460,-T3226,-T2371,-T1118,-T1117",
    [string]$ScriptLocation = "C:\git\dba-tools\SQL Scripts",
    [switch]$isExpress
)

Invoke-Command -ComputerName $ServerName -ScriptBlock {
    # get all the instances on a server
    $property = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
    $instancesObject = $property.psobject.properties | ?{$_.Value -like 'MSSQL*'} 
    $instances = $instancesObject.Value
    #get all the parameters you input
    $startParamTemp = $using:StartupParameters
    $parameters = $startParamTemp.split(",")
    #add all the startup parameters
    if($instances){
        foreach($instance in $instances){
            $ins = $instance.split('.')[1]
            if($ins -eq "MSSQLSERVER"){
                $instanceName = $env:COMPUTERNAME
            }
            else{
                $instanceName = $env:COMPUTERNAME + "\" + $ins
            }
            $regKey = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instance\MSSQLServer\Parameters"
            $property = Get-ItemProperty $regKey
            #$property
            $paramObjects = $property.psobject.properties | ?{$_.Name -like 'SQLArg*'}
            $count = $paramObjects.count
            foreach($parameter in $parameters){
                if($parameter -notin $paramObjects.value){                
                    Write-Host "Adding startup parameter:$parameter for $instanceName"
                    $newRegProp = "SQLArg"+$count
                    Set-ItemProperty -Path $regKey -Name $newRegProp -Value $parameter
                    $count = $count + 1
                }
            }
        }
    }
}

write-host "Setup standard SQL Server settings..." -ForegroundColor Green
Invoke-Sqlcmd -ServerInstance $ServerName -Database 'master' -InputFile "$ScriptLocation\SetStandardSQLServerSettings.sql"

write-host "Setup SQL database mail..." -ForegroundColor Green
Invoke-Sqlcmd -ServerInstance $ServerName -Database 'master' -InputFile "$ScriptLocation\SetupDatabaseMail.sql"

write-host "Setup standard SQL alerts..." -ForegroundColor Green
Invoke-Sqlcmd -ServerInstance $ServerName -Database 'master' -InputFile "$ScriptLocation\SetStandardSQLAlerts.sql"

# We don't want to setup jobs for an express version
if(!$isExpress){
    write-host "Setup standard SQL jobs..." -ForegroundColor Green
    Invoke-Sqlcmd -ServerInstance $ServerName -Database 'master' -InputFile "$ScriptLocation\SetStandardSQLJobs.sql"
}


write-host "You still need to add the new server to the DatabaseManagement server, create DBA/Common databases, Kerberos setup, and Maintenance/Monitoring" -ForegroundColor Magenta
 
<#
	- Setup in DatabaseManagement database
		○ Run the instance and database collection jobs in ActiveBatch that were setup a few steps back
		○ Set the patching schedule and the backup profile
			/*
			SELECT * FROM dbo.PatchingSchedule
			SELECT * FROM dbo.BackupProfile
			*/
			UPDATE dbo.SQLInstance
			SET
				PatchingScheduleID = <PatchingScheduleID,,>
				,BackupProfileID = <BackupProfileID,,>
			WHERE InstanceName = '<InstanceName,,>'
		○ Set the DR and Service Tiers
			UPDATE dbo.Server
			SET
				DRTier = <DRTier,,>
				,ServiceTier = <ServiceTier,,>
			WHERE ServerName = '<ServerName,,>' /* if this is a cluster make sure both servers are set.  Both servers may not be collected yet because it only collects info on the server that is currently active */

#>

<#

	- Create DBA database
		○ Create a blank database
		○ Use SQL Compare to create the objects
	- Create Common database if needed
		○ typically only added if we have 'homemade' databases on here
		○ Create a blank database
		○ Use SQL Compare to create the objects
		○ Use SQL Data Compare to populate tables
#>

<#
	- Configure Kerberos
		○ On your local machine launch by visiting C:\Program Files\Microsoft\Kerberos Configuration Manager for SQL Server 
		○ Try the Kerberos Configuration Manager for SQL to generate cmd file for SPN creation (it doesn't always work)
		○ Have an SE run the cmd file and configure delegation
		○ If Kerberos Configuration Manager doesn't work have the SEs create SPNs similar to this
			§ SetSPN -s "MSSQLSvc/<server name>.subzero.com" "SUBZEROCOM\<sql service account>"
			§ SetSPN -s "MSSQLSvc/<server name>.subzero.com:1433" "SUBZEROCOM\<sql service account>"
	- Setup Maintenance through ActiveBatch
		○ Go into AB -> Production -> IT -> Data Architecture ->SQL Standard Maintenance
		○ Copy a folder and rename it to server.
		○ Change user credentials
		○ Drag user to ExecutionUsers in AA-Master
		○ Run full backup and maintenance
			§ Full back will fail without kerberos
	- Setup Monitoring in Solarwinds DPA
#>

