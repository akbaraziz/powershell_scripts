<#
.notes
	##############################################################################
	#	 	 Nutanix Cluster Info Script
	#	 	 Filename			:	  NTNX_Get_Cluster_Info.ps1
	#	 	 Script Version	:	  1.1.15
	##############################################################################
.prerequisites
	1. Powershell 5 or above ($psversiontable.psversion.major)
	2. Windows Vista or newer.
	3. Set the appropriate variables for your environment.
.synopsis
	Generate 3 CSV files, 1 for cluster information, 1 for cluster resiliency and 1 for host information.
.disclaimer
	This code is intended as a standalone example. Subject to licensing restrictions defined on nutanix.dev, this can be downloaded, copied and/or modified in any way you see fit.

	Please be aware that all public code samples provided by Nutanix are unofficial in nature, are provided as examples only, are unsupported and will need to be heavily scrutinized and potentially modified before they can be used in a production environment. All such code samples are provided on an as-is basis, and Nutanix expressly disclaims all warranties, express or implied.

	All code samples are © Nutanix, Inc., and are provided as-is under the MIT license. (https://opensource.org/licenses/MIT)
#>
##############################################################################
# Set Variables Below
##############################################################################
$my_ClusterArrayIP = @("10.0.0.1", "10.0.0.2", "10.0.0.3") # Define all of your clusters by IPv4 address here!
#//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# CHANGE NOTHING BELOW HERE!
#//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
[string]$my_temperract = $ErrorActionPreference # set error handling preferences
[string]$my_ErrorActionPreference = "silentlycontinue" # set error handling preferences
[string]$my_username = "" # if all of your clusters use the same credentials, you can set your username here.
[string]$my_password = "" # if all of your clusters use the same credentials, you can set the password here.
$hashClusters = @{}
function isonline([string]$my_testcomputer) {
    write-host "|" -NoNewline -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
    write-host "Host: $($my_testcomputer) " -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
    $my_pingsuccess = $false
    try {
        $my_ping = new-object system.net.networkinformation.ping
        $my_pingtest = $my_ping.send($my_testcomputer)
    }
    catch { }
    write-host "[" -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
    if ($my_pingtest.status.tostring() -eq "Success") {
        write-host "Online" -NoNewline -ForeGroundColor GREEN -BackGroundColor BLACK;
        $my_TmpString = "]"
        foreach ($i in 0..($my_SepLength - $my_testcomputer.length - 17)) { $my_TmpString += -join " " }
        write-host ("{0}" -f $my_TmpString) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
        write-host "|" -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
        return $true
    }
    else {
        write-host "Offline" -NoNewline -ForeGroundColor RED -BackGroundColor BLACK;
        $my_TmpString = "]"
        foreach ($i in 0..($my_SepLength - $my_testcomputer.length - 18)) { $my_TmpString += -join " " }
        write-host ("{0}" -f $my_TmpString) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
        write-host "|" -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
        return $false
    }
}
function format-size($size) {
    if ($size -gt 1tb) { [string]::format("{0:0.00} TiB", $size / 1tb) }
    elseif ($size -gt 1gb) { [string]::format("{0:0.00} GiB", $size / 1gb) }
    elseif ($size -gt 1mb) { [string]::format("{0:0.00} MB", $size / 1mb) }
    elseif ($size -gt 1kb) { [string]::format("{0:0.00} KB", $size / 1kb) }
    elseif ($size -gt 0) { [string]::format("{0:0.00} B", $size) }
    else { "N/A" }
}
function mformat-string($string) {
    if (-not ([string]::IsNullOrEmpty($string))) {
        return [string]$string
    }
    return "N/A"
}
function collect_cluster_info($my_TargetIP) {
    ## Collect Cluster Info
    $my_TmpString1 = "..Parsing Cluster Data"
    write-host "|" -NoNewline -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
    write-host ("{0}" -f $my_TmpString1) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
    try {
        $my_RestAPIUrl = "https://$($my_TargetIP):9440/PrismGateway/services/rest/v2.0/cluster/"
        $my_RestResponse = Invoke-RestMethod -Method Get -Uri $my_RestAPIUrl -Headers @{Authorization = "Basic $base64AuthInfo" } -Credential $my_Credential -ContentType "application/json"
        $my_ArrCluster = @()
        $my_TmpClusterObj = new-object psobject
        [int]$my_int = 0
        $my_RestResponse | % {
            $myClusterName = $_.name
            $my_Cluster_Name = mformat-string($_.name)
            if (-not $my_ClusterHash.containskey($my_TargetIP)) { $my_ClusterHash.add($my_TargetIP, $my_Cluster_Name) }
            write-progress -id 2 -parentid 1 -activity " " -status "Enumerating JSON values..." -percentcomplete ($my_int / @($my_RestResponse).count * 100)
            $my_TmpClusterObj | Add-Member -MemberType NoteProperty -Name "Cluster Name" -value $my_Cluster_Name
            $cluster_id = mformat-string($_.id)
            $my_TmpClusterObj | Add-Member -MemberType NoteProperty -Name "Cluster ID" -value $cluster_id
            $cluster_uuid = mformat-string($_.uuid)
            $my_TmpClusterObj | Add-Member -MemberType NoteProperty -Name "Cluster UUID" -value $cluster_uuid
            $cluster_incarnation_id = mformat-string($_.cluster_incarnation_id)
            $my_TmpClusterObj | Add-Member -MemberType NoteProperty -Name "Cluster Incarnation ID" -value $cluster_incarnation_id
            $cluster_external_ipaddress = mformat-string($_.cluster_external_ipaddress)
            $my_TmpClusterObj | Add-Member -MemberType NoteProperty -Name "Cluster Virtual IP Address" -value $cluster_external_ipaddress.trim('{}')
            $cluster_external_data_services_ipaddress = mformat-string($_.cluster_external_data_services_ipaddress)
            $my_TmpClusterObj | Add-Member -MemberType NoteProperty -Name "Cluster iSCSI Data Services IP" -value $cluster_external_data_services_ipaddress.trim('{}')
            $my_Hypervisor_Types = mformat-string($_.hypervisor_types)
            $my_TmpClusterObj | Add-Member -MemberType NoteProperty -Name "Cluster Hypervisor" -value $my_Hypervisor_Types.trim('{k}')
            $timezone = mformat-string($_.timezone)
            $my_TmpClusterObj | Add-Member -MemberType NoteProperty -Name "Cluster Timezone" -value $timezone
            $support_verbosity_type = mformat-string($_.support_verbosity_type)
            $my_TmpClusterObj | Add-Member -MemberType NoteProperty -Name "Cluster Support Verbosity" -value $support_verbosity_type
            $version = mformat-string($_.version)
            $my_TmpClusterObj | Add-Member -MemberType NoteProperty -Name "Cluster AOS Version" -value $version
            $full_version = mformat-string($_.full_version)
            $my_TmpClusterObj | Add-Member -MemberType NoteProperty -Name "Cluster Full AOS Version" -value $full_version
            $my_NCC_version = mformat-string($_.ncc_version)
            $my_TmpClusterObj | Add-Member -MemberType NoteProperty -Name "Cluster NCC Version" -value $my_NCC_version
            $i = 1
            foreach ($nameserver in $_.name_servers) {
                $my_TmpClusterObj | Add-Member -MemberType NoteProperty -Name "Cluster Name Server #$($i)" -value $nameserver.trim('{}')
                $i++
            }
            $i = 1
            foreach ($my_NTPServer in $_.ntp_servers) {
                $my_TmpClusterObj | Add-Member -MemberType NoteProperty -Name "Cluster NTP Server #$($i)" -value $my_NTPServer.trim('{}')
                $i++
            }
            $my_ArrCluster += $my_TmpClusterObj
            $my_int++
        }
        $my_ArrCluster | export-csv $my_File_1 -append -notypeinformation -force
        write-host " [" -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
        write-host "OK" -NoNewline -ForeGroundColor GREEN -BackGroundColor BLACK;
        $my_TmpString = "]"
        foreach ($i in 0..($my_SepLength - 29)) { $my_TmpString += -join " " }
        write-host ("{0}" -f $my_TmpString) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
        write-host "|" -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
    }
    catch {
        write-host " [" -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
        if ($_ -like '*Password*failed*') {
            write-host "Bad Password" -NoNewline -ForeGroundColor RED -BackGroundColor BLACK;
            $my_TmpString = "]"
            foreach ($i in 0..($my_SepLength - 39)) { $my_TmpString += -join " " }
            write-host ("{0}" -f $my_TmpString) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
            write-host "|" -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
        }
        elseif ($_ -like '*Bad*credentials*') {
            write-host "Bad Credentials" -NoNewline -ForeGroundColor RED -BackGroundColor BLACK;
            $my_TmpString = "]"
            foreach ($i in 0..($my_SepLength - 42)) { $my_TmpString += -join " " }
            write-host ("{0}" -f $my_TmpString) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
            write-host "|" -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
        }
        else {
            write-host "FAIL" -NoNewline -ForeGroundColor RED -BackGroundColor BLACK;
            $my_TmpString = "]"
            foreach ($i in 0..($my_SepLength - 31)) { $my_TmpString += -join " " }
            write-host ("{0}" -f $my_TmpString) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
            write-host "|" -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
        }
    }
    write-progress -id 2 -parentid 1 -activity " " -status "Enumerating JSON values..." -complete
    ## Collect Cluster Info
}
function collect_node_info($my_TargetIP) {
    ## Collect Disk Count
    $my_TmpString1 = "..Parsing Node Data"
    write-host "|" -NoNewline -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
    write-host ("{0}" -f $my_TmpString1) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
    try {
        $my_RestAPIUrl = "https://$($my_TargetIP):9440/PrismGateway/services/rest/v2.0/disks/"
        $my_RestResponse = Invoke-RestMethod -Method Get -Uri $my_RestAPIUrl -Headers @{Authorization = "Basic $base64AuthInfo" } -Credential $my_Credential -ContentType "application/json"
        $my_DriveHash = @{}
        $my_TmpHash = @{}
        $my_TmpStorageHash = @{}; $my_RestResponse.entities | get-member -membertype properties | foreach { $my_TmpStorageHash.add($_.name, $my_RestResponse.entities.($_.name)) }
        $i = 0
        $my_TmpStorageHash['cvm_ip_address'] | % {
            $my_TmpIP = $_
            $my_NodeIPId = $my_TmpIP.split('.')[3]
            $driveType = $my_TmpStorageHash['storage_tier_name'][$i]
            if (-not $my_TmpHash.containskey($my_NodeIPId)) { $my_TmpHash.add($my_NodeIPId, $driveType) }
            else { $tmpVal = $my_TmpHash[$my_NodeIPId]; $my_TmpHash[$my_NodeIPId] += ",$($driveType)" }
            $i++
        }
        foreach ($h in $my_TmpHash.getenumerator()) { $my_HDD = 1; $my_SSD = 1; $h.value.split(",") | foreach { switch ($_) { "HDD" { $my_HDD++ }; "SSD" { $my_SSD++ } } }; if (-not $my_DriveHash.containskey($h.name)) { $my_DriveHash.add($h.name, "$($my_HDD)|$($my_SSD)") } }
        ## Collect Disk Count
        $my_RestAPIUrl = "https://$($my_TargetIP):9440/PrismGateway/services/rest/v2.0/hosts/"
        $my_RestResponse = Invoke-RestMethod -Method Get -Uri $my_RestAPIUrl -Headers @{Authorization = "Basic $base64AuthInfo" } -Credential $my_Credential -ContentType "application/json"
        $my_ArrNode = @()
        [int]$my_int = 0
        $my_RestResponse.entities | % {
            write-progress -id 2 -parentid 1 -activity " " -status "Enumerating JSON values..." -percentcomplete ($my_int / @($my_RestResponse.entities).count * 100)
            $my_Entities = $_
            $my_TmpNodeObj = new-object psobject
            $my_Cluster_Name = mformat-string($my_ClusterHash.Item($my_TargetIP))
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "Cluster Name" -value $my_Cluster_Name
            $my_Node_Name = mformat-string($my_Entities.name)
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "Host Name" -value $my_Node_Name
            $my_Hypervisor_Address = mformat-string($my_Entities.hypervisor_address)
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "Hypervisor IP" -value $my_Hypervisor_Address.trim('{}')
            $my_Controller_Address = mformat-string($my_Entities.controller_vm_backplane_ip)
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "Controller VM IP" -value $my_Controller_Address.trim('{}')
            $my_IPMI_Address = mformat-string($my_Entities.ipmi_address)
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "IPMI IP" -value $my_IPMI_Address.trim('{}')
            $my_Node_Serial = mformat-string($my_Entities.serial)
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "Node Serial" -value $my_Node_Serial
            $my_Block_Serial = mformat-string($my_Entities.block_serial)
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "Block Serial" -value $my_Block_Serial
            $my_Block_Model = mformat-string($my_Entities.block_model_name)
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "Block Model" -value $my_Block_Model
            $my_TmpStorageHash = @{}; $my_Entities.usage_stats | get-member -membertype properties | foreach { if ($my_Entities.usage_stats.($_.name) -ne '-1') { $my_TmpStorageHash.add($_.name, $my_Entities.usage_stats.($_.name)) } else { $my_TmpStorageHash.add($_.name, 0) } }
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "Storage Capacity" -value "$(format-size($my_TmpStorageHash['storage.capacity_bytes']))"
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "Disks" -value "HDD: $($my_DriveHash[$my_Entities.controller_vm_backplane_ip.split('.')[3]].split('|')[0]) SSD: $($my_DriveHash[$my_Entities.controller_vm_backplane_ip.split('.')[3]].split('|')[1])"
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "Memory" -value  "$(format-size($my_Entities.memory_capacity_in_bytes))"
            $my_CPU_Capacity = $_.cpu_capacity_in_hz / 1000000000; if ($my_CPU_Capacity -eq 0) { $my_CPU_Capacity = "N/A" } else { [string]$my_CPU_Capacity += " GHz" }
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "CPU Capacity" -value $my_CPU_Capacity
            $my_CPU_Model = mformat-string($my_Entities.cpu_model)
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "CPU Model" -value $my_CPU_Model
            $my_CPU_Cores = mformat-string($my_Entities.num_cpu_cores)
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "No. of CPU Cores" -value $my_CPU_Cores
            $my_CPU_Cores = mformat-string($my_Entities.num_cpu_cores)
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "No. of Sockets" -value $my_Entities.num_cpu_sockets
            $my_Num_VMs = mformat-string($my_Entities.num_vms)
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "No. of VMs" -value $my_Num_VMs
            $my_Oplog_Disk_Pct = mformat-string($my_Entities.oplog_disk_pct)
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "Oplog Disk %" -value "$($my_Oplog_Disk_Pct)%"
            $my_CPU_Cores = mformat-string($my_Entities.num_cpu_cores)
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "Oplog Disk Size" -value "$(format-size($my_Entities.oplog_disk_size))"
            $my_Monitored = mformat-string($my_Entities.monitored)
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "Monitored" -value $my_Monitored
            $my_Hypervisor_Full_Name = mformat-string($my_Entities.hypervisor_full_name)
            $my_TmpNodeObj | Add-Member -MemberType NoteProperty -Name "Hypervisor" -value $my_Hypervisor_Full_Name
            $my_ArrNode += $my_TmpNodeObj
            $my_int++
        }
        $my_ArrNode | export-csv $my_File_3 -append -notypeinformation -force
        write-host " [" -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
        write-host "OK" -NoNewline -ForeGroundColor GREEN -BackGroundColor BLACK;
        $my_TmpString = "]"
        foreach ($i in 0..($my_SepLength - 26)) { $my_TmpString += -join " " }
        write-host ("{0}" -f $my_TmpString) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
        write-host "|" -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
    }
    catch {
        write-host " [" -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
        if ($_ -like '*Password*failed*') {
            write-host "Bad Password" -NoNewline -ForeGroundColor RED -BackGroundColor BLACK;
            $my_TmpString = "]"
            foreach ($i in 0..($my_SepLength - 36)) { $my_TmpString += -join " " }
            write-host ("{0}" -f $my_TmpString) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
            write-host "|" -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
        }
        elseif ($_ -like '*Bad*credentials*') {
            write-host "Bad Credentials" -NoNewline -ForeGroundColor RED -BackGroundColor BLACK;
            $my_TmpString = "]"
            foreach ($i in 0..($my_SepLength - 39)) { $my_TmpString += -join " " }
            write-host ("{0}" -f $my_TmpString) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
            write-host "|" -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
        }
        else {
            write-host "FAIL" -NoNewline -ForeGroundColor RED -BackGroundColor BLACK;
            $my_TmpString = "]"
            foreach ($i in 0..($my_SepLength - 28)) { $my_TmpString += -join " " }
            write-host ("{0}" -f $my_TmpString) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
            write-host "|" -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
        }
    }
    write-progress -id 2 -parentid 1 -activity " " -status "Enumerating JSON values..." -complete
}
function collect_cluster_resiliency($my_TargetIP) {
    ## Collect Cluster Resiliency Info
    $my_TmpString1 = "..Parsing Cluster Resiliency"
    write-host "|" -NoNewline -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
    write-host ("{0}" -f $my_TmpString1) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
    try {
        $my_RestAPIUrl = "https://$($my_TargetIP):9440/PrismGateway/services/rest/v2.0/cluster/domain_fault_tolerance_status/"
        $my_RestResponse = Invoke-RestMethod -Method Get -Uri $my_RestAPIUrl -Headers @{Authorization = "Basic $base64AuthInfo" } -Credential $my_Credential -ContentType "application/json"
        $my_ArrClusterResiliency = @()
        [int]$my_int = 0
        $my_Cluster_Name = mformat-string($my_ClusterHash.Item($my_TargetIP))
        $my_RestResponse | % {
            write-progress -id 2 -parentid 1 -activity " " -status "Enumerating JSON values..." -percentcomplete ($my_int / @($my_RestResponse).count * 100)
            $my_TmpClusterResiliencyObj = new-object psobject
            $my_domain_type = $_.domain_type
            $my_TmpClusterResiliencyObj | Add-Member -MemberType NoteProperty -Name "Cluster Name" -value $my_Cluster_Name
            $my_TmpClusterResiliencyObj | Add-Member -MemberType NoteProperty -Name "Type" -value $my_domain_type
            [int]$my_total = 0
            if ($my_domain_type -eq "DISK") {
                $_.component_fault_tolerance_status.psobject.properties | foreach-object { $my_total = $my_total + $_.value.number_of_failures_tolerable }
                if ($my_total -eq 5) { $my_TmpClusterResiliencyObj | Add-Member -MemberType NoteProperty -Name "Resiliency" -value "Good" } else { $my_TmpClusterResiliencyObj | Add-Member -MemberType NoteProperty -Name "Resiliency" -value "Bad" }
            }
            $_.component_fault_tolerance_status.psobject.properties | foreach-object {
                [string]$my_res_name = mformat-string($_.name)
                [string]$my_res_status = $_.value.number_of_failures_tolerable
                [string]$my_res_message = $_.value.details.message
                if ([string]::IsNullOrEmpty($my_res_status)) { $my_res_status = "0" }
                if ($my_res_name -eq "STATIC_CONFIGURATION") { $my_res_name = "Resiliency"; if ($my_res_status -eq "1") { $my_res_status = "Good" } else { if ([string]::IsNullOrEmpty($my_res_message)) { $my_res_status = "Bad" } } }
                if (($my_domain_type -eq "RACKABLE_UNIT") -and ($my_res_status -eq "0")) { $my_res_status = $my_res_message }
                if (($my_domain_type -eq "RACK") -and ($my_res_status -eq "0")) { $my_res_status = $my_res_message }
                $my_TmpClusterResiliencyObj | Add-Member -MemberType NoteProperty -Name $my_res_name -value $my_res_status
            }
            $my_ArrClusterResiliency += $my_TmpClusterResiliencyObj
        }
        $my_ArrClusterResiliency | export-csv $my_File_2 -append -notypeinformation -force
        write-host " [" -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
        write-host "OK" -NoNewline -ForeGroundColor GREEN -BackGroundColor BLACK;
        $my_TmpString = "]"
        foreach ($i in 0..($my_SepLength - 35)) { $my_TmpString += -join " " }
        write-host ("{0}" -f $my_TmpString) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
        write-host "|" -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
    }
    catch {
        write-host " [" -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
        if ($_ -like '*Password*failed*') {
            write-host "Bad Password" -NoNewline -ForeGroundColor RED -BackGroundColor BLACK;
            $my_TmpString = "]"
            foreach ($i in 0..($my_SepLength - 45)) { $my_TmpString += -join " " }
            write-host ("{0}" -f $my_TmpString) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
        }
        elseif ($_ -like '*Bad*credentials*') {
            write-host "Bad Credentials" -NoNewline -ForeGroundColor RED -BackGroundColor BLACK;
            $my_TmpString = "]"
            foreach ($i in 0..($my_SepLength - 48)) { $my_TmpString += -join " " }
            write-host ("{0}" -f $my_TmpString) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
        }
        else {
            write-host "FAIL" -NoNewline -ForeGroundColor RED -BackGroundColor BLACK;
            $my_TmpString = "]"
            foreach ($i in 0..($my_SepLength - 37)) { $my_TmpString += -join " " }
            write-host ("{0}" -f $my_TmpString) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
        }
        write-host "|" -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
    }
    write-progress -id 2 -parentid 1 -activity " " -status "Enumerating JSON values..." -complete
    ## Collect Cluster Info
}

if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
    $my_CertCallback = @"
		using System;
		using System.Net;
		using System.Net.Security;
		using System.Security.Cryptography.X509Certificates;
		public class ServerCertificateValidationCallback {
			public static void Ignore() {
				if (ServicePointManager.ServerCertificateValidationCallback ==null) { ServicePointManager.ServerCertificateValidationCallback += delegate ( Object obj, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors )  { return true; }; }
			}
		}
"@
    Add-Type $my_CertCallback
}
[ServerCertificateValidationCallback]::Ignore()
[net.servicepointmanager]::securityprotocol = [net.securityprotocoltype]::tls12
$my_ScriptPath = $myinvocation.mycommand.path # grab the full path to the scripts execution directory/location.
$my_WorkingDir = split-path $my_ScriptPath # split the execution full path from the filename to create a working directory variable.
$my_File_1 = "$($my_WorkingDir)\Nutanix_Clusters_$((get-date -uformat '%m%d%Y')).csv"
$my_File_2 = "$($my_WorkingDir)\Nutanix_Resiliency_$((get-date -uformat '%m%d%Y')).csv"
$my_File_3 = "$($my_WorkingDir)\Nutanix_Nodes_$((get-date -uformat '%m%d%Y')).csv"
[int]$my_int1 = 0
if (test-path $my_File_1) { remove-item $my_File_1 }
if (test-path $my_File_2) { remove-item $my_File_2 }
if (test-path $my_File_3) { remove-item $my_File_3 }
$my_SepLength = $my_File_2.length + 10
foreach ($i in 0..($my_SepLength)) { $my_LineDiv += "-" }
write-host $my_LineDiv -ForeGroundColor BLACK -BackGroundColor DARKGRAY;
write-host "Collecting " -NoNewline -ForeGroundColor BLACK -BackGroundColor DARKGRAY;
write-host "NUTANI" -NoNewline -ForeGroundColor BLUE -BackGroundColor DARKGRAY;
write-host "X" -NoNewline -ForeGroundColor GREEN -BackGroundColor DARKGRAY;
$my_TmpString = " Cluster Information"
foreach ($i in 0..($my_SepLength - 38)) { $my_TmpString += -join " " }
write-host ("{0}" -f $my_TmpString) -ForeGroundColor BLACK -BackGroundColor DARKGRAY;
write-host $my_LineDiv -ForeGroundColor BLACK -BackGroundColor DARKGRAY;
$my_ClusterHash = @{}
foreach ($my_Cluster in $my_ClusterArrayIP) {
    if (isonline($my_Cluster.trim())) {
        write-progress -id 1 -Activity "Collecting data" -status "Parsing REST data for $($my_Cluster)" -percentcomplete ($my_int1 / $my_ClusterArrayIP.count * 100)
        if (($my_username -eq "") -or ($my_password -eq "")) {	$my_Credentials = $host.ui.promptforcredential("Credentials for $($my_Cluster)", "Please enter your user name and password for $($my_Cluster)", "", "") }
        else {
            $pass = convertto-securestring -asplaintext $my_password -force
            $my_Credentials = new-object -typename system.management.automation.pscredential -argumentlist $my_username, $pass
        }
        if ($my_Credentials) {
            $my_Credential = New-Object –TypeName "System.Management.Automation.PSCredential" -ArgumentList $my_Credentials.username, $my_Credentials.password
            $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $my_Credentials.username, $my_Credentials.password)))
            collect_cluster_info($my_Cluster)
            collect_cluster_resiliency($my_Cluster)
            collect_node_info($my_Cluster)
        }
        else {
            $my_TmpString = "..No credentials!"
            write-host "|" -NoNewline -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
            foreach ($i in 0..($my_SepLength - 19)) { $my_TmpString += -join " " }
            write-host ("{0}" -f $my_TmpString) -NoNewline -ForeGroundColor RED -BackGroundColor BLACK;
            write-host "|" -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
        }
        $my_int1++
    }
}
write-progress -id 1 -Activity "Collecting data" -status "Done..." -complete
write-host $my_LineDiv -ForeGroundColor BLACK -BackGroundColor DARKGRAY;
write-host "|" -NoNewline -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
$my_TmpString = "Done!"
foreach ($i in 0..($my_SepLength - 7)) { $my_TmpString += -join " " }
write-host ("{0}" -f $my_TmpString) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
write-host "|" -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
if ((test-path $my_File_1) -or (test-path $my_File_2)) {
    write-host $my_LineDiv -ForeGroundColor BLACK -BackGroundColor DARKGRAY;
}
if (test-path $my_File_1) {
    write-host "|" -NoNewline -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
    $my_TmpString = "File 1: $($my_File_1)"
    foreach ($i in 0..(($my_SepLength - $my_TmpString.length) - 2)) { $my_TmpString += -join " " }
    write-host ("{0}" -f $my_TmpString) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
    write-host "|" -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
}
if (test-path $my_File_2) {
    write-host "|" -NoNewline -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
    $my_TmpString = "File 2: $($my_File_2)"
    foreach ($i in 0..(($my_SepLength - $my_TmpString.length) - 2)) { $my_TmpString += -join " " }
    write-host ("{0}" -f $my_TmpString) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
    write-host "|" -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
}
if (test-path $my_File_3) {
    write-host "|" -NoNewline -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
    $my_TmpString = "File 3: $($my_File_3)"
    foreach ($i in 0..(($my_SepLength - $my_TmpString.length) - 2)) { $my_TmpString += -join " " }
    write-host ("{0}" -f $my_TmpString) -NoNewline -ForeGroundColor GRAY -BackGroundColor BLACK;
    write-host "|" -ForeGroundColor DARKGRAY -BackGroundColor DARKGRAY;
}
write-host $my_LineDiv -ForeGroundColor BLACK -BackGroundColor DARKGRAY;
$ErrorActionPreference = $my_temperract
exit
########