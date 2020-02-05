#Bulk enable NGT on clones
#Matthew Bator
#3-4-2016
#PROVIDED AS IS
​
if ( (Get-PSSnapin -Name NutanixCmdletsPSSnapin -ErrorAction SilentlyContinue) -eq $null ) 
{ 
    Add-PsSnapin NutanixCmdletsPSSnapin 
}
#Get cluster username/password
$cred = Get-Credential
​
#Connect to cluster
$clusterIP = Read-Host "Cluster IP"
Connect-NTNXCluster -Server $clusterIP -Username $cred.Username -Password $cred.Password -AcceptInvalidSSLCerts
​
#Get clone prefix
$clonePrefix = Read-Host "Clone Prefix"
$vms = Get-NTNXVM | where {$_.vmName -match $clonePrefix -and $_.vmName -notmatch "CVM"}
​
#Mount NGT for each cloned VM
foreach ($vm in $vms)
{
	Write-Host "Attempting to mount NGT on VM:" $vm.vmName
	Mount-NTNXGuestTool -VmId $vm.vmId
}
​
Write-Host "Disconnecting from Nutanix cluster:" $clusterIP
Disconnect-NTNXCluster $clusterIP
Write-Host "KTHXBYE!"