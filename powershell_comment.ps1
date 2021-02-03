<#
.SYNOPSIS
  Powers off or migrates VMs to a different VMHost then applies a baseline and remediate the host.
.DESCRIPTION
  <Brief description of script>
.PARAMETER VIServer
    The name or IP address of your vCenter server appliance.
.PARAMETER VMHost
    The name or IP address of the VMHost you want to upgrade.
.PARAMETER Baseline
    The name of the baseline you want to attach to hosts.
.INPUTS
  None.
.OUTPUTS
  Log file stored in C:\Windows\Temp\<name>.log>
  Email will be sent once script completes.
.NOTES
  Version:        1.0
  Author:         
  Creation Date:  
  Purpose: 
  
.EXAMPLE
  #This starts a host upgrade on the ContosoVIserver in the cluster Contoso_Cluster on the VMHost Contoso-ESXi01.
  New-VMHostUpgrade -VIServer "ContosoVIServer.Domain.com" -Cluster "Contoso_Cluster" -VMHost "Contoso-ESXi01.domain.com" -UserName "Domain\Username" 

  #This starts a host upgrade on the ContosoVIserver in the cluster Contoso_Cluster on the VMHost's contained in the text file "c:\temp\VMHostList.txt"
  New-VMHostUpgrade -VIServer "ContosoVIServer.Domain.com" -Cluster "Contoso_Cluster" -VMHostList "c:\temp\VMHostList.txt" -UserName "Domain\Username" 
#>