function Update-IPv4Address {
<# 
.SYNOPSIS
Update-IpAddress changes the IP of a NIC and deletes the old IP Address configured on that NIC. It can also disable DHCP (or not) for that interface and disable (or not) DNS registration.
.EXAMPLE
Update-IPv4Address -ComputerName Fs1 -InterfaceAlias Ethernet1 -NewIPv4Address 192.168.1.101 -PrefixLength 24 -DisableDhcp Yes -DisableDnsRegistration No -Verbose
Sets IP Address 192.168.1.101 on server Fs1, on NIC "Ethernet1." DHCP is disabled for the NIC, and DNS registration is enabled.
.EXAMPLE
Update-IPv4Address -ComputerName Node1 -InterfaceAlias "Ethernet #5" -NewIPv4Address 10.0.1.5 -PrefixLength 16
Sets IP Address 10.0.1.5/16 on server Node1, on NIC "Ethernet #5." DHCP is disabled for the NIC, and registration is enabled.
.EXAMPLE
Update-IPv4Address -ComputerName Server3 -InterfaceAlias "LAN2" -NewIPv4Address 192.168.5.5 -PrefixLength 24 -DisableDnsRegistration Yes
Sets IP Address 192.168.5.5/24 on server Server3, on the NIC "LAN2." DHCP is disabled for the NIC, and DNS registration is disabled.

#>

[CmdletBinding()]

Param(
[Parameter(Mandatory=$false)][string]$ComputerName = $env:COMPUTERNAME, # Name of the computer where the IP Address will be udpated
[Parameter(Mandatory=$true)][string]$InterfaceAlias, # Network Interface Card on which the IP Address will be updated
[Parameter(Mandatory=$true)][string]$NewIPv4Address, # New IP Address for the selected NIC
[Parameter(Mandatory=$true)][ValidateRange(2,30)][int]$PrefixLength, # Subnet Mask for the new IP Address
[Parameter(Mandatory=$false)][ValidateSet("Yes","No")][string]$DisableDhcp = "Yes", # Define whether DHCP is enabled for the NIC 
[Parameter(Mandatory=$false)][ValidateSet("No","Yes")][string]$DisableDnsRegistration = "No", # Define whether DNS registration is enabled for the NIC
[Parameter(Mandatory=$false)][string]$DnsServer # Name of the DNS server on which the new IP address will be updated and old addresses will be removed (if DNS registration is required). If a DNS server is not mentioned, the command will be run against the logon DC (which is usually a DNS server)
)

# If a Computer Name is not provided, the operation will be performed on the local computer.
if (!($ComputerName)) { Write-Verbose "A computer name was not specified. The operation will be performed on this computer" }

# If DisableDhcp is not specified, DHCP will be disabled by default for the NIC.
if (!($DisableDhcp)) { Write-Verbose "No option was specified for disabling DHCP. DHCP on the NIC $InterfaceAlias will be disabled automatically." }

# If DisableDnsRegistration is not specified, DNS Registration will be enabled by default for the NIC.
if (!($DisableDnsRegistration)) { Write-Verbose "No option was specified for DNS registration. DNS registration for the NIC $InterfaceAlias will be enabled automatically." }

# Test whether the computer is available for remote management. Abort if it cannot be reached.
if (!(Test-NetConnection -ComputerName $ComputerName -CommonTCPPort WINRM -InformationLevel Quiet)) {
    Write-Warning "The computer $ComputerName is not reachable. Make sure the computer name `"$ComputerName`" is correct and that the computer is reachable"
    break
    }

# Test whether the NIC is present on the $ComputerName. Abort if there is no NIC with the specified Name.
if (!(Get-NetAdapter -CimSession $ComputerName | where Name -EQ $InterfaceAlias)) {
    Write-Warning "The NIC $InterfaceAlias could not be found on  $ComputerName. Aborting the operation."
    break
    }

# If DNS registration is required for the NIC, check that the DNS server service is running on the $DnsServer (and abort if it is not).
if ($DisableDnsRegistration -eq "No") {
    if (!(Get-Module -ListAvailable DnsServer)) {
        Write-Warning "The function requires the module DNSServer in order to perform operations on a DNS server. Please install the Powershell Module for DNS Management and run the function again. The syntax for installing the DNS Server PowerShell Module is: Install-WindowsFeature -Name RSAT-DNS-Server"
        break
        }
  
    # If a DNS server is not specified, DNS operations will be attempted on the logon DC (DCs are usually DNS servers).
    if (!($DnsServer)) {
        $DnsServer = ($env:LOGONSERVER).Replace("\","")
        }
    # If the service is not running, the operation will be aborted.
    if (((Get-Service -ComputerName $DnsServer -ServiceName DNS -ErrorAction SilentlyContinue).Status) -ne "Running") {
        Write-Warning "You have selected to enable DNS registration for the NIC $InterfaceAlias but have not provided a valid DNS server. Please run the command again and specify a valid DNS server"
        break
        }
    }

# Get the current IPv4 address(es). These will be replaced with the new IP Address.
$OldIpv4Address = Get-NetIPAddress -CimSession $ComputerName -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 

# Perform changes if the new IP address is different.
if ($NewIPv4Address -notin $OldIpv4Address.IPv4Address) {

    # Set the new IP address to the target on the NIC.
    Write-Verbose  "Adding the IP Address $NewIPv4Address to the NIC $InterfaceAlias on computer $ComputerName"
    New-NetIPAddress -CimSession $ComputerName  -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -IPAddress $NewIpv4Address -PrefixLength $PrefixLength -Type Unicast | Out-Null

    # Configure DNS and DNS registration, if required. Also register the client in DNS.
    if ($DisableDnsRegistration -eq "No") {
        
        # Notify that the function will attempt to use the logon DC for the local computer as DNS server.
        Write-Verbose  "No DNS server was specified. Will use the logon DC ($DnsServer) for the computer $env:COMPUTERNAME as DNS server" 
        
        # Get the IP Address(es) of the DNS server(s) from the local computer.
        $DnsServerIpAddress = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE | where DNSDomain -EQ $env:USERDNSDOMAIN).DNSServerSearchOrder
        
        # Get a list of entries in DNS for the old IP Address(es) for $ComputerName.
        $OldServerDnsEntries = Get-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName "$env:USERDNSDOMAIN" -RRType A | Where-Object {$_.Hostname -like $ComputerName} | Select-Object HostName,@{Name="IpAddress";Expression={$_.RecordData.IPV4Address.IPAddressToString}}
        
        # Set the IP address(es) for the DNS Server(s) on the NIC.
        Write-Verbose  "Add the DNS server(s) $DnsServerIpAddress to the NIC $InterfaceAlias on computer $ComputerName"
        Set-DnsClientServerAddress -CimSession $ComputerName -InterfaceAlias $InterfaceAlias -ServerAddresses $DnsServerIpAddress
        
        # Enable DNS registration for the NIC.
        Write-Verbose  "Enable DNS registration for the interface $InterfaceAlias on $ComputerName"
        Set-DnsClient -CimSession $ComputerName -InterfaceAlias $InterfaceAlias -RegisterThisConnectionsAddress $true
        # Register the server in DNS.
        Register-DnsClient
        
        # Wait for the host to learn the new IP Address of the computer $ComputerName.
        Write-Verbose  "Waiting for this computer ($env:COMPUTERNAME) to learn the new IP Address of the computer $ComputerName..."

        # Wait for the new IP Address to appear in DNS.
        while ($NewIPv4Address -notin ((Resolve-DnsName -Name $ComputerName -Server $DnsServer).IPAddress)) {
            Clear-DnsClientCache
            Start-Sleep -Seconds 1 
            #$CheckIp = (Resolve-DnsName -Name $ComputerName -Server $DnsServer).IPAddress
            }
        }
    
    # Disable DNS registration, if required.
    else {
        Write-Verbose  "Disable DNS registration for the NIC $InterfaceAlias on $ComputerName"
        Set-DNSClient -CimSession $ComputerName -InterfaceAlias $InterfaceAlias –RegisterThisConnectionsAddress $False
        }

    # Disable DHCP, if required.
    if ($DisableDhcp -eq "Yes") {
        Write-Verbose  "Disabling DHCP for the interface $InterfaceAlias on $ComputerName"
        Set-NetIPInterface -CimSession $ComputerName  -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -Dhcp Disabled -ErrorAction SilentlyContinue
        }

    # Go through each of the old IP Addresses and remove them from DNS.
    foreach ($i in $OldIpv4Address) {
        # Clean up old IP address entries in DNS and on the NIC.
        if ($i.IPv4Address -in $OldServerDnsEntries.IpAddress) {
            Write-Verbose  "Removing IP Address $($i.IPv4Address) from DNS"
            Remove-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName "$env:USERDNSDOMAIN" -RRType A -Name $ComputerName -RecordData $i.IPv4Address -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            }
        }

    Clear-DnsClientCache
    # Remove the old IP Addresses from the interface.
    foreach ($i in $OldIpv4Address) {
        Write-Verbose  "Removing IP Address $($i.IPAddress) from NIC $InterfaceAlias on $ComputerName"
        Remove-NetIPAddress -CimSession $ComputerName -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -IPAddress $i.IPAddress -Confirm:$false
        }
    }
# If the new IP address is not different, display a notification that the address is the same.
else { 
    Write-Verbose  "The IP address provided is already set on the NIC `"$InterfaceAlias`" on computer $ComputerName. No change was made" 
    }