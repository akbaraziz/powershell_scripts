# Script author: OutsideSys
# Script site: https://itpro.outsidesys.com/2015/12/13/lab-build-a-domain-controller-with-powershell/
# Script date: 06/30/2020
# Script ver: 1.0
# Script tested on OS: Windows 2016 DataCenter Edition
# Script purpose: Install AD, Promote to DC, Create OU, Create Users, Disable Admin Account


#--------------------------------------------------

# Setup the NIC, Rename the Computer, and Reboot
# Define the Computer Name
$computerName = "dc1"

# Define the IPv4 Addressing
$IPv4Address = "10.10.100.25"
$IPv4Prefix = "24"
$IPv4GW = "10.10.100.1"
$IPv4DNS = "8.8.8.8"

# Get the Network Adapter's Prefix
$ipIF = (Get-NetAdapter).ifIndex

# Add IPv4 Address, Gateway, and DNS
New-NetIPAddress -InterfaceIndex $ipIF -IPAddress $IPv4Address -PrefixLength $IPv4Prefix -DefaultGateway $IPv4GW
Set-DNSClientServerAddress –interfaceIndex $ipIF –ServerAddresses $IPv4DNS

# Rename the Computer, and Restart
Rename-Computer -NewName $computerName -force
Restart-Computer


# Install Active Directory Services and Promote to DC 
$domainName  = "contoso.com"
$netBIOSname = "CONTOSO"
$mode  = "Win2016"

Install-WindowsFeature AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools

Import-Module ADDSDeployment

$forestProperties = @{

    DomainName           = $domainName
    DomainNetbiosName    = $netBIOSname
    ForestMode           = $mode
    DomainMode           = $mode
    CreateDnsDelegation  = $false
    InstallDns           = $true
    DatabasePath         = "C:\Windows\NTDS"
    LogPath              = "C:\Windows\NTDS"
    SysvolPath           = "C:\Windows\SYSVOL"
    NoRebootOnCompletion = $false
    Force                = $true

}

Install-ADDSForest @forestProperties

Configure DNS, Sites and Services, and Time Keeping
# Define DNS and Sites & Services Settings
$IPv4netID = "10.10.100.0/24"
$siteName = "LAB"
$location = "New Lab City"

# Define Authoritative Internet Time Servers
$timePeerList = "0.us.pool.ntp.org 1.us.pool.ntp.org"

# Add DNS Reverse Lookup Zones
Add-DNSServerPrimaryZone -NetworkID $IPv4netID -ReplicationScope 'Forest' -DynamicUpdate 'Secure'

# Make Changes to Sites & Services
$defaultSite = Get-ADReplicationSite | Select DistinguishedName
Rename-ADObject $defaultSite.DistinguishedName -NewName $siteName
New-ADReplicationSubnet -Name $IPv4netID -site $siteName -Location $location

# Re-Register DC's DNS Records
Register-DnsClient

# Enable Default Aging/Scavenging Settings for All Zones and this DNS Server
Set-DnsServerScavenging –ScavengingState $True –ScavengingInterval 7:00:00:00 –ApplyOnAllZones
$Zones = Get-DnsServerZone | Where-Object {$_.IsAutoCreated -eq $False -and $_.ZoneName -ne 'TrustAnchors'}
$Zones | Set-DnsServerZoneAging -Aging $True

# Set Time Configuration
w32tm /config /manualpeerlist:$timePeerList /syncfromflags:manual /reliable:yes /update

# Build an OU Structure
$baseDN = "DC=contoso,DC=com"
$resourcesDN = "OU=Resources," + $baseDN

New-ADOrganizationalUnit "Resources" -path $baseDN
New-ADOrganizationalUnit "Admin Users" -path $resourcesDN
New-ADOrganizationalUnit "Groups Security" -path $resourcesDN
New-ADOrganizationalUnit "Service Accounts" -path $resourcesDN
New-ADOrganizationalUnit "Workstations" -path $resourcesDN
New-ADOrganizationalUnit "Servers" -path $resourcesDN
New-ADOrganizationalUnit "Users" -path $resourcesDN

# Enable the Recycle Bin 
$ForestFQDN = "contoso.com"
$SchemaDC   = "dc1.contoso.com"

Enable-ADOptionalFeature –Identity 'Recycle Bin Feature' –Scope ForestOrConfigurationSet –Target $ForestFQDN -Server $SchemaDC -confirm:$false

# Create a Privileged Account
$userProperties = @{

    Name                 = "John Dougherty EA"
    GivenName            = "John"
    Surname              = "Dougherty EA"
    DisplayName          = "John Dougherty EA"
    Path                 = "OU=Admin Users,OU=Resources,DC=Contoso,DC=com"
    SamAccountName       = "dougherty-ea"
    UserPrincipalName    = "dougherty-ea@contoso.com"
    AccountPassword      = $Password
    PasswordNeverExpires = $True
    Enabled              = $True
    Description          = "Contoso Enterprise Admin"

}

New-ADUser @userProperties

# Add Privileged Account to EA, DA, & SA Groups
Add-ADGroupMember "Domain Admins" $userProperties.SamAccountName
Add-ADGroupMember "Enterprise Admins" $userProperties.SamAccountName
Add-ADGroupMember "Schema Admins" $userProperties.SamAccountName

# Create a Non-Privileged Account 
# Create a Non-Privileged User Account
$userProperties = @{

    Name                 = "John Dougherty"
    GivenName            = "John"
    Surname              = "Dougherty"
    DisplayName          = "John Dougherty"
    Path                 = "OU=Users,OU=Resources,DC=Contoso,DC=com"
    SamAccountName       = "john.dougherty"
    UserPrincipalName    = "john.dougherty@contoso.com"
    AccountPassword      = $Password
    PasswordNeverExpires = $True
    Enabled              = $True
    Description          = "Contoso User"

}

New-ADUser @userProperties

# Secure and Disable the Administrator Account
Set-ADUser Administrator -AccountNotDelegated:$true -SmartcardLogonRequired:$true -Enabled:$false

# Create an AD Snapshot
C:\Windows\system32\ntdsutil.exe snapshot "activate instance ntds" create quit quit
