$swhost = '10.10.11.38'
$swuser = '@@{SolarWinds.username}@@'
$swpassword = '@@{SolarWinds.secret}@@'
$swis = Connect-Swis -Hostname $swhost -Username $swuser -Password $swpassword

Install-Module -Name SwisPowerShell
Import-Module SwisPowerShell


$ip_address = Invoke-SwisVerb $swis IPAM.SubnetManagement StartIpReservation @("@@{network}@@", "23", "0") -Verbose | select -expand '#text'

Invoke-SwisVerb -SwisConnection $swis -EntityName IPAM.SubnetManagement -Verb ChangeIpStatus @($ip_address, "Blocked") -Verbose
Invoke-SwisVerb -SwisConnection $swis -EntityName IPAM.SubnetManagement -Verb FinishIpReservation @($ip_address, "Reserved") -Verbose

write-host "ip_address=$ip_address"

