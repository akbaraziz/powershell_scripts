[CmdletBinding()]
param (
    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true,
        HelpMessage = "Mac Address with colons."
    )]
    [ValidatePattern('^[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}$')]
    [string]$macAddress
)

# Changes the MAC address to lower since IPv6 doesn't like uppercase, and splits it at the colons
$macParts = $macAddress.ToLower().Split(":")
# [int]("0x" + $macParts[0])
    # Converts the first octet from hex to int
# ([int]("0x" + $macParts[0]) -bor 2)
    # Takes the new int and does a bitwise OR against int 2
# '{0:x02}'
    # Converts the int back to hex
$macParts[0] = '{0:x02}' -f ([int]("0x" + $macParts[0]) -bor 2)
# Creates the link-local IPv6 address using the MAC parts ("octects")
$ipv6Address = "fe80::{0}{1}:{2}ff:fe{3}:{4}{5}" -f $macParts

Out-Host -InputObject "The link-local IPv6 address is: $ipv6Address"
Out-Host -InputObject "The URL for IPMI is: https://[$ipv6Address]"