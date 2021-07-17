$NICs = Get-WMIObject Win32_NetworkAdapterConfiguration `
| where{$_.IPEnabled -eq “TRUE”}
Foreach($NIC in $NICs) {
$NIC.EnableDHCP()
$NIC.SetDNSServerSearchOrder()
}
IPConfig /all