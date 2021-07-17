param($NodeToDelete= "")
if($NodeToDelete-eq ""){
    Write-Error "You need to specify a name to delete" -Category NotSpecified -CategoryReason "Need a name to delete" -CategoryTargetName "Missing parameter" -CategoryTargetType "DNS name"
    return
}

$DNSServer = "dns01.rcmtech.co.uk"
$ZoneName = "rcmtech.co.uk"
$ReverseZoneName = "168.192.in-addr.arpa"
$NodeARecord = $null
$NodePTRRecord = $null


Write-Host "Check for existing DNS record(s)"
$NodeARecord = Get-DnsServerResourceRecord -ZoneName $ZoneName -ComputerName $DNSServer -Node $NodeToDelete -RRType A -ErrorAction SilentlyContinue
if ($NodeARecord -eq $null) {
    Write-Host "No A record found"
}
else {
    $IPAddress = $NodeARecord.RecordData.IPv4Address.IPAddressToString
    $IPAddressArray = $IPAddress.Split(".")
    $IPAddressFormatted = ($IPAddressArray[3] + "." + $IPAddressArray[2])
    $NodePTRRecord = Get-DnsServerResourceRecord -ZoneName $ReverseZoneName -ComputerName $DNSServer -Node $IPAddressFormatted -RRType Ptr -ErrorAction SilentlyContinue
    if ($NodePTRRecord -eq $null) {
        Write-Host "No PTR record found"
    }
    else {
        Remove-DnsServerResourceRecord -ZoneName $ReverseZoneName -ComputerName $DNSServer -InputObject $NodePTRRecord -Force
        Write-Host ("PTR gone: " + $IPAddressFormatted)
    }
    Remove-DnsServerResourceRecord -ZoneName $ZoneName -ComputerName $DNSServer -InputObject $NodeARecord -Force
    Write-Host ("A gone: " + $NodeARecord.HostName)
}