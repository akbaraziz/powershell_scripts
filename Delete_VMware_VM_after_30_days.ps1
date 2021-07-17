$vms = Get-VM | where {$_.PowerState -eq "PoweredOff"}
$vmPoweredOff = $vms | %{$_.Name}
$events = Get-VIEvent -Start (Get-Date).AddDays(-30) -Entity $vms | 
  where{$_.FullFormattedMessage -like "*is powered off"}
$lastMonthVM = $events | %{$_.Vm.Name}
$moreThan1Month = $vmPoweredOff | where {!($lastMonthVM -contains $_)} 

$moreThan1Month | Remove-VM -DeletePermanently -Confirm:$false
$vmNames = $moreThan1Month | Select -ExpandProperty Name

Send-MailMessage -From report@domain.com -To me@domain.com -SmtpServer mail@domain.com `
-Subject "Removed $($moreThan1Month.Count) VM" -Body ($vmNames | Out-String)