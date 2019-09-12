$dc = "ENTERPRISE"
$pw = "Password123" | ConvertTo-SecureString -asPlainText -Force
$usr = "$dc\User"
$pc = "hostname"
$creds = New-Object System.Management.Automation.PSCredential($usr,$pw)
Remove-Computer -ComputerName $pc -Credential $creds –Verbose –Restart –Force