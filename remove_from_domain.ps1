$dc = "@@{DOMAIN_NAME}@@" # Specify the domain to join.
$pw = "password" | ConvertTo-SecureString -asPlainText –Force # Specify the password for the domain admin.
$usr = "$dc\Administrator" # Specify the domain admin account.
$creds = New-Object System.Management.Automation.PSCredential($usr,$pw)
$ou = "OU=Servers,DC=contoso,DC=com" # Specify the OU to removed the system.
$pc = "@@{HOST_NAME}@@" # Specify Computer Name
Remove-Computer -ComputerName $pc -Credential $creds -OUPATH $ou -Force -Verbose -Restart # This will restart the computer