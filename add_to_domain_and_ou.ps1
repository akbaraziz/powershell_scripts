$dc = "@@{DOMAIN_NAME}@@" # Specify the domain to join.
$pw = "password" | ConvertTo-SecureString -asPlainText –Force # Specify the password for the domain admin.
$usr = "$dc\administrator" # Specify the domain admin account.
$creds = New-Object System.Management.Automation.PSCredential($usr,$pw)
$ou = "OU=Servers,DC=contoso,DC=com" # Specify the OU to add the system.
$NewComputerName = "@@{HOST_NAME}@@" # Specify new Computer Name
Add-Computer -DomainName $dc -Credential $creds -NewName $NewComputerName -OUPATH $ou -Force -Verbose
Add-LocalGroupMember -Group "Administrators" -Member "Contoso\Administrator"
Restart-Computer -Force