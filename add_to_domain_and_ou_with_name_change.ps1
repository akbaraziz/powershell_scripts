$domain = "subzero.com" or @@{DOMAIN}@@
$password = "Yv2Eu*btBwKP47K7" | ConvertTo-SecureString -asPlainText -Force or @@{DOMAIN_CRED.credentials}@@
$username = "svcnutanixsvrdeploy" or @@{DOMAIN_CRED.username}@@
$hostname=hostname
$credential = New-Object System.Management.Automation.PSCredential($username,$password)
Add-Computer -DomainName $domain -OUPath "OU=Virtual Servers,OU=Servers,DC=corp,DC=tcf,DC=biz" -ComputerName $hostname -NewName @@{HOST_NAME}@@ -Credential $credential -Restart

