$Credentials = Get-Credential
$Credentials.Password | ConvertFrom-SecureString | Set-Content C:\test\password.txt
$Username = $Credentials.Username
$Password = Get-Content “C:\test\password.txt” | ConvertTo-SecureString
$Credentials = New-Object System.Management.Automation.PSCredential $Username,$Password