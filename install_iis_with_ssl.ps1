Import-Module -Name ServerManager

Install-WindowsFeature -Name Web-Server -IncludeManagementTools

Import-Module -Name WebAdministration

Get-PSProvider -PSProvider WebAdministration
 
Get-ChildItem -Path IIS:\ 
Get-ChildItem -Path IIS:\Sites
Get-ChildItem -Path IIS:\AppPools
Get-ChildItem -Path IIS:\SslBindings

$Cert = New-SelfSignedCertificate -dnsName "<Server FQDN>" `
    -CertStoreLocation cert:\LocalMachine\My `
    -KeyLength 2048 `
    -noafter (Get-Date).AddYears(1)

$x509 = 'System.Security.Cryptography.X509Certificates.X509Store'
$Store = New-Object -TypeName $x509 -ArgumentList 'Root', 'LocalMachine'
 
$Store.Open('ReadWrite')
$store.Add($Cert)
$Store.Close()

New-WebBinding -Name "Default Web Site" -protocol https -port 443

$Cert | New-Item -path IIS:\SslBindings\0.0.0.0!443

https://&lt; Server FQDN&gt;
