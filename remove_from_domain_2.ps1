$HOSTNAME = "Win-@@{calm_unique}@@"

function RemoveFromDomain {
  [CmdletBinding()]
  Param(
      [parameter(Mandatory=$true)]
      [string]$DomainName,
      [parameter(Mandatory=$false)]
      [string]$OU,
      [parameter(Mandatory=$true)]
      [string]$Username,
      [parameter(Mandatory=$true)]
      [string]$Password,
  )
  $adapter = Get-NetAdapter | ? {$_.Status -eq "up"}
  $adapter | Set-DnsClientServerAddress -ServerAddresses $Server

  $adminname = "$DomainName\$Username"
  $adminpassword = ConvertTo-SecureString -asPlainText -Force -String "$Password"
  Write-Host "$adminname , $password"
  $credential = New-Object System.Management.Automation.PSCredential($adminname,$adminpassword)
  Remove-computer -UnjoinDomaincredential $credential -PassThru -Verbose -Force
  Write-Host "Removed from domain @@{DOMAIN}@@"
}

RemoveFromDomain -DomainName "@@{DOMAIN}@@" -Username "@@{DOMAIN_CRED.username}@@" -Password "@@{DOMAIN_CRED.secret}@@"