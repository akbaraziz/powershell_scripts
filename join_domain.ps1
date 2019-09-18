$HOSTNAME = "Win-@@{calm_unique}@@"

function Set-Hostname{
  [CmdletBinding()]
  Param(
      [parameter(Mandatory=$true)]
      [string]$Hostname
)
  if ($Hostname -eq  $(hostname)){
    Write-Host "Hostname already set."
  } else{
    Rename-Computer -NewName $HOSTNAME -ErrorAction Stop
  }
}

function JointoDomain {
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
  
  if ($env:computername  -eq $env:userdomain) {
    Write-Host "Not in domain"
    $adminname = "$DomainName\$Username"
    $adminpassword = ConvertTo-SecureString -asPlainText -Force -String "$Password"
    Write-Host "$adminname , $password"
    $credential = New-Object System.Management.Automation.PSCredential($adminname,$adminpassword)
    Add-computer -DomainName $DomainName -Credential $credential -force -Options JoinWithNewName,AccountCreate -PassThru -ErrorAction Stop
  } else {
     Write-Host "Already in domain"
  }
}

if ($HOSTNAME -ne $Null){
  Write-Host "Setting Hostname"
  Set-Hostname -Hostname $HOSTNAME
}

add-computer -DomainName "@@{DOMAIN}@@" -OUPath "OU=Servers,DC=gso,DC=lab" -Username "@@{DOMAIN_CRED.username}@@" -Password "@@{DOMAIN_CRED.secret}@@"

Restart-Computer -Force -AsJob
exit 0
