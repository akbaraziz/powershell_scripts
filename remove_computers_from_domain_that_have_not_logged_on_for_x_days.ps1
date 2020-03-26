$stale = (Get-Date).AddDays(-30) # means 30 days since last logon, can be changed to any number.

Get-ADComputer -Property Name,lastLogonDate -Filter {lastLogonDate -lt $stale} | FT Name,lastLogonDate

Get-ADComputer -Property Name,lastLogonDate -Filter {lastLogonDate -lt $stale} | Remove-ADComputer