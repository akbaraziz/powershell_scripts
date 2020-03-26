# Enable Windows Remote Desktop
Invoke-Command -Computername <computer name> -ScriptBlock {Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 0 }

# Add Firewall Rule
Invoke-Command -Computername <computer name> -ScriptBlock {Enable-NetFirewallRule -DisplayGroup "Remote Desktop"}