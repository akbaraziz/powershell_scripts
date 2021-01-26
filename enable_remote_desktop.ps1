# Enable Windows Remote Desktop
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0

# Add Firewall Rule
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"