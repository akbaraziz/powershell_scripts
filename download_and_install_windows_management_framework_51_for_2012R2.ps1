# Download Windows Management Framework 5.1 for Windows 2012 R2
Invoke-WebRequest -Uri "https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win8.1AndW2K12R2-KB3191564-x64.msu" -outfile "Win8.1AndW2K12R2-KB3191564-x64.msu"

# Install Windows Management Framework 5.1 on Windows 2012 R2
Start-Process -Filepath "$PSScriptRoot/Win8.1AndW2K12R2-KB3191564-x64.msu" -ArgumentList /quiet /norestart

# Remove Installer When Finished
Remove-Item -recurse "C:\Win8.1AndW2K12R2-KB3191564-x64.msu"

# Reboot System
Restart-Computer