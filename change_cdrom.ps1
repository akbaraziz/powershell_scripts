Get-WmiObject -Class Win32_volume -Filter "DriveLetter = 'D:'" |Set-WmiInstance -Arguments @{DriveLetter='R:'}
