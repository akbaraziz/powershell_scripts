Get-Disk -Number 1 | Initialize-Disk -ErrorAction SilentlyContinue
New-Partition -DiskNumber 1 -UseMaximumSize -DriveLetter E
Format-Volume -DriveLetter E -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel Apps -Force