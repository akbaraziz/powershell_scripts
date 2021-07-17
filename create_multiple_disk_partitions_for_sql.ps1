$start_time = Get-Date

# Initialize and Format Drive E - DB_INSTALL
Get-Disk | Where-Object partitionstyle -eq 'raw'
Initialize-Disk -Number 1 -PartitionStyle MBR -PassThru -ErrorAction SilentlyContinue
New-Partition -DiskNumber 1 -DriveLetter E -UseMaximumSize
Format-Volume -DriveLetter E -FileSystem NTFS -AllocationUnitSize 4096 -NewFileSystemLabel "SQLINSTALL" -Confirm:$false

# Initialize and Format Drive F - DATA
Get-Disk | Where-Object partitionstyle -eq 'raw'
Initialize-Disk -Number 2 -PartitionStyle MBR -PassThru -ErrorAction SilentlyContinue
New-Partition -DiskNumber 2 -DriveLetter F -UseMaximumSize
Format-Volume -DriveLetter F -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel "DATA" -Confirm:$false

# Initialize and Format Drive G - TRANSACTIONS
Get-Disk | Where-Object partitionstyle -eq 'raw'
Initialize-Disk -Number 3 -PartitionStyle MBR -PassThru -ErrorAction SilentlyContinue
New-Partition -DiskNumber 3 -DriveLetter G -UseMaximumSize
Format-Volume -DriveLetter G -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel "TRANSACTIONS" -Confirm:$false

# Initialize and Format Drive H - ANALYSIS
Get-Disk | Where-Object partitionstyle -eq 'raw'
Initialize-Disk -Number 4 -PartitionStyle MBR -PassThru -ErrorAction SilentlyContinue
New-Partition -DiskNumber 4 -DriveLetter H -UseMaximumSize
Format-Volume -DriveLetter H -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel "ANALYSIS" -Confirm:$false

# Initialize and Format Drive I - MONITORING
Get-Disk | Where-Object partitionstyle -eq 'raw'
Initialize-Disk -Number 5 -PartitionStyle MBR -PassThru -ErrorAction SilentlyContinue
New-Partition -DiskNumber 5 -DriveLetter I -UseMaximumSize
Format-Volume -DriveLetter I -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel "MONITORING" -Confirm:$false

# Initialize and Format Drive J - ARCHIVE_1
Get-Disk | Where-Object partitionstyle -eq 'raw'
Initialize-Disk -Number 6 -PartitionStyle MBR -PassThru -ErrorAction SilentlyContinue
New-Partition -DiskNumber 6 -DriveLetter J -UseMaximumSize
Format-Volume -DriveLetter J -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel "ARCHIVE_1" -Confirm:$false

# Initialize and Format Drive K - ARCHIVE_2
Get-Disk | Where-Object partitionstyle -eq 'raw'
Initialize-Disk -Number 7 -PartitionStyle MBR -PassThru -ErrorAction SilentlyContinue
New-Partition -DiskNumber 7 -DriveLetter K -UseMaximumSize
Format-Volume -DriveLetter K -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel "ARCHIVE_2" -Confirm:$false

# Initialize and Format Drive L - LOGS_1
Get-Disk | Where-Object partitionstyle -eq 'raw'
Initialize-Disk -Number 8 -PartitionStyle MBR -PassThru -ErrorAction SilentlyContinue
New-Partition -DiskNumber 8 -DriveLetter L -UseMaximumSize
Format-Volume -DriveLetter L -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel "LOGS_1" -Confirm:$false

# Initialize and Format Drive M - LOGS_2
Get-Disk | Where-Object partitionstyle -eq 'raw'
Initialize-Disk -Number 9 -PartitionStyle MBR -PassThru -ErrorAction SilentlyContinue
New-Partition -DiskNumber 9 -DriveLetter M -UseMaximumSize
Format-Volume -DriveLetter M -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel "LOGS_2" -Confirm:$false

# Initialize and Format Drive P - PAGEFS
Get-Disk | Where-Object partitionstyle -eq 'raw'
Initialize-Disk -Number 10 -PartitionStyle MBR -PassThru -ErrorAction SilentlyContinue
New-Partition -DiskNumber 10 -DriveLetter P -UseMaximumSize
Format-Volume -DriveLetter P -FileSystem NTFS -AllocationUnitSize 4096 -NewFileSystemLabel "PAGEFS" -Confirm:$false

# Initialize and Format Drive T - TEMP_1
Get-Disk | Where-Object partitionstyle -eq 'raw'
Initialize-Disk -Number 11 -PartitionStyle MBR -PassThru -ErrorAction SilentlyContinue
New-Partition -DiskNumber 11 -DriveLetter T -UseMaximumSize
Format-Volume -DriveLetter T -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel "TEMP_1" -Confirm:$false

# Initialize and Format Drive U - TEMP_2
Get-Disk | Where-Object partitionstyle -eq 'raw'
Initialize-Disk -Number 12 -PartitionStyle MBR -PassThru -ErrorAction SilentlyContinue
New-Partition -DiskNumber 12 -DriveLetter U -UseMaximumSize
Format-Volume -DriveLetter U -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel "TEMP_2" -Confirm:$false

Write-Output "Time taken: $((Get-Date).Subtract($start_time).seconds) Second(s)"