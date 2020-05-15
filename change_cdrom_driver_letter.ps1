# Find drives with no partitions
$getInitDrive = gwmi -Query "Select * from Win32_diskdrive where Partitions = 0"
If (!$getInitDrive)
{
    Exit
}
# Get CDROM drive, move drive letter to E:
$getDrive = gwmi -query "Select DeviceID from Win32_LogicalDisk Where DriveType=5"
$cdDrive = gwmi Win32_Volume -filter "DriveLetter=’$($getDrive.DeviceId)’"
$cdDrive.DriveLetter=’E:’
$cdDrive.Put()
# Init drive
$newDisk = $getInitDrive.DeviceID.Replace("\\.\PHYSICALDRIVE", "")
$DPCommands = @"
select disk $newDisk
online disk noerr
attribute disk clear readonly
create partition primary
format fs=ntfs label=WriteCache quick
assign letter D:
"@
$DPCommands | diskpart