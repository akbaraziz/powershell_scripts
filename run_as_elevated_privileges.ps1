$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
if ($myWindowsPrincipal.IsInRole($adminRole))
{
$Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + “(Elevated)”
clear-host
}
else {
$newProcess = new-object System.Diagnostics.ProcessStartInfo “PowerShell”;
$newProcess.Arguments = $myInvocation.MyCommand.Definition;
$newProcess.Verb = “runas”;
[System.Diagnostics.Process]::Start($newProcess);
exit
}
# Add the code of your script here