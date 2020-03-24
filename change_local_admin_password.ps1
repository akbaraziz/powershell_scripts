$password = Read-Host "Enter the password" -AsSecureString
$confirmpassword = Read-Host "Confirm the password" -AsSecureString
$pwd1_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.
  InteropServices.Marshal]::SecureStringToBSTR($password))
$pwd2_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.
  InteropServices.Marshal]::SecureStringToBSTR($confirmpassword))
if($pwd1_text -ne $pwd2_text) {
   Write-Error "Entered passwords are not same. Script is exiting"
exit
}