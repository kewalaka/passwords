# Mary is smarter than the average bear, and has encrypted her password
$encrypted = Get-Content "$PSScriptRoot\mypassword.txt"
$user = "Prod\Mary"
$password = ConvertTo-SecureString $encrypted

# at this point, '$password' is a SecureString
# > $password
# System.Security.SecureString

# Powershell's prefer method of passing usernames and passwords is via a PSCredential object:
$MyCredentials = New-Object -TypeName System.Management.Automation.PSCredential `
    -ArgumentList $user, $password
# password is available in plain text like this:
$decryptedPassword =$MyCredentials.GetNetworkCredential().password

# Alternatively, if you just want to access the password directly:
$decryptedPassword2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
