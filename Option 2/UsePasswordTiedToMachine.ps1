
$encrypted = Get-Content 'mypasswordlocalmachine.txt'
$byteForm = [Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
$password = [System.Text.Encoding]::Unicode.GetString($byteForm) | ConvertTo-SecureString

# could use as a PSCredential, see Option 2
# below, we just decrypt using [System.Runtime.InteropServices.Marshal]
$decryptedPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
