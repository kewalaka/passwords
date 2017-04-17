$KeyFile = "$PSScriptRoot\my.keyfile"
$Key = New-Object Byte[] 24 # You can use 16, 24, or 32 for AES
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
$Key | out-file $KeyFile

$PasswordFile = "$PSScriptRoot\mypassword.txt"
$KeyFile = "$PSScriptRoot\my.keyfile"
$Key = Get-Content $KeyFile
$Password = Read-Host "Please enter your password" -AsSecureString
$Password | ConvertFrom-SecureString -Key $Key | Out-File $PasswordFile
