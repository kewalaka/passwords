$password = read-host -prompt "Enter your Password" -AsSecureString
$byteForm = [System.Text.Encoding]::Unicode.GetBytes( (ConvertFrom-SecureString $password) )
$SecurePassword = [Security.Cryptography.ProtectedData]::Protect($byteForm, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
$SecurePassword | Out-File "$PSScriptRoot\mypasswordlocalmachine.txt"


