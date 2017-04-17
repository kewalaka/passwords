#region: Parmeters
$certificateCommonName = 'SecretEncryptionCert'
$password = 'This is my password.  There are many like it, but this one is mine.'
$targetLocation = '.\mypassword.xml'
#endregion

try
{
    $secureString = $password | ConvertTo-SecureString -AsPlainText -Force

    # Generate our new 32-byte AES key.  I don't recommend using Get-Random for this; the System.Security.Cryptography namespace
    # offers a much more secure random number generator.

    $key = New-Object byte[](32)
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()

    $rng.GetBytes($key)

    $encryptedString = ConvertFrom-SecureString -SecureString $secureString -Key $key

    # get the certificate to be used to encrypt the password
    $thumbprint = (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$certificateCommonName" })[0].Thumbprint
    $cert = Get-Item -Path Cert:\LocalMachine\My\$thumbprint -ErrorAction Stop

    # encrypt the key using the certificate
    $encryptedKey = $cert.PublicKey.Key.Encrypt($key, $true)

    $object = New-Object psobject -Property @{
        Key = $encryptedKey
        Payload = $encryptedString
    }

    $object | Export-Clixml $targetLocation

}
finally
{
    # In the event of an error, we call [array]::Clear() on the AES key's byte array. 
    # It's a good habit to make sure you're not leaving the sensitive data lying around in memory longer than absolutely necessary. 
    if ($null -ne $key) { [array]::Clear($key, 0, $key.Length) }
}    