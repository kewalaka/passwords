$certificateCommonName = 'SecretEncryptionCert'

try
{
    # load the password and encrypted key from the XML file
    $object = Import-Clixml -Path .\mypassword.xml

    # get the certificate stored on the machine
    $thumbprint = (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$certificateCommonName" })[0].Thumbprint
    $cert = Get-Item -Path Cert:\LocalMachine\My\$thumbprint -ErrorAction Stop

    # use the certificate to decrypt the key
    $key = $cert.PrivateKey.Decrypt($object.Key, $true)

    # $object.Payload has the secret, here, we convert it to a secure string:
    $secureString = $object.Payload | ConvertTo-SecureString -Key $key

    # Alternatively, if you just want to access the password directly:
    $decryptedPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString))
    
}
finally
{
    if ($null -ne $key) { [array]::Clear($key, 0, $key.Length) }
}