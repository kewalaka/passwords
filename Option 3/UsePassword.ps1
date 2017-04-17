# Mary is getting cunning and has secured her encrypted password with a keyfile
# in this example the encrypted password is stored in a script:
$encrypted = '76492d1116743f0423413b16050a5345MgB8AFkAbABqAEkANwBXADgANwAzADkAdQBTAEEAYgAyAEkAegBhAFQAcAB2AFEAPQA9AHwAOQA3AGIAMQBjADQAZgBlADgAYQA3ADYAMABmAGEAYgAxADkANwBiADQAYwAwADMAYgA1AGIANQA3ADcAMwA3AA=='

# this is the keyfile used to encrypt and decrypt the password
$KeyFile = "$PSScriptRoot\my.keyfile"
$user = "Mary"
# the important part is the 'Key' parameter, which is how you specify 
$password = $encrypted | ConvertTo-SecureString -Key (Get-Content $KeyFile)

# As per Option 2 - decrypt using a PSCredential
$MyCredentials = New-Object -TypeName System.Management.Automation.PSCredential `
    -ArgumentList $user, $password
# password is available in plain text like this:
$decryptedPassword =$MyCredential.GetNetworkCredential().password

# .. or again, as per Option 2, if you just want to access the password directly:
$decryptedPassword2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))