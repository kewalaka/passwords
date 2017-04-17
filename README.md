# Dealing with passwords in PowerShell

Oftentimes, it is necessary to store a password or some other secret within a script.  It’s not uncommon to see password in plain text in a script.  The obvious concern here is anyone who can read the script immediately knows the password.  If you use a source code repository to version control your scripts (which since you're reading this on GitHub, I assume you do), this means your passwords are stored in plain text in this repository.  

In this article, I’ll discuss and provide examples of a number of other options, starting with the straightforward, ending by leveraging the mechanism used by Microsoft to secure PowerShell DSC configurations.

Whilst this article discusses passwords, it can obviously be applied to any secret that you want to secure or encrypt.

**NB** - In all of these examples, I have purposefully not excluded my password files from GitHub so you can see what they look like.  Make sure you don't do this with your real passwords!  Use a  [.gitignore](https://git-scm.com/docs/gitignore) file to hide things you don't want in source control.  If you save your secrets to source control by mistake, this walks you through [removing sensitive data from a repository](https://help.github.com/articles/removing-sensitive-data-from-a-repository/), but don't forget to then change the potentially compromised password.

## Option 1 – Store the password in a separate file outside the script

This is a really simple approach requiring little effort.  The password is stored in a text file format outside the main script, in the current directory

```powershell

# simple one password in a text file
$password = Get-Content .\mypassword.txt

```

You can also use a structured file format like JSON to store all environment specific settings:

```powershell

# get secrets and environmental settings from a .json file
> $settings = Get-Content .\environmentals.json | ConvertFrom-Json
> $settings

UserName Password                      Domain
-------- --------                      ------
Bob      Oh dear, you know my password prod
Mary     You know my password too!     prod

# to illustrate how to read a specific password...
> $MaryPassword = ( $settings | where {$_.UserName -eq 'Mary'} ).Password
> $MaryPassword
You know my password too!

```

This solves the version control issue, as long as you’re careful not to check in the external file, and also allows the same script to be used in multiple environments.  I would generally encourage you to environmental settings out to a separate file, however, storing passwords in plain text is not ideal, so lets explore more options.

## Option 2 – Use a Windows account to encrypt the password

You're not so keen on storing passwords in plain text?  Good.

Another approach uses your Windows credentials to encrypt the password, you can create an encrypted password using the following code (see [CreatePassword.ps1](https://github.com/kewalaka/passwords/blob/master/Option%202/CreatePassword.ps1)):

``` powershell
$password = read-host -prompt "Enter your Password" -AsSecureString
# this will store the encrypted password in 'mypassword.txt'
ConvertFrom-SecureString $password | out-file .\mypassword.txt
```

The resulting password  is tied to your user profile **on the machine you used to create the password** - only by using the same machine + your same user account will you be able to decrypt the password successfully.  This is provided by [Windows Data Protection API (DPAPI)](https://en.wikipedia.org/wiki/Data_Protection_API).

If you inspect the contents of [mypassword.txt](https://raw.githubusercontent.com/kewalaka/passwords/master/Option%202/mypassword.txt), it will look something like this (yours will be different, because it will be created for your user on your machine).  It will still look scarily long!

```
01000000d08c9ddf0115d1118c7a00c04fc297eb010000007d703781d2413e41a30a32725ca37e8000000000020000000000106600000001000020000000e84793fdafb6f74aa100696ce897ec3efb1f27152ba4f3a897cf30d93f996d50000000000e80000000020000200000001b9e4de1e8b977e2490e28956b27d63ac594fbb714a4808a36199a0c3148f06920000000730f687d4809e94db81fa4ab0cfb99c927b009033931783faf67f7676bcf24a540000000629d733a1e1bfe79ddc83dd98e579c3934cd8bf304cad02227446ebe2299c9940851abbfd1ad2d2f9edd11554343680194d06e11098e720f34e8aa7eeeb42fb4
```

There are a number of ways to decrypt this password (see below, or [UsePassword.ps1](https://github.com/kewalaka/passwords/blob/master/Option%202/UsePassword.ps1))

``` powershell
# Mary is smarter than the average bear, and has encrypted her password
$encrypted = Get-Content "$PSScriptRoot\mypassword.txt"
$user = "Prod\Mary"
$password = ConvertTo-SecureString $encrypted

# at this point, '$password' is a SecureString
# > $password
# System.Security.SecureString

# Powershell's prefer method of passing usernames and passwords is via a PSCredential object
# this includes both the domain\username and the password:
$MyCredentials = New-Object -TypeName System.Management.Automation.PSCredential `
    -ArgumentList $user, $password
# password is available in plain text like this:
$decryptedPassword =$MyCredential.GetNetworkCredential().password

# Alternatively, if you just want to access the password directly:
$decryptedPassword2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
```

In order to ensure the password is being decrypted OK, you'll need access to the machine & the user account used to create the password.  It also means that anyone testing or developing the script will need to create encrypted credentials.

Instead of tieing the password to the user profile on the machine, it is also possible to tie it to the localmachine account (aka 'SYSTEM').  See [CreatePasswordTiedToMachine.ps1](https://github.com/kewalaka/passwords/blob/master/Option%202/CreatePasswordTiedToMachine.ps1) and [UsePasswordTiedToMachine.ps1](https://github.com/kewalaka/passwords/blob/master/Option%202/UsePasswordTiedToMachine.ps1) for examples.  This allows anyone using the machine to decrypt the password.

This is quite a secure approach, but not very convenient or scalable.  Definitely worth considering if you don't mind the limitations.


## Option 3 - Use a 'key' stored in a separate file to encrypt the password

This is similiar to option 1, however, instead of simply storing the password unencrypted in a file, the means to encrypt & decrypt the file is via a 'keyfile'.  

The benefit of this approach is it is more portable, as long as you have the keyfile, you can decrypt the password.

The downside is obvious - if the keyfile is compromised, or accidentally checked into source control, it's not much better than having the password in plain text.

Here's how to create the encrypted password, stored to mypassword.txt and keyfile, stored to my.keyfile.   This is from [CreatePassword.ps1](https://github.com/kewalaka/passwords/blob/master/Option%203/CreatePassword.ps1):

``` powershell
$KeyFile = "$PSScriptRoot\my.keyfile"
$Key = New-Object Byte[] 24 # You can use 16, 24, or 32 for AES
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
$Key | out-file $KeyFile

$PasswordFile = "$PSScriptRoot\mypassword.txt"
$KeyFile = "$PSScriptRoot\my.keyfile"
$Key = Get-Content $KeyFile
$Password = Read-Host "Please enter your password" -AsSecureString
$Password | ConvertFrom-SecureString -Key $Key | Out-File $PasswordFile
```

The following illustrates use, again from [UsePassword.ps1](https://github.com/kewalaka/passwords/blob/master/Option%203/UsePassword.ps1):

``` powershell
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
$decryptedPassword2 = $Marshal::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
```

Protecting the keyfile is important, as that can be used by anyone to decrypt the password.

## Option 4 - Use a certificate stored in the LocalMachine store to encrypt passwords

One problem with Option 3, is the importance placed on the keyfile.  An alternative approach is to use TLS (aka "SSL") certificates, as explained by [David Wyatt's article](https://powershell.org/2014/02/01/revisited-powershell-and-encryption/).  

Certificate encryption works by having a pair of keys
 - A "public" key, widely shared.  Anyone can encrypt secrets with this.
 - A "private" key, not shared.  Only the holder of the paired private key can decrypt secrets that have been encrypted by the public key.

This is quite a complex example, that I combine this with guidance from Microsoft on [how to secure passwords in Powershell DSC](https://msdn.microsoft.com/en-us/powershell/dsc/securemof).  Combining these approaches is purely optional - there is nothing to prevent you from creating your own certificates specficially for encrypting Powershell script secrets.

### Create a certificate ###

First, we create the necessary certificate + keys.  Self-signed certificates (i.e. ones that you can  create yourself for free) are perfectly fine for this, even in a production environment.  However, as with the keyfile, protecting the private key is important, as if that is lost, it can be used to decrypt any secrets created.

Your friendly administrator might have already created a certificate for this purpose, so, check with them first.  If not, here's what you need to do.

First, we create a certificate on your Windows 10 authoring PC, I create a "C:\Admin\Certs" folder to store these files, the following is from [Stage1-CreateCertificate.ps1](https://github.com/kewalaka/passwords/blob/master/Option%204/Stage1-CreateCertificates.ps1):

``` powershell
# In order to generate the certificate using this method, you need to use Windows 10 or Server 2016
# however you can use the resulting certificates on any recent version of Windows (probably 2008/Vista+)
New-Item C:\Admin\Certs -Type Directory -Force -ErrorAction SilentlyContinue
$cert = New-SelfSignedCertificate -Type DocumentEncryptionCertLegacyCsp -DnsName 'SecretEncryptionCert' -HashAlgorithm SHA256

# export the private key certificate
$mypwd = ConvertTo-SecureString -String "This password isn't very secure coz everyone can see it!" -Force -AsPlainText
$cert | Export-PfxCertificate -FilePath "C:\Admin\Certs\MyCertificateAndKey.pfx" -Password $mypwd -Force
```

We then take the resulting PFX file and copy it to the target machine that will run the script and need to decrypt the password, this is from [Stage2-ImportCertificate.ps1](https://github.com/kewalaka/passwords/blob/master/Option%204/Stage2-ImportCertificate.ps1):

``` powershell
# Assumes the .pfx file generated above has been copied to c:\Admin\MyCertificateAndKey.pfx
Import-PfxCertificate -FilePath "C:\Admin\MyCertificateAndKey.pfx" -CertStoreLocation Cert:\LocalMachine\My -Password $mypwd -Exportable > $null
```

### Using the certificate ###

This is fairly involved, we can't directly encrypt the string, because the Encrypt method of the RSACryptoServiceProvider class expects a byte array.

If you take a look at [CreatePassword.ps1](https://github.com/kewalaka/passwords/blob/master/Option%204/CreatePassword.ps1), there are 3 key parameters:

``` powershell
#region: Parmeters
$certificateCommonName = 'SecretEncryptionCert'
$password = 'This is my password.  There are many like it, but this one is mine.'
$targetLocation = '.\mypassword.xml'
#endregion
```

The rest of the script is not included above, for brevity.  However, with the above parameters, [CreatePassword.ps1](https://github.com/kewalaka/passwords/blob/master/Option%204/CreatePassword.ps1) will encrypt $password into a file called 'mypassword.xml' in the current directory.  This XML file includes both the encrypted password and the key encrypted by the certificate.

It creates an XML file that looks like this:

``` xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCustomObject</T>
      <T>System.Object</T>
    </TN>
    <MS>
      <BA N="Key">Gg7bWOVcI3sf6drKOdAbD9i0FOnpICHrMD0X/ShFNh2qEw3tFgaDL+xJtW97YEzHKwf5WX8CYIG6wEzfbKzcFmLltSaVv/oIXDmZcyiyN9HuVZYTfTvTeYoV7wRR25PhFlAjOju1m8INuHXeKPrZ3myrduynm5CGHgN9AfC7Lme+uQ4vzX7zkQGBWRkTiHa5a/yHRjj0xiJL9FRZcvHnc6UwCWOz/emiToyvhTIF0BkToXJks+P83pE73hS9bnxyk/IFsSrC2BD0YhQWg+ODQBJ1a1k8ygCOiEubvEn1Tnzh2wOpu8vd634zblvSEjfdcJ8oQjVHDEICU7id3Bkouw==</BA>
      <S N="Payload">76492d1116743f0423413b16050a5345MgB8AFcAdwBYAEMAegBtADkAbgAzAG0AWAA0AGgANgBYADUATgBOAHgAQwBnAGcAPQA9AHwAOQBmADQAMAAxAGMAZgA2ADUAYwBkAGEANgAzADQANQBjADUAYgA1AGUANgAwAGQANwBlAGUAZAAyAGUANAA5AGYAMQBhAGQAMwBlAGEAMgBjADYAMAAzADIAYgAzAGUAYwA0AGIAYgA2ADgANgBlADIAYwAzAGQAYQAyADgANQBmAGYAMQA1AGUAMAA3AGQAMgA3AGIANgBhAGEAMwA3AGYAYgA3ADcANgAzADQANgA1ADgAMgA5AGUANQAxAGIAOQBlAGYAMABjADUANgAzADgAZQA1ADkAMABlAGUAMgBkADkAOAA4ADUAMgA1ADgAMQA3ADIAOAA3ADQANgA3ADEAMgBlADYAMgBmADYAMwA4ADYAZAA0ADcANgA5ADcANQAwADYAYQAwAGQAMgAwAGYANwBlAGUAYgBkADUAZgAyAGIAOQBiADUAMwAyAGIAZQA5ADcAZgA5ADgANAA2ADgAOQBmAGYAMgA1ADQAMQAzADIAMAA3ADMAZAAxAGMANAA3ADEAYwAzADYANQA4ADkAYgA3ADkAZAA3AGIAMAA2ADQAMAA1ADkANAA5ADgAZQA1ADEAYgA0ADAAZQA2ADAAZQAzADcAZQAxADQAMwA5ADYAOABmADYAOAA4ADUAYwA3AGMAZAA4AGEAOQA3ADcAMgA5ADAAZAA2ADEAMAAzAGYAYgAxADEAYQBjAGUAMQBkAGYAMQBlAGUAMwA1AGYANQAwADMANwBiADkAMgBkAGYAZgAwADcAOAAxAGQA</S>
    </MS>
  </Obj>
</Objs>
```

To use this certificate, see the example in [Use-Password.ps1](https://github.com/kewalaka/passwords/blob/master/Option%204/UsePassword.ps1)

``` powershell
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
```

We've come a long way from the simplicity of Option 1, but do have a mechanism for sharing secrets between developers via the use of a certificate, and have done so utilising infrastructure that is required if your organisation is using PowerShell DSC.

## Option X ##

Use of the above is at your own risk, I don't guarantee there aren't any banana peelings left for you to trip on.

You're most welcome to contact me, or open up a GitHub issue if you'd like to discuss other options, if you'd like to educate my feeble grasp of things, or to correct any errors you might spot.

