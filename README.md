# Dealing with passwords in PowerShell

Oftentimes, it is necessary to store a password or some other secret within a script.  It’s not uncommon to see password in plain text in a script.  The obvious concern here is anyone who can read the script immediately knows the password.  If you use a source code repository to version control your scripts (which since you're reading this on GitHub, I assume you do), this means your passwords are stored in plain text in this repository.  

In this article, I’ll discuss and provide examples of a number of other options, starting with the straightforward, ending with the mechanism used by Microsoft to secure PowerShell DSC configurations.

Whilst this article discusses passwords, it can obviously be applied to any secret that you want to secure or encrypt.

**NB** - In all of these examples, I have purposefully not excluded my password files from GitHub so you can see what they look like.  Make sure you don't do this with your real passwords!  Use a  [.gitignore](https://git-scm.com/docs/gitignore) file to hide things you don't want in source control.  If you save your secrets to source control by mistake, this walks you through [removing sensitive data from a repository](https://help.github.com/articles/removing-sensitive-data-from-a-repository/), *and then change the potentially compromised password*.

## Option 1 – Store the password in a separate file outside the script

This is a really simple approach requiring little effort.  The password is stored in a text file format outside the main script.

```powershell

# simple one password in a text file
$password = Get-Content $PSScriptRoot\mypassword.txt

```

You can also use a structured file format like JSON to store all environment specific settings:

```powershell

# get secrets and environmental settings from a .json file
> $settings = Get-Content $PSScriptRoot\environmentals.json | ConvertFrom-Json
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

This solves the version control issue, as long as you’re careful not to check in the password, and also allows the same script to be used in multiple environments.

## Option 2 – Use a Windows account to encrypt the password

OK, so you're not so keen on storing passwords in plain text?  Good.

Another approach uses your Windows credentials to encrypt the password , you can create an encrypted password using the following code (see CreatePassword.ps1):

``` powershell
$password = read-host -prompt "Enter your Password" -AsSecureString
# this will store the encrypted password in 'mypassword.txt'
ConvertFrom-SecureString $password | out-file .\mypassword.txt
```

The resulting password  is tied to your user profile **on the machine you used to create the password** - only by using the same machine + your same user account will you be able to decrypt the password successfully.  This is provided by [Windows Data Protection API (DPAPI)](https://en.wikipedia.org/wiki/Data_Protection_API).

If you inspect the contents of mypassword.txt, it will look something like this (yours will be different, because it will be created for your user on your machine)

```
01000000d08c9ddf0115d1118c7a00c04fc297eb010000007d703781d2413e41a30a32725ca37e8000000000020000000000106600000001000020000000e84793fdafb6f74aa100696ce897ec3efb1f27152ba4f3a897cf30d93f996d50000000000e80000000020000200000001b9e4de1e8b977e2490e28956b27d63ac594fbb714a4808a36199a0c3148f06920000000730f687d4809e94db81fa4ab0cfb99c927b009033931783faf67f7676bcf24a540000000629d733a1e1bfe79ddc83dd98e579c3934cd8bf304cad02227446ebe2299c9940851abbfd1ad2d2f9edd11554343680194d06e11098e720f34e8aa7eeeb42fb4
```

There are a number of ways to decrypt this password (see below, or UsePassword.ps1)

``` powershell
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
$decryptedPassword =$MyCredential.GetNetworkCredential().password

# Alternatively, if you just want to access the password directly:
$decryptedPassword2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
```

Confirming this is working in production becomes a little harder with this approach, in order to ensure the password is being decrypted OK, you'll need access to the machine & the user account used to create the password.  It also means that anyone testing or developing the script will need to create encrypted credentials.

Instead of tieing the password to the user profile on the machine, it is also possible to tie it to the localmachine account (aka 'SYSTEM').  See CreatePasswordTiedToMachine.ps1 and UsePasswordTiedToMachine.ps1 for examples.

This is quite a secure approach, but not very convenient or scalable.  Definitely worth considering if you don't mind the limitations.


## Option 3 - Use a 'key' stored in a separate file to encrypt the password

This is similiar to option 1, however, instead of simply storing the password unencrypted in a file, the means to encrypt & decrypt the file is via a 'keyfile'.  This is just a text file containing a hash.  

The benefit of this approach is it is more portable, as long as you have the keyfile, you can decrypt the password.

The downside is obvious - if the keyfile is compromised, or accidentally checked into source control, it's not much better than having the password in plain text.

Here's how to create the encrypted password, stored to mypassword.txt and keyfile, stored to my.keyfile.   This is from CreatePassword.ps1:

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

The following illustrates use, again from UsePassword.ps1:

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

One problem with Option 3, is the importance placed on the keyfile.  An alternative approach is to use SSL certificates, as explained by [David Wyatt's article](https://powershell.org/2014/02/01/revisited-powershell-and-encryption/).



