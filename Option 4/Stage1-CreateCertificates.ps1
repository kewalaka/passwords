# This is typically run on the machine where you are authoring the script, e.g. a Windows 10 workstation.
# This script only works on Windows 10 or WIndows 2016+
# These steps need to be performed in an Administrator PowerShell session
$cert = New-SelfSignedCertificate -Type DocumentEncryptionCertLegacyCsp -DnsName 'SecretEncryptionCert' -HashAlgorithm SHA256

# export the private key certificate
$mypwd = ConvertTo-SecureString -String "This password isn't very secure coz everyone can see it!" -Force -AsPlainText
$cert | Export-PfxCertificate -FilePath "$env:temp\MyCertificateAndKey.pfx" -Password $mypwd -Force

<#
 # Optionally, remove the private key certificate from the node but keep the public key certificate
 # this is more secure, but means you can't test the script on your authoring PC
 
$cert | Export-Certificate -FilePath "$env:temp\MyPublicKey.cer" -Force
$cert | Remove-Item -Force
Import-Certificate -FilePath "$env:temp\MyPublicKey.cer" -CertStoreLocation Cert:\LocalMachine\My
#>


# The PFX file "MyCertificateAndKey.pfx" needs to be copied to the target nodes (see Stage2), and then should be stored somewhere safe, like a password vault.

# It should be removed from the source machine.