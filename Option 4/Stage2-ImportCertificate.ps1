# This is typically run on the target node
# It requires the .pfx file generated in stage 1 to be in the same location as the script
Import-PfxCertificate -FilePath "$PSScriptRoot\MyCertificateAndKey.pfx" -CertStoreLocation Cert:\LocalMachine\My -Password $mypwd -Exportable > $null
