$password = Get-Content $PSScriptRoot\mypassword.txt

Write-Output "The password for this script is '$password'"
Write-Output "You should ensure 'mypassword.txt' is stored securely, e.g. using NTFS permissions, and not in source control!"