$password = read-host -prompt "Enter your Password" -AsSecureString
ConvertFrom-SecureString $password | out-file .\mypassword.txt
