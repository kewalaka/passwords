# Dealing with passwords in PowerShell

Oftentimes, it is necessary to store a password or some other secret within a script.  It’s not uncommon to see password in plain text in a script.  The obvious concern here is anyone who can read the script immediately knows the password.  If you use a source code repository to version control your scripts (which since you're reading this on GitHub, I assume you do), this means your passwords are stored in plain text in this repository.  

In this article, I’ll discuss and provide examples of a number of other examples, starting with the straightforward, ending with the mechanism used by Microsoft to secure PowerShell DSC configurations.

Whilst this article discusses passwords, it can obviously be applied to any secret that you want to secure or encrypt.

## Option 1 – Store the password in a separate file outside the script

This solves the version control issue, as long as you’re careful not to check in the password (e.g. use .gitignore), and also allows the same script to be used in multiple environments.

## Option 2 – Use a Windows account to encrypt the password

## Option 3 - Use a 'key' stored in a separate file to encrypt the password

## Option 4 - Use a certificate stored in the LocalMachine store to encrypt passwords


