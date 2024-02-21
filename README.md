# ADEnum

Automated enumeration for basic AD checks

```
./admad.sh [One DC] [username] [password]
```


Automated network check for things such as MSSQL server (still working)


# Passpull

Automated enumeration of possible password policy locations 

**Linux**

distingushed name can be found in bloodhound

Usage
```
passpull.sh [user] [password] [dc list] [domain.local] [distingushed name]
```
Example
```
passpull.sh CoffeeLover 'p@ssword123' ./dcs.txt domain.local "CN=PENTEST,OU=USERS,OU=test,DC=lab,DC=LOCAL"
```

**Powershell**

```
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kahvi-0/ADEnum/main/passpull.ps1')
```

```
passpull [DC hostname]
```
