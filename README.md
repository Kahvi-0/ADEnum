## ADEnum

Automated enumeration for basic AD checks

```
wget https://raw.githubusercontent.com/Kahvi-0/ADEnum/main/admad.sh && chmod +x admad.sh
```

```
./admad.sh [One DC] [username] [password]
```

## Netlooker (WIP)
```
https://raw.githubusercontent.com/Kahvi-0/ADEnum/main/netlooker.sh && chmod +x netlooker.sh
```
```
netlooker.sh [scope file] [user] [pwd]
```

Automated network check for things such as MSSQL server (still working)

To do:
- Look for SCCM
- Cleanup checks

## Passpull

Automated enumeration of possible password policy locations 

**Linux**

_distingushed name can be found in bloodhound_

```
https://raw.githubusercontent.com/Kahvi-0/ADEnum/main/passpull.sh  && chmod +x passpull.sh
```

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
