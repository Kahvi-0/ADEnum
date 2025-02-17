# ADEnum
Automated enumeration for basic AD checks

Linux:
```
wget https://raw.githubusercontent.com/Kahvi-0/ADEnum/main/admad.sh && chmod +x admad.sh
```

```
./admad.sh [One DC] [username] [password]
```

Windows:
```
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kahvi-0/ADEnum/refs/heads/main/ADEnum.ps1')
adenum
```


# Light Network vuln scan
Windows
```
```


Linux (To rework)
```
https://raw.githubusercontent.com/Kahvi-0/ADEnum/main/netlooker.sh && chmod +x netlooker.sh
```
```
netlooker.sh [scope file] [user] [pwd]
```


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


## LogHarvest
Inspired by: https://practicalsecurityanalytics.com/extracting-credentials-from-windows-logs/

Will Search through Windows 4688 events. This will only work if the client has enabled logging. The script will check for the regestry key. 
```
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kahvi-0/ADEnum/main/logharvest.ps1')
```
More reading:
- https://community.splunk.com/t5/Getting-Data-In/CMD-Command-Line-Logging/m-p/519506
