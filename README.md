![image](https://github.com/user-attachments/assets/74db0dcf-668a-4106-95a7-57274fbd3d75)


# ADEnum 
## Active Directory Enumeration
Windows:
```
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kahvi-0/ADEnum/refs/heads/main/ADEnum.ps1')
adenum
```
![ADEnum](https://github.com/user-attachments/assets/ec4171f6-ea5e-4523-9070-166d6c9a2005)


Linux:
```
wget https://raw.githubusercontent.com/Kahvi-0/ADEnum/refs/heads/main/ADEnum.py 
```

Requirements
```
sudo apt-get install -y libkrb5-dev
pip install gssapi
pip install impacket
https://www.netexec.wiki/getting-started/installation
```

```
python3 ./ADEnum.py --user [user]@[Domain - uppercase] --password [password] --server [server]  --domain [domain]
```

#Example
```
python3 ./ADEnum.py --user administrator@LAB.LOCAL --password P@ssword! --server dc1.lab.local  --domain lab.local

```



# Vulnscan
## Common service port scan, nmap scripts, common service checks, etc
Windows - ensure that nmap is installed (may need to change the location in the script)
```
vulnscan.ps1 scope.txt
```


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

## LogHarvest
Inspired by: https://practicalsecurityanalytics.com/extracting-credentials-from-windows-logs/

Will Search through Windows 4688 events. This will only work if the client has enabled logging. The script will check for the regestry key. 
```
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kahvi-0/ADEnum/main/logharvest.ps1')
```
More reading:
- https://community.splunk.com/t5/Getting-Data-In/CMD-Command-Line-Logging/m-p/519506
