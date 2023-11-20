#!/bin/bash

# Usage  ./adnet.sh [scopefile] [user] [pwd]

# Add user auth check


# Port scan
# SMB host scan
sudo nmap -Pn -sS -T4 -n -p 445 -iL $1 -oG - --open | awk '/Up$/{print $2}' > smb-nmap.txt
nxc smb smb-nmap.txt > hosts.txt && cat hosts.txt | awk -F " " '{print$4}' > SMBHostNames.txt && cat hosts.txt | awk -F " " '{print$2}' > SMBHostIPs.txt
cat hosts.txt | sort | uniq | awk -F " " 'BEGIN { ORS=" " }; {print$2}{print$NF}{printf"\n"}' | grep SMBv1:True > smbv1.txt
cat hosts.txt | grep -a signing:False > SMBsigningFalse.txt

#MSSQL hosts
sudo nmap -Pn -sS -T4 -n -p 3306 -iL $1 -oG - --open | awk '/Up$/{print $2}' > mssql-nmap.txt
nxc mssql mssql-nmap.txt > mssqlhosts.txt && cat mssqlhosts.txt | awk -F " " '{print$4}' > MSSQLHostNames.txt && cat mssqlhosts.txt | awk -F " " '{print$2}' > MSSQLHostIPs.txt && rm mssqlhosts.txt

#WSUS hosts
#SCCM hosts

#SMB share enumeration
nxc smb SMBHostIPs.txt -u ''  -p '' --shares > nullsessions.txt
nxc smb SMBHostIPs.txt -u 'a' -p '' --shares > Shares-Anon.txt
nxc smb SMBHostIPs.txt -u $2  -p $3 --shares > Shares-Auth.txt 

# OUTPUT

echo "List of hosts that support smbv1 saved to smbv1.txt"
echo "List of hosts that do not enforce SMB signing saved to SMBsigningFalse.txt"
echo "Hosts that are running MSSQL are in the MSSQL* files"
echo "SMB share enumeration files saved to nullsessions.txt, Shares-Anon.txt, Shares-Auth.txt"

echo " " 
echo "Hosts running MSSQL:"
cat MSSQLHostNames.txt
echo " "

echo " "
echo "Example of hosts that do not enforce SMB signing"
echo " "
cat SMBsigningFalse.txt  | grep -a signing:False | awk -F " " '{print $1,$2,$4,$12,$13}' | grep False

echo " "
echo "Example of hosts that support SMBv1"
echo " "
cat smbv1.txt  | grep -a SMBv1:True | awk -F " " '{print $1,$2,$4,$13,$15}' | grep SMBv1:True
