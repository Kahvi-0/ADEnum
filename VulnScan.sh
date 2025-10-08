#!/bin/bash
rm AliveIPs-nmapvuln.txt hosts-nmapvuln.txt
nmap -sL -iL $1 -n 2>/dev/null | grep -oE '[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}' | sort | uniq >> hosts-nmapvuln.txt
nmap -PS445,80,8080,135,22 -PR -PE -sn -n -T4 --min-hostgroup 250 --min-parallelism 50 --max-rtt-timeout 100ms -iL hosts-nmapvuln.txt >> AliveCheck.txt

cat ./AliveCheck.txt | egrep -o '[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}' | sort | uniq >> AliveIPs-nmapvuln.txt

echo ===========================
echo =======Starting Scan=======
echo ===========================

#scan
file=$(cat AliveIPs-nmapvuln.txt)
echo "" > log.txt

for i in $file; do
    echo ======================== | tee log.txt
    echo =======$i======= | tee log.txt
    echo ======================== | tee log.txt
    nmap -sT -Pn -v -T5 --open -p 21,22,23,25,80,110,111,137,139,143,161,389,443,445,465,587,623,636,1099,1433,1521,2049,3000,3306,3389,5432,5000,5985,5986,5900,6556,8000,8080,8443,8888,10443 --script-timeout 5m --script ftp-anon,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,nfs-ls,nfs-showmount,nfs-statfs,mongodb-info,ftp-anon,rdp-vuln-ms12-020,iscsi-info,iscsi-brute,ipmi-version,ipmi-brute,ipmi-cipher-zero,jdwp-info,jdwp-version,maxdb-info,ms-sql-info,ms-sql-ntlm-info,mysql-enum,mysql-users,mysql-vuln-cve2012-2122,nbstat,rpcinfo,samba-vuln-cve-2012-1182,smb-double-pulsar-backdoor,smb-vuln-conficker,smb-vuln-cve2009-3103,smb-vuln-cve-2017-7494,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-ms17-010,smb-vuln-webexec,smtp-enum-users,smtp-ntlm-info,smtp-open-relay,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764,x11-access,vnc-info,xmpp-info,voldemort-info,snmp-brute,snmp-info,vmware-version,wdb-version,ubiquiti-discovery,supermicro-ipmi-conf,redis-info,realvnc-auth-bypass,netbus-auth-bypass,netbus-info,ndmp-version,ndmp-fs-info,ncp-serverinfo,ncp-enum-users,ms-sql-dac,ldap-novell-getpass,mcafee-epo-agent,mmouse-brute,mmouse-exec,mongodb-info,mongodb-databases $i | grep -vE 'MAC Address:|Initiating NSE|NSE: Script|Completed NSE|Read data files|Nmap done:| Raw packets sent|Discovered open port|Starting Nmap|NSE: Loaded|Initiating ARP|Completed ARP|Completed Parallel|Initiating Parallel|Initiating SYN|Nmap scan report|Host is up|Scanning|Completed SYN|Not shown:|Initiating Connect Scan|Completed Connect Scan|Some closed ports' | tee log.txt
    echo "" | tee log.txt
    done

rm hosts-nmapvuln.txt
rm AliveCheck.txt
rm AliveIPs-nmapvuln.txt
