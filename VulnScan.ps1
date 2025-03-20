Start-Transcript -Path .\InternalVulnScan.txt
foreach($line in Get-Content $args[0]) {
     C:\"Program Files (x86)"\Nmap\nmap.exe -PS -PR -PE -sn -n -T4 --min-hostgroup 250 --min-parallelism 50 --max-rtt-timeout 100ms $line >> AliveCheck.txt
}

(cat AliveCheck.txt | select-string -Pattern '[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}').matches.value > .\Alive-IPs.txt

echo ""

foreach($line in Get-Content .\Alive-IPs.txt) {
    echo =======$Line=======
   C:\"Program Files (x86)"\Nmap\nmap.exe -sS -sV -Pn -v -T5 --open -p 21,22,23,25,80,110,111,137,139,143,161,389,443,445,465,587,623,636,1433,2049,3000,3306,3389,5432,5000,5985,5986,5900,6556,8000,8080,8443,8888,10443 --script-timeout 5m --script ftp-anon,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,nfs-ls,nfs-showmount,nfs-statfs,mongodb-info,ftp-anon,rdp-vuln-ms12-020,iscsi-info,iscsi-brute,ipmi-version,ipmi-brute,ipmi-cipher-zero,jdwp-info,jdwp-version,maxdb-info,ms-sql-info,ms-sql-ntlm-info,mysql-enum,mysql-users,mysql-vuln-cve2012-2122,nbstat,rpcinfo,samba-vuln-cve-2012-1182,smb-double-pulsar-backdoor,smb-vuln-conficker,smb-vuln-cve2009-3103,smb-vuln-cve-2017-7494,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-ms17-010,smb-vuln-webexec,smtp-enum-users,smtp-ntlm-info,smtp-open-relay,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764,x11-access,vnc-info,xmpp-info,voldemort-info,snmp-brute,snmp-info,vmware-version,wdb-version,ubiquiti-discovery,supermicro-ipmi-conf,redis-info,realvnc-auth-bypass,netbus-auth-bypass,netbus-info,ndmp-version,ndmp-fs-info,ncp-serverinfo,ncp-enum-users,ms-sql-dac,ldap-novell-getpass,mcafee-epo-agent,mmouse-brute,mmouse-exec,mongodb-info,mongodb-databases $line | Select-String -Pattern 'MAC Address:|Initiating NSE|NSE: Script|Completed NSE|Read data files|Nmap done:| Raw packets sent|Discovered open port|Starting Nmap|NSE: Loaded|Initiating ARP|Completed ARP|Completed Parallel|Initiating Parallel|Initiating SYN|Nmap scan report|Host is up|Scanning|Completed SYN|Not shown:' -NotMatch 
   echo ""
   echo "   UDP services check   "
   echo ""
   C:\"Program Files (x86)"\Nmap\nmap.exe $line -p 161,623 --open --script snmp-info,snmp-brute,ipmi-version,ipmi-brute,ipmi-cipher-zero -sU | Select-String -Pattern 'MAC Address:|Initiating NSE|NSE: Script|Completed NSE|Read data files|Nmap done:| Raw packets sent|Discovered open port|Starting Nmap|NSE: Loaded|Initiating ARP|Completed ARP|Completed Parallel|Initiating Parallel|Initiating SYN|Nmap scan report|Host is up|Scanning|Completed SYN|Not shown:' -NotMatch 
    echo ""
    echo =====================

}

Stop-Transcript
rm Alive-IPs.txt
Get-Content InternalVulnScan.txt | Where-Object { $_ -match '^=.*=$' -or $_ -match 'http' } > InternalWebPorts1.txt
$lines = Get-Content InternalWebPorts1.txt
$filteredLines = @()
$keepIP = $false

for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^=.*=$') {
        $ipStart = $i
        $keepIP = $false

        for ($j = $i + 1; $j -lt $lines.Count; $j++) {
            if ($lines[$j] -match '^=.*=$') {
                break  # Stop when another IP block is reached
            }
            if ($lines[$j] -match '.*http.*') {
                $keepIP = $true  # Mark as needed if HTTP is found
            }
        }

        if ($keepIP) {
            $filteredLines += $lines[$ipStart]
        }
    } else {
        $filteredLines += $lines[$i]
    }
}

$filteredLines | Set-Content InternalWebPorts.txt

$lines = Get-Content InternalWebPorts.txt
$urls = @{}
$currentIP = ""

foreach ($line in $lines) {
    if ($line -match '^=.*=$') {
        $currentIP = $matches[1]
        if (-not $urls.ContainsKey($currentIP)) {
            $urls[$currentIP] = @()
        }
    }
    elseif ($line -match '^(\d+)/tcp\s+open\s+.*http.*') {  # Match any service containing "http"
        $port = $matches[1]
        
        # Convert ports to URL format
        if ($port -eq "80") {
            $urls[$currentIP] += "http://$currentIP"
        } elseif ($port -eq "443") {
            $urls[$currentIP] += "https://$currentIP"
        } else {
            $urls[$currentIP] += "$currentIP`:$port"
        }
    }
}

# Sort IPs numerically and remove duplicates within each IP
$sortedURLs = $urls.Keys | Sort-Object { [System.Net.IPAddress]::Parse($_) } | ForEach-Object {
    ($urls[$_] | Sort-Object -Unique)
}

# Save output
$sortedURLs | Set-Content InternalURLS.txt

echo "===Scan output saved to InternalVulnScan.txt==="
echo ""
echo "===Web services output saved to InternalWebPorts.txt==="
echo ""
echo "===URL list saved to InternalURLS.txt==="
