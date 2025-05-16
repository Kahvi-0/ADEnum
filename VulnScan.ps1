Remove-Item Alive-IPs.txt -erroraction 'silentlycontinue'| Out-Null
Remove-Item AliveCheck.txt  -erroraction 'silentlycontinue'| Out-Null
Remove-Item InternalWebPorts1.txt -erroraction 'silentlycontinue'| Out-Null
foreach($line in Get-Content $args[0]) {
     C:\"Program Files (x86)"\Nmap\nmap.exe -PS -PR -PE -sn -n -T4 --min-hostgroup 250 --min-parallelism 50 --max-rtt-timeout 100ms $line >> AliveCheck.txt 
}

(cat AliveCheck.txt | select-string -Pattern '[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}').matches.value | Sort-Object -Unique | Out-File Alive-IPs.txt -Encoding ascii 
echo "Doing TCP services check"
echo ""
C:\"Program Files (x86)"\Nmap\nmap.exe -sS -sV -Pn -T5 -iL Alive-IPs.txt --open -p 21,22,23,25,80,110,111,137,139,143,161,389,443,445,465,587,623,636,1099,1433,1521,2049,3000,3306,3389,5432,5000,5985,5986,5900,6556,8000,8080,8443,8888,10443 --script-timeout 5m --script ftp-anon,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,nfs-ls,nfs-showmount,nfs-statfs,mongodb-info,ftp-anon,rdp-vuln-ms12-020,iscsi-info,iscsi-brute,ipmi-version,ipmi-brute,ipmi-cipher-zero,jdwp-info,jdwp-version,maxdb-info,ms-sql-info,ms-sql-ntlm-info,mysql-enum,mysql-users,mysql-vuln-cve2012-2122,nbstat,rpcinfo,samba-vuln-cve-2012-1182,smb-double-pulsar-backdoor,smb-vuln-conficker,smb-vuln-cve2009-3103,smb-vuln-cve-2017-7494,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-ms17-010,smb-vuln-webexec,smtp-enum-users,smtp-ntlm-info,smtp-open-relay,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764,x11-access,vnc-info,xmpp-info,voldemort-info,snmp-brute,snmp-info,vmware-version,wdb-version,ubiquiti-discovery,supermicro-ipmi-conf,redis-info,realvnc-auth-bypass,netbus-auth-bypass,netbus-info,ndmp-version,ndmp-fs-info,ncp-serverinfo,ncp-enum-users,ms-sql-dac,ldap-novell-getpass,mcafee-epo-agent,mmouse-brute,mmouse-exec,mongodb-info,mongodb-databases -oA vulnscan-nnmap |Out-Null
Get-Content vulnscan-nnmap.nmap | Select-String -Pattern 'scan initiated|Nmap done|Service detection performed|MAC Address:|Initiating NSE|NSE: Script|Completed NSE|Read data files|Nmap done:| Raw packets sent|Discovered open port|Starting Nmap|NSE: Loaded|Initiating ARP|Completed ARP|Completed Parallel|Initiating Parallel|Initiating SYN|Host is up|Scanning|Completed SYN|Not shown:|service unrecognized|^SF:|^SF-Port|^Service Info:|services unrecognized|NEXT SERVICE FINGERPRINT' -NotMatch > InternalTCPScan.txt
echo ""
echo "Doing UDP services check"
C:\"Program Files (x86)"\Nmap\nmap.exe $line -p 161,623 --open -iL Alive-IPs.txt --script snmp-info,snmp-brute,ipmi-version,ipmi-cipher-zero -sU -oA vulnscan-UDP-nnmap | Out-Null
Get-Content vulnscan-UDP-nnmap.nmap | Select-String -Pattern 'scan initiated|Nmap done|Service detection performed|MAC Address:|Initiating NSE|NSE: Script|Completed NSE|Read data files|Nmap done:| Raw packets sent|Discovered open port|Starting Nmap|NSE: Loaded|Initiating ARP|Completed ARP|Completed Parallel|Initiating Parallel|Initiating SYN|Host is up|Scanning|Completed SYN|Not shown:' -NotMatch > InternalUDPScan.txt

Get-Content InternalTCPScan.txt | Where-Object { $_ -match '^Nmap scan report for' -or $_ -match '.*open.*http.*' } > InternalWebPorts1.txt
$lines = Get-Content InternalWebPorts1.txt
$filteredLines = @()
$keepIP = $false

for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^Nmap scan report for') {
        $ipStart = $i
        $keepIP = $false

        for ($j = $i + 1; $j -lt $lines.Count; $j++) {
            if ($lines[$j] -match '^Nmap scan report for') {
                break  # Stop when another IP block is reached
            }
            if ($lines[$j] -match '.*open.*http.*') {
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


#Filtering out and forming the URL list for detected services
$lines = Get-Content "InternalWebPorts.txt"
$urls = @{}
$currentIP = ""

foreach ($line in $lines) {
    if ($line -match 'Nmap scan report for ([^ ]+)(?: \(([^)]+)\))?') {
        $currentIP = $matches[1]
        if (-not $urls.ContainsKey($currentIP)) {
            $urls[$currentIP] = @()
        }
    }
    elseif ($line -match '^(\d+)/tcp\s+open\s+(\S+)') {
        $port = $matches[1]
        $service = $matches[2].ToLower()

        if ($port -eq "80") {
            $urls[$currentIP] += "http://$currentIP"
        }
        elseif ($port -eq "443") {
            $urls[$currentIP] += "https://$currentIP"
        }
        else {
            if ($service -like "*https*") {
                $urls[$currentIP] += "https://$currentIP`:$port"
            }
            else {
                $urls[$currentIP] += "http://$currentIP`:$port"
            }
        }
    }
}
$outputPath = "WebUrls.txt"
$urls.Keys | Sort-Object {[System.Net.IPAddress]::Parse($_)} | ForEach-Object {
    Add-Content -Path $outputPath -Value $urls[$_] | Sort-Object -Unique | ForEach-Object { Write-Host "  $_" }
}


#TCPparse
$nmapFile = "InternalTCPScan.txt"
$fingerprintFile = Invoke-WebRequest https://raw.githubusercontent.com/Kahvi-0/ADEnum/refs/heads/main/vulnscan-fingerprints.txt -UseBasicParsing
$outputFile = "InternalVulnScan-TCP.txt"
$fingerprintslist = ($fingerprintFile.tostring() -split "[`r`n]")
$fingerprints = @{}
foreach($line in $fingerprintslist) {
         if ($line -match "::") {
   $parts = $line -split "::", 2
           if ($parts.Count -eq 2) {
              $key = $parts[0].Trim()
              $value = $parts[1].Trim()
              $fingerprints[$key] = $value
         }
     }
 }
$nmapLines = Get-Content $nmapFile | ForEach-Object {
     $line = $_
     foreach ($key in $fingerprints.Keys) {
         if ($line -match "\b$key\b") {
             $line = $line -replace "\b$key\b", $fingerprints[$key]
         }
     }
     $line
 }
$nmapLines | Set-Content $outputFile

#UDPparse
$nmapFile = "InternalUDPScan.txt"
$fingerprintFile = Invoke-WebRequest https://raw.githubusercontent.com/Kahvi-0/ADEnum/refs/heads/main/vulnscan-fingerprints.txt -UseBasicParsing
$outputFile = "InternalVulnScan-UDP.txt"
$fingerprintslist = ($fingerprintFile.tostring() -split "[`r`n]")
$fingerprints = @{}
foreach($line in $fingerprintslist) {
         if ($line -match "::") {
   $parts = $line -split "::", 2
           if ($parts.Count -eq 2) {
              $key = $parts[0].Trim()
              $value = $parts[1].Trim()
              $fingerprints[$key] = $value
         }
     }
 }
$nmapLines = Get-Content $nmapFile | ForEach-Object {
     $line = $_
     foreach ($key in $fingerprints.Keys) {
         if ($line -match "\b$key\b") {
             $line = $line -replace "\b$key\b", $fingerprints[$key]
         }
     }
     $line
 }
$nmapLines | Set-Content $outputFile


#Cleanup
Remove-Item Alive-IPs.txt -erroraction 'silentlycontinue'| Out-Null
Remove-Item AliveCheck.txt  -erroraction 'silentlycontinue'| Out-Null
Remove-Item InternalWebPorts1.txt -erroraction 'silentlycontinue'| Out-Null
Remove-Item InternalUDPScan.txt -erroraction 'silentlycontinue'| Out-Null
Remove-Item InternalTCPScan.txt -erroraction 'silentlycontinue'| Out-Null

#output
echo "" 
echo "===Scan output saved to InternalVulnScan-TCP.txt==="
echo ""
echo "===Scan output saved to InternalVulnScan-UDP.txt==="
echo ""
echo "===Web services output saved to InternalWebPorts.txt==="
echo ""
echo "===URL list saved to InternalURLS.txt==="
