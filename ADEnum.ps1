function adenum {
    del AD-Status.log -erroraction 'silentlycontinue'
    Start-Transcript -Path .\AD-Status.log
    $FormatEnumerationLimit=-1
    #Setup root
    $domainRoot = [ADSI]"LDAP://RootDSE"
    $baseDN = $domainRoot.defaultNamingContext
    Write-Host "=====[Domain Controllers]==========" -BackgroundColor Red 
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=8192))").findAll() | ForEach-Object { $_.properties.name} 
    Write-Host "=======[Domain Trusts]==========" -BackgroundColor Red
    nltest /DOMAIN_TRUSTS /ALL_TRUSTS 
    Write-Host "=======[Domain Users]==========" -BackgroundColor Red 
    (New-Object DirectoryServices.DirectorySearcher "objectcategory=user").FindAll() | ForEach-Object { $_.Properties.samaccountname } |Tee-Object DomainUsers.txt
    Write-Host "=======[Domain Groups]==========" -BackgroundColor Red
    (New-Object DirectoryServices.DirectorySearcher "objectcategory=group").FindAll() | ForEach-Object { $_.Properties.samaccountname } 
    Write-Host "=======[Members of the protected users group]==========" -BackgroundColor Red
    Write-Host "Accounts cannot be delegated" -Foregroundcolor Green
    Write-Host "Forces Kerberos" -Foregroundcolor Green
    Write-Host "Reduces credential lifetime (e.g. TGT lifetime is shortened to 4 hours)," -Foregroundcolor Green
    Write-Host "Prevents caching of plaintext credentials or weaker hashes" -Foregroundcolor Green
    ([adsisearcher]"(&(objectCategory=group)(name=protected users))").findAll() | ForEach-Object { $_.properties.name,$_.properties.member,""} 
    Write-Host "=======[Accounts marked for No Delegation]==========" -BackgroundColor Red
    Write-Host "Accounts cannot be delegated - No S4U for example" -Foregroundcolor Green
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=1048576))").findAll() | ForEach-Object { $_.properties.samaccountname}
    Write-Host "=======[Accounts that require smart cards for interaction]==========" -BackgroundColor Red
    Write-Host "Users must use a smart card to sign into the network" -Foregroundcolor Green
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=262144))").findAll() | ForEach-Object { $_.properties.name} 
    Write-Host "=======[Accounts where a password is not required]==========" -BackgroundColor Red
    Write-Host "Attempt to authenticate to host with no password" -Foregroundcolor Green
    Write-Host 'nxc smb -u Guest -p ""' -Backgroundcolor magenta
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=32))").findAll() | ForEach-Object { $_.properties.name} 
    Write-Host "=======[Interdomain Trust]==========" -BackgroundColor Red
    Write-Host "Accounts trusted for a system domain that trusts other domains" -Foregroundcolor Green
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=2048))").findAll() | ForEach-Object { $_.properties.name} 
    Write-Host "=======[Enumerating LDAP descriptions]==========" -BackgroundColor Red
    ([adsisearcher]"(&(objectCategory=user)(description=*))").findAll() | ForEach-Object { $_.properties.name,$_.properties.description,""} |Tee-Object LDAPDescriptions.txt
    Write-Host "=======[Enumerating current user's MAQ]==========" -BackgroundColor Red
    Write-Host "Number of computer accounts that your account can create" -ForegroundColor Green
    $MAQcommand = (New-Object DirectoryServices.DirectorySearcher "ms-DS-MachineAccountQuota=*").FindAll() | ForEach-Object { $_.Properties.'ms-ds-machineaccountquota'}
    echo "MAQ:$MAQcommand" 
    Write-Host "=======[Enumerating Domain GPOs]==========" -BackgroundColor Red
    (New-Object DirectoryServices.DirectorySearcher "objectCategory=groupPolicyContainer").FindAll()| ForEach-Object { $_.Properties.displayname,$_.Properties.gpcfilesyspath,""} 
    Write-Host "=======[GPOs applied to current user and computer]==========" -BackgroundColor Red
    Write-Host "If you do not see the computer settings, elevate powershell to admin" -ForegroundColor Green
    gpresult /r /f
    Write-Host ""
    Write-Host "=======[Enumerate dangerous user attributes (not exhaustive)==========" -BackgroundColor Red
    Write-Host "Need to look into the format of each, belive its in UTF-8 format" -ForegroundColor Green
    Write-Host "Users with the 'userPassword' attribute" -ForegroundColor Green
    ([adsisearcher]"(&(UserPassword=*))").findAll() | ForEach-Object { $_.properties.name,$_.properties.userpassword,""} 
    Write-Host "Users with the 'unicodePwd' attribute" -ForegroundColor Green
    ([adsisearcher]"(&(unicodePwd=*))").findAll() | ForEach-Object { $_.properties.name,$_.properties.unicodepwd,""} 
    Write-Host "Users with the 'unixUserPassword' attribute" -ForegroundColor Green
    ([adsisearcher]"(&(unixUserPassword=*))").findAll() | ForEach-Object { $_.properties.name,$_.properties.unixuserpassword,""} 
    Write-Host "Users with the 'msSFU30Password' attribute" -ForegroundColor Green
    ([adsisearcher]"(&(msSFU30Password=*))").findAll() | ForEach-Object { $_.properties.name,$_.properties.mssfu30password,""} 
    Write-Host "Users with the 'orclCommonAttribute' attribute" -ForegroundColor Green
    ([adsisearcher]"(&(orclCommonAttribute=*))").findAll() | ForEach-Object { $_.properties.name,$_.properties.orclcommonattribute,""} 
    Write-Host "Users with the 'defender-tokenData' attribute" -ForegroundColor Green
    ([adsisearcher]"(&(defender-tokenData=*))").findAll() | ForEach-Object { $_.properties.name,$_.properties."defender-tokendata",""} 
    Write-Host "Users with the 'dBCSPwd' attribute" -ForegroundColor Green
    ([adsisearcher]"(&(dBCSPwd=*))").findAll() | ForEach-Object { $_.properties.name,$_.properties."dbcspwd",""} 
    Write-Host "=======[Kerb roeast Users]==========" -BackgroundColor Red
    Write-Host "Rubeus.exe / nxc.exe" -Backgroundcolor magenta
    ([adsisearcher]"(&(objectCategory=user)(servicePrincipalname=*))").findAll() | ForEach-Object { $_.properties.name,$_.properties.serviceprincipalname,""} 
    Write-Host "=======[ASREP roastable Users]==========" -BackgroundColor Red
    Write-Host "Rubeus.exe / nxc.exe" -Backgroundcolor magenta
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=4194304))").findAll() | ForEach-Object { $_.properties.name} 
    Write-Host "=======[ADCS]==========" -BackgroundColor Red
    Write-Host "Enumerate ADCS servers. Enumerate with further tools" -ForegroundColor Green
    Write-Host "Certify.exe find /vulnerable" -Backgroundcolor magenta
    $Root = [adsi] "LDAP://CN=Configuration,$baseDN"
    $Searcher = new-object System.DirectoryServices.DirectorySearcher($root)
    $Searcher.filter = "(&(objectClass=pKIEnrollmentService))"
    $Searcher.FindAll() | ForEach-Object { "Hostname:", $_.properties.dnshostname,  "CA name:",$_.properties.displayname,  "Entrollment endpoints:", $_.properties."mspki-enrollment-servers", $_.properties."certificatetemplates", "" }
    Write-Host "=======[LDAP Signing and channel binding]==========" -BackgroundColor Red
    Write-Host "If you have any errors with channel binding, use NXC. Its a limitation in pwsh" -ForegroundColor Yellow
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    $dcRecords = ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=8192))").findAll() | ForEach-Object { $_.properties.name}
    foreach ($dc in $dcRecords) {
        Write-Host "`n[$dc]"
        try {
            $rootDSE = [ADSI]"LDAP://$dc/RootDSE"
            $ldapSigning = if ($rootDSE) {
                "Signing Not Required (LDAP bind succeeded)"
            } else {
                "Signing Required (bind failed)"
            }
            $portCheck = Test-NetConnection -ComputerName $dc -Port 636 -WarningAction SilentlyContinue
            $LDAPSPORT = "636"
            if (-not $portCheck.TcpTestSucceeded) {
                Write-Host "  LDAPS (port 636) not reachable on $dc, trying port 389"
                $LDAPSPORT = "389"
                continue
            }
            $cbStatus = try {
                $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($dc, $LDAPSPORT, $false, $false)
                $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
                $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
                $connection.SessionOptions.SecureSocketLayer = $true
                $connection.SessionOptions.ProtocolVersion = 3
                $connection.Bind()
                "[$dc] Channel Binding NOT Enforced (bind succeeded)"
            }
            catch {
                $msg = $_.Exception.Message
                if ($msg -like "*80090346*") {
                    "[$dc] Channel binding is enforced"
                } elseif ($msg -like "*52e*" -or $msg -like "*logon failure*") {
                    "[$dc] Channel binding is NOT enforced"
                } else {
                    "[$dc] Unknown LDAPS error: $msg"
                }
            }
            Write-Host "  LDAP Signing     : $ldapSigning"
            Write-Host "  Channel Binding  : $cbStatus"
        }
        catch {
            Write-Host "  Could not connect or retrieve RootDSE from $dc"
        }
    }
    Write-Host "=======[Unconstrained Delegation hosts]==========" -BackgroundColor Red
    Write-Host "Machines / users that can impersonate any domain user domain wide" -ForegroundColor Green
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=524288))").findAll() | ForEach-Object { $_.properties.name} 
    Write-Host "=======[Constrained Delegation hosts]==========" -BackgroundColor Red
    Write-Host "Machines / users that can impersonate any domain user on specified host/service" -ForegroundColor Green
    ([adsisearcher]"(&(msds-allowedtodelegateto=*))").findAll() | ForEach-Object { $_.properties.name,$_.properties."msds-allowedtodelegateto",""} 
    Write-Host "=======[GMSA Service]==========" -BackgroundColor Red
    Write-Host "Need to expand on later" -ForegroundColor Green
    ([adsisearcher]"(&(objectClass=msDS-ManagedServiceAccount))").findAll() | ForEach-Object { $_.properties,""} 
    ([adsisearcher]"(&(PrincipalsAllowedToRetrieveManagedPassword=*))").findAll() | ForEach-Object { $_.properties,""} 
    Write-Host "=======[LAPS]==========" -BackgroundColor Red
    ([adsisearcher]"(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=*))").findAll() | ForEach-Object { $_.properties}  
    Write-Host "=======[SCCM]==========" -BackgroundColor Red
    Write-Host "Enumerate SCCM servers. Enumerate with further tools" -ForegroundColor Green
    Write-Host "SharpSCCM.exe local site-info --no-banner" -Backgroundcolor magenta
    ([ADSISearcher]("objectClass=mSSMSManagementPoint")).FindAll() | ForEach-Object { $_.properties.dnshostname,$_.properties.cn,$_.properties.mssmsmpname,""} 
    Write-Host "=======[MSSQL]==========" -BackgroundColor Red
    Write-Host "Not perfect, computer accounts based off name" -ForegroundColor Green
    Write-Host "Sill enum via nmap with -sV" -Backgroundcolor magenta
    ([adsisearcher]"(&(objectCategory=computer)(Name=*SQL*))").findAll() | ForEach-Object { $_.properties.name,""}

    Write-Host "=======[Permissions for DNS]==========" -BackgroundColor Red
    Write-Host "Still in the works - cannot pinpoint the privs for each zone yet https://i.kym-cdn.com/entries/icons/original/000/041/998/Screen_Shot_2022-09-23_at_10.40.58_AM.jpg" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "DNS Dynamic Update Settings" -ForegroundColor Green
    Write-Host "Still in the works - cannot pinpoint exact zone via LDAP yet" -ForegroundColor Yellow
    Write-Host "Look for Nonsecure and Secure, this means Anynoymous DNS updates." -ForegroundColor Green
    Write-Host "To attempt to update your own host's IP to test:" -ForegroundColor Green
    Write-Host "python3 ./adddns.py --domain lab.local --dnsip [ADIDNS Server ip] --hostname [target hostname] --hostip [IP address to modify]" -Backgroundcolor magenta
    $dnsZones = ([ADSISearcher]("(&(objectClass=dnsZone))")).FindAll()
    foreach ($zone in $dnsZones) {
        $properties = $zone.Properties
        $zoneName = $properties["name"][0]  # Get the forward lookup zone name
        Write-Host "`nForward Lookup Zone: $zoneName"
        if ($properties.Contains("dnsproperty")) {
            $dnsPropertyValues = $properties["dnsproperty"]
            foreach ($value in $dnsPropertyValues) {
                # Decode byte array to readable format
                $decoded = [System.BitConverter]::ToString($value)
                # Check if this entry contains dynamic update settings
                if ($value.Length -ge 16) {
                    $dynamicUpdateFlag = [BitConverter]::ToInt32($value, 16)  # Offset where dynamic update flag is stored
                    $updateStatus = switch ($dynamicUpdateFlag) {
                        0 { "None (No Dynamic Updates Allowed)" }
                        1 { "Nonsecure and Secure" }
                        2 { "Secure Only" }
                        default { "Unknown" }
                    }
                    Write-Host "Domain: $zoneName | Dynamic Update Setting: $updateStatus"
                }
            }
        } else {
            Write-Host "Domain: $zoneName | No dynamic update setting found."
        }
    }
    echo " "
    Write-Host "Low priv users/groups with privs to update DNS" -ForegroundColor Green
    Write-Host "python3 ./dnstool.py -r 'UpdateTest' -a add --data 10.10.10.68 -u '' -p '' [DC IP]" -Backgroundcolor magenta
    $searchRoot = "LDAP://CN=MicrosoftDNS,CN=System,$baseDN"
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = [ADSI]$searchRoot
    $searcher.Filter = "(objectClass=dnsZone)"  # Filter for DNS zones
    $searcher.PropertiesToLoad.Add("name") | Out-Null
    $searcher.PropertiesToLoad.Add("nTSecurityDescriptor") | Out-Null  # Load security descriptor
    $results = $searcher.FindAll()
    Function Resolve-SID {
        param([string]$sid)
        Try {
            $wellKnownSIDs = @{
                "S-1-5-32-544" = "Administrators"
                "S-1-5-32-545" = "Users"
                "S-1-5-32-554" = "Enterprise Admins"
                "S-1-5-32-550" = "Account Operators"
                "S-1-5-32-551" = "Server Operators"
                "S-1-5-32-552" = "Print Operators"
                "S-1-5-32-553" = "Backup Operators"
            }
            if ($wellKnownSIDs.ContainsKey($sid)) {
                return $wellKnownSIDs[$sid]
            }
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid, 0)
            $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
            return $objUser.Value
        } Catch {
            return $sid  # Return raw SID if resolution fails
        }
    }
    
    foreach ($result in $results) {
        $zoneName = $result.Properties["name"][0]
        $sd = $result.Properties["nTSecurityDescriptor"]
        if ($sd) {
            $rawSD = New-Object System.DirectoryServices.ActiveDirectorySecurity
            $rawSD.SetSecurityDescriptorBinaryForm($sd[0])
    
            Write-Host "`nZone: $zoneName"
            Write-Host "Permissions:"
            $rawSD.Access | ForEach-Object {
                # Resolve SID in IdentityReference to readable name
                $resolvedIdentity = Resolve-SID $_.IdentityReference.ToString()
                
                Write-Host "  Identity: $resolvedIdentity"
                Write-Host "  Rights: $($_.ActiveDirectoryRights)"
                Write-Host "  Type: $($_.AccessControlType)"
                Write-Host "--------------------------"
            }
        } else {
            Write-Host "`nZone: $zoneName - No security descriptor found!"
        }
    }

    Write-Host "=======[Checking for accessible network shares]==========" -BackgroundColor Red
    Write-Host "This may take a while" -ForegroundColor Green
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $computers = net view /domain:$env:USERDOMAIN 2>$null | ForEach-Object {
        if ($_ -match "\\\\(.*)") { $matches[1] }
    }
    if (-not $computers) {
        $computers = (New-Object DirectoryServices.DirectorySearcher "objectcategory=computer").FindAll() | 
            ForEach-Object { $_.Properties.cn }
    }
    $accessibleShares = @()
    Function Test-Permissions {
        param ($sharePath)
        $testFile = "$sharePath\testLetsNotOverwriteARealFiles.tmp"
        $readAccess = $false
        $writeAccess = $false
        try {
            $files = Get-ChildItem -Path $sharePath -ErrorAction Stop
            $readAccess = $true
        } catch {}
        try {
            Set-Content -Path $testFile -Value "test" -ErrorAction Stop
            Remove-Item -Path $testFile -ErrorAction Stop
            $writeAccess = $true
        } catch {}
        return [PSCustomObject]@{
            ReadAccess  = $readAccess
            WriteAccess = $writeAccess
        }
    }
    foreach ($computer in $computers) {
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            try {
                $shares = net view \\$computer /all 2>$null | ForEach-Object { if ($_ -match "^(.*)\s+Disk") { $matches[1].Trim() } }
                foreach ($share in $shares) {
                    $path = "\\$computer\$share"
                    $name = $share
                    $permissions = Test-Permissions -sharePath $path
                    $accessibleShares += [PSCustomObject]@{
                        Path       = $path
                        ReadAccess = $permissions.ReadAccess
                        WriteAccess = $permissions.WriteAccess

                    }
                }
            } catch {
                Write-Host "Could not retrieve shares from $computer"
            }
        } else {
        }
    }
    if ($accessibleShares.Count -gt 0) {
        Write-Host "`nAccessible Network Shares (including hidden) with Permissions:"
        $accessibleShares | Format-Table -AutoSize
    } else {
        Write-Host "`nNo accessible shares found!"
    }


    echo ""
    Write-Host "=======[Obsolete host enumeration]==========" -BackgroundColor Red
    echo ""
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectCategory=computer))"
    $searcher.PropertiesToLoad.Add("cn") | Out-Null
    $searcher.PropertiesToLoad.Add("operatingSystem") | Out-Null
    $results = $searcher.FindAll()
    $obsoletePatterns = @(
        "Windows XP*", "Windows 7*", "Windows 8*", "Windows Server 2003*", 
        "Windows Server 2008*", "Windows Server 2012*", "Windows Vista*"
    )
    $obsoleteHosts = @()
    foreach ($result in $results) {
        $hostname = $result.Properties.cn
        $os = $result.Properties.operatingsystem
    
        if ($os) {
            $osName = $os[0]
            if ($obsoletePatterns | Where-Object { $osName -like $_ }) {
                $obsoleteHosts += [PSCustomObject]@{
                    ComputerName = $hostname[0]
                    OS           = $osName
                }
            }
        }
    }
    
    if ($obsoleteHosts.Count -gt 0) {
        Write-Host "`nObsolete OS found:"
        $obsoleteHosts | Format-Table -AutoSize
    } else {
        Write-Host "`nNo obsolete OS found."
    }




    #Password policy enumeration
    #uses the first DC returned.
    echo ""
    Write-Host "=======[Checking password policy, GPOs, and fine grain policies from: $DC]==========" -BackgroundColor Red
    echo ""
    $DC = ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=8192))").findOne() | ForEach-Object { $_.properties.name}
    echo "Checking policy applied to current account" -ForegroundColor Green
    net accounts
    echo ""
    Write-Host "Checking other policies" -ForegroundColor Green
    echo ""
    Get-ChildItem \\$DC\sysvol\*\GptTmpl.inf -Recurse -erroraction 'silentlycontinue'  | select-string -Pattern ".*Bad.*|Password.*"  -AllMatches |  Format-Table -GroupBy Path -Property line
    echo ""
    Write-Host "Checking for accounts with a fine grain policy applied" -ForegroundColor Green
    echo ""
    $Filter = "(msds-psoapplied=*)"
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DC")
    $Searcher.Filter = $Filter 
    $Searcher.SearchScope = "Subtree"
    $Result = $Searcher.FindAll()
    foreach ($objResult in $Result)
        {echo ""; $objResult.Properties.givenname; $objResult.Properties."msds-psoapplied";}

    echo ""
    Write-Host "Checking for fine grain policy details (may require elevated privileges to see)" -ForegroundColor Green
    echo ""
    $Filter2 = "(msDS-LockoutThreshold=*)"
    $Searcher2 = New-Object DirectoryServices.DirectorySearcher
    $Searcher2.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DC")
    $Searcher2.Filter = $Filter2
    $Searcher2.SearchScope = "Subtree"
    $Searcher2.FindAll()
    $Result2 = $Searcher2.FindAll()
    foreach ($objResult2 in $Result2)
        {echo ""; $objResult2.Properties.cn; echo "User who this applies to"; $objResult2.Properties."msds-psoappliesto"; echo "Lockout Threshold"; $objResult2.Properties."msds-lockoutthreshold";echo "Min Password Length"; $objResult2.Properties."msds-minimumpasswordlength"; echo "Reversible Encryption Enabled?"; $objResult2.Properties."msds-passwordreversibleencryptionenabled"; echo "Min Password Age"; $objResult2.Properties."msds-minimumpasswordage"; echo "Password Complexity Enabled?"; $objResult2.Properties."msds-passwordcomplexityenabled"; echo "Password Settings Precedence"; $objResult2.Properties."msds-passwordsettingsprecedence"; echo "Max Password Age"; $objResult2.Properties."msds-maximumpasswordage"; echo "LockoutDuration"; $objResult2.Properties."msds-lockoutduration"; echo "Lockout Observation Window"; $objResult2.Properties."msds-lockoutobservationwindow"; echo "Password History Length"; $objResult2.Properties."msds-passwordhistorylength"; 
        Out-Null
        } 
        
    Write-Output ""    
    Write-Output "-------------------------------------------"    
    Stop-Transcript
    Write-Output "List of domain users: DomainUsers.txt" 
    Write-Output "-------------------------------------------"
}
