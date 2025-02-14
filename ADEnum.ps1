function adenum {
    del log.txt -erroraction 'silentlycontinue'
    del DomainUsers.txt -erroraction 'silentlycontinue'
    Write-Host "=====[Domain Controllers]==========" -ForegroundColor Red | Tee-Object -file log.txt
    #$Domain = "$env:userdnsdomain"
    #nltest /dclist:$Domain
    #Native LDAP
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=8192))").findAll() | ForEach-Object { $_.properties.name}
    Write-Host "=======[Domain Users]==========" -ForegroundColor Red | Tee-Object -file log.txt
    (New-Object DirectoryServices.DirectorySearcher "objectcategory=user").FindAll() | ForEach-Object { $_.Properties.samaccountname } | Tee-Object -file log.txt 
    Write-Host "=======[Domain Groups]==========" -ForegroundColor Red| Tee-Object -file log.txt
    (New-Object DirectoryServices.DirectorySearcher "objectcategory=group").FindAll() | ForEach-Object { $_.Properties.samaccountname } | Tee-Object -file log.txt
    Write-Host "=======[Enumerating Domain GPOs]==========" -ForegroundColor Red| Tee-Object -file log.txt
    (New-Object DirectoryServices.DirectorySearcher "objectCategory=groupPolicyContainer").FindAll()| ForEach-Object { $_.Properties.displayname,$_.Properties.gpcfilesyspath,""}
    Write-Host "=======[GPOs applied to current computer]==========" -ForegroundColor Red| Tee-Object -file log.txt
    #Get-DomainGPO -ComputerIdentity (hostname) | select displayname,gpcfilesyspath,objectcategory | format-list | Tee-Object -file log.txt
    Write-Host "=======[GPOs applied to current user]==========" -ForegroundColor Red| Tee-Object -file log.txt   
    $GUID = [guid]::New(([adsisearcher]"SamAccountName=$env:USERNAME").FindOne().Properties.objectguid[0]).Guid
    echo "Still figuring a clean way to convert GUIDS"
    ([adsisearcher]"(&(objectCategory=groupPolicyContainer))").findAll() | ForEach-Object { $_.properties.displayname,$_.properties.gpcmachineextensionnames,""}

    #$user =[Environment]::UserName
    #([adsisearcher]"(&(objectCategory=user)(name=$user))").findAll()
    #[guid]::New(([adsisearcher]"SamAccountName=$env:COMPUTERNAME`$").FindOne().Properties.objectguid[0]).Guid
    #[guid]::New(([adsisearcher]"SamAccountName=$env:USERNAME").FindOne().Properties.objectguid[0]).Guid
    Write-Host "=======[Enumerating LDAP descriptions]==========" -ForegroundColor Red| Tee-Object -file log.txt
    ([adsisearcher]"(&(objectCategory=user)(description=*))").findAll() | ForEach-Object { $_.properties.name,$_.properties.description,""}
    Write-Host "=======[Enumerating current user's MAQ]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    echo "MAQ:"
    (New-Object DirectoryServices.DirectorySearcher "ms-DS-MachineAccountQuota=*").FindAll() | ForEach-Object { $_.Properties.'ms-ds-machineaccountquota'} | Tee-Object -file log.txt 
    Write-Host "=======[Domain Trusts]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    nltest /DOMAIN_TRUSTS /ALL_TRUSTS
    Write-Host "=======[Kerberoastable Users]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    ([adsisearcher]"(&(objectCategory=user)(servicePrincipalname=*))").findAll() | ForEach-Object { $_.properties.name,$_.properties.serviceprincipalname,""} | Tee-Object -file log.txt
    Write-Host "=======[ASREP roastable Users]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=4194304))").findAll() | ForEach-Object { $_.properties.name} | Tee-Object -file log.txt
    Write-Host "=======[ADCS]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    Write-Host "To Do, for now use NXC or another tool <3" -ForegroundColor Green| Tee-Object -file log.txt
    Write-Host "=======[LDAP Signing]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    Write-Host "To Do, for now use NXC or another tool <3" -ForegroundColor Green| Tee-Object -file log.txt
    Write-Host "=======[Unconstrained Delegation]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=524288))").findAll() | ForEach-Object { $_.properties.name}
    Write-Host "=======[Constrained Delegation]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    ([adsisearcher]"(&(msds-allowedtodelegateto=*))").findAll() | ForEach-Object { $_.properties.name,$_.properties."msds-allowedtodelegateto",""}
    Write-Host "=======[Accounts marked for No Delegation]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=1048576))").findAll() | ForEach-Object { $_.properties.name}
    Write-Host "=======[Accounts that require smart cards for interaction]==========" -ForegroundColor Red| Tee-Object -file log.txt
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=262144))").findAll() | ForEach-Object { $_.properties.name}
    Write-Host "=======[Accounts where a password is not required]==========" -ForegroundColor Red| Tee-Object -file log.txt
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=32))").findAll() | ForEach-Object { $_.properties.name}
    Write-Host "=======[Interdomain Trust: Accounts trusted for a system domain that trusts other domains.]==========" -ForegroundColor Red| Tee-Object -file log.txt
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=2048))").findAll() | ForEach-Object { $_.properties.name}
    Write-Host "=======[LAPS]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    ([adsisearcher]"(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=*))").findAll() | ForEach-Object { $_.properties} | Tee-Object -file log.txt
    Write-Host "=======[SCCM]==========" -ForegroundColor Red| Tee-Object -file log.txt
    ([ADSISearcher]("objectClass=mSSMSManagementPoint")).FindAll() | % {$_.Properties} | Tee-Object -file log.txt
    Write-Host "=======[MSSQL]==========" -ForegroundColor Red| Tee-Object -file log.txt
    #Still to do
    #Get-DomainGroup -Identity *SQL* | % { Get-DomainGroupMember -Identity $_.distinguishedname | select groupname, membername } | Tee-Object -file log.txt


}
