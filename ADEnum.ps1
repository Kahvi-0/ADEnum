function adenum {
    del log.txt -erroraction 'silentlycontinue'
    Write-Host "=====[Domain Controllers]==========" -ForegroundColor Red | Tee-Object -file AD-Status.log
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=8192))").findAll() | ForEach-Object { $_.properties.name} | Tee-Object -file AD-Status.log
    Write-Host "=======[Domain Users]==========" -ForegroundColor Red | Tee-Object -file AD-Status.log
    (New-Object DirectoryServices.DirectorySearcher "objectcategory=user").FindAll() | ForEach-Object { $_.Properties.samaccountname } | Tee-Object -file AD-Status.log
    Write-Host "=======[Domain Groups]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    (New-Object DirectoryServices.DirectorySearcher "objectcategory=group").FindAll() | ForEach-Object { $_.Properties.samaccountname } | Tee-Object -file AD-Status.log
    Write-Host "=======[Members of the protected users group]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    ([adsisearcher]"(&(objectCategory=group)(name=protected users))").findAll() | ForEach-Object { $_.properties.name,$_.properties.member,""} | Tee-Object -file AD-Status.log
    Write-Host "=======[Enumerating Domain GPOs]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    (New-Object DirectoryServices.DirectorySearcher "objectCategory=groupPolicyContainer").FindAll()| ForEach-Object { $_.Properties.displayname,$_.Properties.gpcfilesyspath,""} | Tee-Object -file AD-Status.log
    Write-Host "=======[GPOs applied to current user and computer]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    Write-Host "If you do not see the computer settings, elevate powershell to admin" -ForegroundColor Green| Tee-Object -file AD-Status.log
    gpresult /r /f
    Write-Host "=======[Enumerating LDAP descriptions]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    ([adsisearcher]"(&(objectCategory=user)(description=*))").findAll() | ForEach-Object { $_.properties.name,$_.properties.description,""} | Tee-Object -file AD-Status.log
    Write-Host "=======[Enumerating current user's MAQ]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    echo "MAQ:" | Tee-Object -file AD-Status.log
    (New-Object DirectoryServices.DirectorySearcher "ms-DS-MachineAccountQuota=*").FindAll() | ForEach-Object { $_.Properties.'ms-ds-machineaccountquota'} | Tee-Object -file AD-Status.log
    Write-Host "=======[Domain Trusts]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    nltest /DOMAIN_TRUSTS /ALL_TRUSTS | Tee-Object -file AD-Status.log
    Write-Host "=======[Kerberoastable Users]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    ([adsisearcher]"(&(objectCategory=user)(servicePrincipalname=*))").findAll() | ForEach-Object { $_.properties.name,$_.properties.serviceprincipalname,""} | Tee-Object -file AD-Status.log
    Write-Host "=======[ASREP roastable Users]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=4194304))").findAll() | ForEach-Object { $_.properties.name} | Tee-Object -file AD-Status.log
    Write-Host "=======[ADCS]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    Write-Host "To Do, for now use NXC or another tool <3" -ForegroundColor Green| Tee-Object -file AD-Status.log
    Write-Host "=======[LDAP Signing]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    Write-Host "To Do, for now use NXC or another tool <3" -ForegroundColor Green| Tee-Object -file AD-Status.log
    Write-Host "=======[Unconstrained Delegation]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=524288))").findAll() | ForEach-Object { $_.properties.name} | Tee-Object -file AD-Status.log
    Write-Host "=======[Constrained Delegation]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    ([adsisearcher]"(&(msds-allowedtodelegateto=*))").findAll() | ForEach-Object { $_.properties.name,$_.properties."msds-allowedtodelegateto",""} | Tee-Object -file AD-Status.log
    Write-Host "=======[Accounts marked for No Delegation]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=1048576))").findAll() | ForEach-Object { $_.properties.name} | Tee-Object -file AD-Status.log
    Write-Host "=======[Accounts that require smart cards for interaction]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=262144))").findAll() | ForEach-Object { $_.properties.name} | Tee-Object -file AD-Status.log
    Write-Host "=======[Accounts where a password is not required]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=32))").findAll() | ForEach-Object { $_.properties.name} | Tee-Object -file AD-Status.log
    Write-Host "=======[Interdomain Trust: Accounts trusted for a system domain that trusts other domains.]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    ([adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=2048))").findAll() | ForEach-Object { $_.properties.name} | Tee-Object -file AD-Status.log
    Write-Host "=======[GMSA Service]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    echo "Need to expand on later" | Tee-Object -file AD-Status.log
    ([adsisearcher]"(&(objectClass=msDS-ManagedServiceAccount))").findAll() | ForEach-Object { $_.properties,""} | Tee-Object -file AD-Status.log
    ([adsisearcher]"(&(PrincipalsAllowedToRetrieveManagedPassword=*))").findAll() | ForEach-Object { $_.properties,""} | Tee-Object -file AD-Status.log
    Write-Host "=======[LAPS]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    ([adsisearcher]"(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=*))").findAll() | ForEach-Object { $_.properties} | Tee-Object -file AD-Status.log
    Write-Host "=======[SCCM]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    ([ADSISearcher]("objectClass=mSSMSManagementPoint")).FindAll() | % {$_.Properties} | Tee-Object -file AD-Status.log
    Write-Host "=======[MSSQL]==========" -ForegroundColor Red| Tee-Object -file AD-Status.log
    echo "Not perfect, computer accounts based off name. Sill enum via nmap with -sV"
    ([adsisearcher]"(&(objectCategory=computer)(Name=*SQL*))").findAll() | ForEach-Object { $_.properties.name,""} | Tee-Object -file AD-Status.log

    Write-Host "================================" -ForegroundColor Red
    Write-Host "Output is saved in AD-Status.log" -ForegroundColor Green
    Write-Host "================================" -ForegroundColor Red
}
