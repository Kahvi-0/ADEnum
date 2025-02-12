import-module .\PowerView.ps1


function adenum {
    del log.txt -erroraction 'silentlycontinue'
    del DomainUsers.txt -erroraction 'silentlycontinue'
    Write-Host "=====[Enumerating Domain Info]==========" -ForegroundColor Red | Tee-Object -file log.txt
    Get-Domain | Tee-Object -file log.txt
    Write-Host "=======[Enumerating Domain Users]==========" -ForegroundColor Red | Tee-Object -file log.txt
    Get-DomainUser | Select-object -expandproperty samaccountname |  Tee-Object -file DomainUsers.txt
    Write-Host "=======[Enumerating Domain Groups]==========" -ForegroundColor Red| Tee-Object -file log.txt
    Get-DomainGroup |  Select-object -expandproperty samaccountname | Tee-Object -file log.txt
    Write-Host "=======[Enumerating Domain GPOs]==========" -ForegroundColor Red| Tee-Object -file log.txt
    Get-DomainGPO | select displayname,gpcfilesyspath,objectcategory | format-list  | Tee-Object -file log.txt 
    Write-Host "=======[GPOs applied to current computer]==========" -ForegroundColor Red| Tee-Object -file log.txt    
    Get-DomainGPO -ComputerIdentity (hostname) | select displayname,gpcfilesyspath,objectcategory | format-list | Tee-Object -file log.txt
    Write-Host "=======[GPOs applied to current user]==========" -ForegroundColor Red| Tee-Object -file log.txt   
    Get-DomainGPO -UserIdentity ([Environment]::UserName) | select displayname,gpcfilesyspath,objectcategory | format-list | Tee-Object -file log.txt
    Write-Host "=======[Enumerating LDAP descriptions]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    Get-DomainUser | Select Name,Description| format-list | Tee-Object -file log.txt 
    Write-Host "=======[Enumerating current user's MAQ]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    $Domain = "$env:userdnsdomain"
    $LDAP = "DC=" + $Domain.Split(".")
    $LDAP = $LDAP -replace " ", ",DC="
    (Get-DomainObject -Identity $LDAP -Properties ms-DS-MachineAccountQuota) | Select-Object -ExpandProperty ms-DS-MachineAccountQuota
    #Non PV method, need to filter out other noise
    #([adsisearcher]"(&(ms-DS-MachineAccountQuota=*))").findAll()| ForEach-Object { $_.properties}
    Write-Host "=======[Domain Trusts]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    nltest /DOMAIN_TRUSTS /ALL_TRUSTS
    Write-Host "=======[Kerberoastable Users]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    Get-DomainUser -SPN | select name,serviceprincipalname | Out-String  | Tee-Object -file log.txt 
    Write-Host "=======[ASREP roastable Users]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    Get-DomainUser -PreauthNotRequired | select name | Out-String | Tee-Object -file log.txt 
    Write-Host "=======[ADCS]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    Write-Host "To Do, for now use NXC or another tool <3" -ForegroundColor Green| Tee-Object -file log.txt
    Write-Host "=======[LDAP Signing]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    Write-Host "To Do, for now use NXC or another tool <3" -ForegroundColor Green| Tee-Object -file log.txt
    Write-Host "=======[Unconstrained Delegation]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    Get-DomainComputer -Unconstrained -Properties name,samaccountname,useraccountcontrol | format-list | Tee-Object -file log.txt 
    Write-Host "=======[Constrained Delegation]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    Get-DomainUser -TrustedToAuth | select userprincipalname,msds-allowedtodelegateto | format-list | Tee-Object -file log.txt
    Get-DomainComputer -TrustedToAuth | select name,msds-allowedtodelegateto | format-list | Tee-Object -file log.txt
    Write-Host "=======[LAPS]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    ([adsisearcher]"(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=*))").findAll() | ForEach-Object { $_.properties}
    Write-Host "=======[SCCM]==========" -ForegroundColor Red| Tee-Object -file log.txt
    ([ADSISearcher]("objectClass=mSSMSManagementPoint")).FindAll() | % {$_.Properties} | Tee-Object -file log.txt
    Write-Host "=======[MSSQL]==========" -ForegroundColor Red| Tee-Object -file log.txt
    Get-DomainGroup -Identity *SQL* | % { Get-DomainGroupMember -Identity $_.distinguishedname | select groupname, membername } | Tee-Object -file log.txt


}
