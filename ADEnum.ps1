import-module .\PowerView.ps1

function adenum {
    del log.txt 
    del DomainUsers.txt
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
    Write-Host "=======[Domain Trusts]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    nltest /DOMAIN_TRUSTS /ALL_TRUSTS
    Write-Host "=======[Kerberoastable Users]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    Get-DomainUser -SPN | select name,serviceprincipalname
    Write-Host "=======[ASREP roastable Users]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    Get-DomainUser -PreauthNotRequired | select name
    Write-Host "=======[ADCS]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    Write-Host "To Do" -ForegroundColor Green| Tee-Object -file log.txt

}
