import-module .\PowerView.ps1


function adenum {
    del log.txt -erroraction 'silentlycontinue'
    del DomainUsers.txt -erroraction 'silentlycontinue'
    Write-Host "=====[Domain Controllers]==========" -ForegroundColor Red | Tee-Object -file log.txt
    #Get-Domain | Tee-Object -file log.txt
    #native
    $Domain = "$env:userdnsdomain"
    nltest /dclist:$Domain
    Write-Host "=======[Domain Users]==========" -ForegroundColor Red | Tee-Object -file log.txt
    #Get-DomainUser | Select-object -expandproperty samaccountname |  Tee-Object -file DomainUsers.txt
    #native
    (New-Object DirectoryServices.DirectorySearcher "objectcategory=user").FindAll() | ForEach-Object { $_.Properties.samaccountname } | Tee-Object -file log.txt 
    Write-Host "=======[Domain Groups]==========" -ForegroundColor Red| Tee-Object -file log.txt
    #Get-DomainGroup |  Select-object -expandproperty samaccountname | Tee-Object -file log.txt
    #native
    (New-Object DirectoryServices.DirectorySearcher "objectcategory=group").FindAll() | ForEach-Object { $_.Properties.samaccountname } | Tee-Object -file log.txt
    Write-Host "=======[Enumerating Domain GPOs]==========" -ForegroundColor Red| Tee-Object -file log.txt
    Get-DomainGPO | select displayname,gpcfilesyspath,objectcategory | format-list  | Tee-Object -file log.txt 
    Write-Host "=======[GPOs applied to current computer]==========" -ForegroundColor Red| Tee-Object -file log.txt    
    Get-DomainGPO -ComputerIdentity (hostname) | select displayname,gpcfilesyspath,objectcategory | format-list | Tee-Object -file log.txt
    Write-Host "=======[GPOs applied to current user]==========" -ForegroundColor Red| Tee-Object -file log.txt   
    Get-DomainGPO -UserIdentity ([Environment]::UserName) | select displayname,gpcfilesyspath,objectcategory | format-list | Tee-Object -file log.txt
    Write-Host "=======[Enumerating LDAP descriptions]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    Get-DomainUser | Select Name,Description| format-list | Tee-Object -file log.txt 
    Write-Host "=======[Enumerating current user's MAQ]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    #$Domain = "$env:userdnsdomain"
    #$LDAP = "DC=" + $Domain.Split(".")
    #$LDAP = $LDAP -replace " ", ",DC="
    #(Get-DomainObject -Identity $LDAP -Properties ms-DS-MachineAccountQuota) | Select-Object -ExpandProperty ms-DS-MachineAccountQuota
    #Native
    echo "MAQ:"
    (New-Object DirectoryServices.DirectorySearcher "ms-DS-MachineAccountQuota=*").FindAll() | ForEach-Object { $_.Properties.'ms-ds-machineaccountquota'} | Tee-Object -file log.txt 
    Write-Host "=======[Domain Trusts]==========" -ForegroundColor Red| Tee-Object -file log.txt 
    #Native
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
    #native
    ([adsisearcher]"(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=*))").findAll() | ForEach-Object { $_.properties}
    Write-Host "=======[SCCM]==========" -ForegroundColor Red| Tee-Object -file log.txt
    #native
    ([ADSISearcher]("objectClass=mSSMSManagementPoint")).FindAll() | % {$_.Properties} | Tee-Object -file log.txt
    Write-Host "=======[MSSQL]==========" -ForegroundColor Red| Tee-Object -file log.txt
    Get-DomainGroup -Identity *SQL* | % { Get-DomainGroupMember -Identity $_.distinguishedname | select groupname, membername } | Tee-Object -file log.txt


}
