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
            $files = Get-ChildItem -Path $sharePath -ErrorAction SilentlyContinue
            $readAccess = $true
        } catch {}
        try {
            Set-Content -Path $testFile -Value "test" -ErrorAction SilentlyContinue
            Remove-Item -Path $testFile -ErrorAction SilentlyContinue
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
					if ($permissions.ReadAccess -or $permissions.WriteAccess) {
					    $accessibleShares += [PSCustomObject]@{
					        Path        = $path
					        ReadAccess  = $permissions.ReadAccess
					        WriteAccess = $permissions.WriteAccess
					    }
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
