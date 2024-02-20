
function passpull {

    $DC=$args[0]
    echo "--------------------------------"
    echo "Checking policy applied to current account"
    echo "--------------------------------"
    net accounts


    # Other policies 
    echo ""
    echo "--------------------------------"
    echo "Checking other policies"
    echo "--------------------------------"
    Get-ChildItem \\$DC\sysvol\*\GptTmpl.inf -Recurse -erroraction 'silentlycontinue'  | select-string -Pattern ".*Bad.*|Password.*"  -AllMatches |  Format-Table -GroupBy Path -Property line

    # Fine Grain 
    echo ""
    echo "--------------------------------"
    echo "Checking for fine grain policies"
    echo "--------------------------------"
    $Filter = "(msds-psoapplied=*)"
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DC")
    $Searcher.Filter = $Filter 
    $Searcher.SearchScope = "Subtree"
    $Result = $Searcher.FindAll()
    foreach ($objResult in $Result)
        {echo ""; $objResult.Properties.givenname; $objResult.Properties."msds-psoapplied";}

    echo ""
    echo "--------------------------------"
    echo "Checking for fine grain policies"
    echo "--------------------------------"
    $Filter = "(msDS-LockoutThreshold=*)"
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DC")
    $Searcher.Filter = $Filter
    $Searcher.SearchScope = "Subtree"
    $Searcher.FindAll()
    foreach ($objResult in $Result)
        {echo ""; $objResult.Properties.givenname; $objResult.Properties.LockoutThreshold;}
}
