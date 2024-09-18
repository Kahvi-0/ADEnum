echo "Checking if the ProcessCreationIncludeCmdLine_Enabled is set to 1(true)"
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name "ProcessCreationIncludeCmdLine_Enabled" | Select 'ProcessCreationIncludeCmdLine_Enabled'
echo "-----------------------------------------------------------------------"

echo "Checking all windows 4688 events"
get-winevent @{logname='security';id=4688}  | % { [xml]$xml = $_.toxml(); $xml.event.eventdata.data } | ? name -match 'commandline'  > pc.txt

Get-Content pc.txt | Sort-Object -unique > Commands.txt
del pc.txt
echo ""
echo "Full output was saved to Commands.txt"
echo "-------------------------------------"
echo ""
echo ""
echo "Here are some common regex used to try and find some passwords"
echo "--------------------------------------------------------------"
Select-String -Path Commands.txt "net.*user.*" -AllMatches | Foreach-Object {$_.Matches}  | Foreach-Object {$_.Value}
