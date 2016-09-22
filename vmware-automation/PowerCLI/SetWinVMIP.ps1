Function Set-WinVMIP ($VM, $GC, $IP, $SNM, $GW){
 $netsh = "c:\windows\system32\netsh.exe interface ip set address ""Local Area Connection"" static $IP $SNM $GW 1"
 Write-Host "Setting IP address for $VM..."
 Invoke-VMScript -VM $VM -GuestCredential $GC -ScriptType bat -ScriptText $netsh
 Write-Host "Setting IP address completed."
}
 
$VM = Get-VM ( Read-Host "Enter VM name" )
#$ESXHost = $VM | Get-VMHost
$GuestCred = $Host.UI.PromptForCredential("Please enter credentials", "Enter Guest credentials for $VM", "", "")
 
$IP = "10.112.1.11"
$SNM = "255.255.255.0"
$GW = "10.112.1.254"
 
Set-WinVMIP $VM $HostCred $GuestCred $IP $SNM $GW