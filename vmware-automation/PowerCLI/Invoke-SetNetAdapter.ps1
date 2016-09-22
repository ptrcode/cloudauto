
Param(
  [string]$IP,
  [string]$GW,
  [string]$DNS,
  [string]$VmName,
  [PSObject]$GuestCred
)

$VM = Get-VM $VmName

$scriptString = "
`$netadapter = Get-NetAdapter -Name Ethernet
`$netadapter | Set-NetIPInterface -DHCP Disabled
`$netadapter | New-NetIPAddress -AddressFamily IPv4 -IPAddress $IP -PrefixLength 24 -Type Unicast -DefaultGateway $GW
`Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses $DNS
"

Write-Host $scriptString

Invoke-VMScript -VM $VM -GuestCredential $GuestCred -ScriptType PowerShell -ScriptText $scriptString
