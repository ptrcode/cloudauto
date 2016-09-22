
$newPortGroup = Read-host "Enter the name of the port group you'd like to create"
$vlanId = Read-Host "What VLAN ID would you like to give this port group?"
$numPorts = Read-Host "How many ports would you like it to have? "
New-VDPortGroup -VDSwitch vDS_host_pNICs -Name $newPortGroup -VlanId $vlanId -NumPorts $numPorts
