$VMName = Read-host "Enter the name of the VM you wish to create"

#Lists host for the connected vCenter, prompts user to enter the desired host location for the VM

Get-VMHost | Format-Wide
$HOSTName = Read-host "Enter the Name of the Host you wish to create the VM on"

#Lists datastores for the connected vCenter, prompts user to enter the desired datastore location for the VM

Get-Datastore | Format-Wide
$DSName = Read-Host "Enter the name of the datastore you wish to create the VM on"

#Lists VM folders for the connected vCenter, prompts user to enter the desired folder location for the VM

Get-Folder | Format-Wide
$FOLDERName = Read-host "Enter the name of the folder you wish to create the VM in"

#Takes input from above steps and passes them to the New-VM command for VM creation

#Get-VirtualPortGroup | Format-Wide
#$PortName = Read-host "Enter the name of the portgroup you wish to add to the VM: "

Get-Template | Format-Wide
$TemplateName = Read-host "Enter the name of the template you'd like to use: "
$Template = Get-Template | Where-Object {$_.Name -eq $TemplateName}

New-VM -Name $VMName -Template $Template -VMHost $HOSTName -Location $FOLDERName -Datastore $DSName

#New-VM -Name $VMName -Template $Template -Location $FOLDERName -VMHost $HOSTName -Datastore $DSName -Version v9 -GuestId windows8Server64Guest -NumCpu 1 -MemoryMB 4096 -DiskMB 40960 -DiskStorageFormat Thin -PortGroup (Get-VirtualPortGroup | Where-Object {$_.Name -eq $PortName})

#Once VM creation is completed, VM network adapters are converted to vmxnet3

Get-VM $VMName | Get-NetworkAdapter | Set-NetworkAdapter -Confirm:$false -Type vmxnet3 
#Get-VM $VMName | Get-NetworkAdapter | Set-NetworkAdapter -NetworkName "ral01test01" -Confirm:$false
#Get-VM 'test01_ad01' | Get-NetworkAdapter | Set-NetworkAdapter -Confirm:$false -PortGroup (Get-VDPortGroup | Where-Object {$_.Name -eq 'test01'})
