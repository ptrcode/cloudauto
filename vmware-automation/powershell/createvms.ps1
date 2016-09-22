<#	
	.NOTES
	===========================================================================
	 Created on:   	3/1/2015 11:30 AM
	 Created by:   	papu
	 Organization: 	Medfusion Inc
	 Filename:createvm.ps1     	
	===========================================================================
	.DESCRIPTION
		A description of the file.
	It will take the VM's information from CSV file and will provision the VM's 
#>
#Just take input as full path of the CSV file
PARAM (
	[Parameter(Mandatory = $true, HelpMessage = "You must specify the full path of the INI file")]
	[ValidateScript({ Test-Path -Path $_ })]
	$iniPath,
	[Parameter(Mandatory = $true, HelpMessage = "You must specify the full path of the CSV file")]
	[ValidateScript({ Test-Path -Path $_ })]
	$csvPath)

#Specify the path of the ini file
$iniFile = $iniPath
$iniContent = ConvertFrom-StringData((Get-Content $iniPath) -join "`n")
#Write-Host ($iniContent | Out-String) -ForegroundColor Red
#Write-Host $iniContent.user
#Specify the path of the csv file
$csvFile = $csvPath
#Import-CSV $FilePath | Get-Member
#Clear-Host
$Records = Import-CSV $csvFile
#just for testing records - commennted
<#$Records | foreach {
	Write-Output $_ `n
}#>
#initialize the powercli environment
D:\buildagent\workspace\root\DevOps\Create_VM\powershell\setenv.bat
Add-PSSnapin "VMware.VimAutomation.Core" | Out-Null
<#cd "%ProgramFiles(x86)%"\VMware\Infrastructure\vSphere PowerCLI\Scripts\
powershell .\Initialize-PowerCLIEnvironment.ps1#>

#connect the server  - should we take it from commandline ? currently hardcoded
Connect-VIServer -Server $iniContent.vcenter_host -Protocol https -User $iniContent.vcenter_user -Password $iniContent.vcenter_password
#added the memory parameter
$Records | foreach {
	#	Write-Output $_.ipAddress $_.vmname $_.templateName $_.physicalHost $_.dataStore $_.clusterPool $_.clusterPool $_.folder $_.networkName
	New-VM -Name $_.vmname -Template $_.templateName -VMHost  $_.physicalHost -Datastore $_.dataStore -ResourcePool $_.ResourcePool -Location $_.FolderLocation  -RunAsync
}
#guest password initialized - simple string dont work
$guestUser= $iniContent.vm_user
$guestPassword = $iniContent.vm_password

#Lets start and wait
$Records | foreach {
	#lets wait untill the vm is created
	#changes for https://medfusion.atlassian.net/browse/DEVOPS-190 - keep pinging the hosts unless start 
	While ((Get-VM $_.vmname).Version -eq “Unknown”)
	{
		Write-Host “Waiting to start .....” $_.vmname -ForegroundColor Red
		Start-Sleep -milliseconds 10000
	}
	#$vm = Get-View -ViewType VirtualMachine -Filter @{ "Name" = $_.vmname }
	#set the memory -- in NewVM call it should have worked , but it does not
	get-vm $_.vmname | Set-VM -MemoryMB $_.MemoryMB -Confirm:$false
	#lets pause a bit
	Sleep 5
	#start the vm
	Start-VM $_.vmname
	Sleep 10
	#lets check whether vmware tools is running
	while (((get-vm $_.vmname).ExtensionData.Guest.ToolsRunningStatus) -ne "guestToolsRunning")
	{
		Write-Host "....." -ForegroundColor Yellow
		Sleep 5
	}
    $myHostName = $_.vmname
	$myip = $_.ipAddress
	$myNetmask = $_.netmask
	$myGateway = $_.gateway
	$myDns = $_.dns
	$script = "/root/changescript.sh   $myHostName $myip  $myNetmask  $myGateway  $myDns"
	Write-Host $script
	Invoke-VMScript -ScriptText $script -VM $_.vmname -GuestUser root -GuestPassword $guestPassword
	#sometime this call to Invoke-VMScript failing - lets repeatedly attempt unless it pass
	while ($? -eq $false)
	{
		sleep 2
		Invoke-VMScript -ScriptText $script -VM $_.vmname -GuestUser root -GuestPassword $guestPassword
	}
}

