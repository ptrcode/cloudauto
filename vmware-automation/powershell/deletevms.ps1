<#	
	.NOTES
	===========================================================================
	 Created on:   	3/26/2015 11:42 PM
	 Created by:   	papu
	 Organization: 	Medfusion
	 Filename:   deletevms.ps1  	
	===========================================================================
	.DESCRIPTION
		A description of the file.
	The script will stop the vm if powered on and then permanently delete from disks without confirmation 
	It has to be run like
	.\deletevms.ps1  iniFilePath vm1 vm2 vm3 
	where vm1 vm2 vm3 are the names of the vm's
#>
Function sendMail([string]$emailSmtpServer, [string]$emailfrom,[string]$emailto,[string]$emailSubject,[string]$emailbody,[System.Management.Automation.PSCredential]$mycreds){
    Send-MailMessage -To $emailTo -From $emailFrom  -Credential $mycreds -Subject $emailSubject -Body $emailBody -BodyAsHTML -SmtpServer $emailSmtpServer 
}
#Specify the path of the ini file
#$iniPath = "D:\medfusionwork\git\vmware-automation\credential.ini"
$iniPath = "D:\buildagent\workspace\root\DevOps\DeleteVMwithName\vmware-automation\credential.ini"
$iniContent = ConvertFrom-StringData((Get-Content $iniPath) -join "`n")
#initialize the powercli environment
D:\buildagent\workspace\root\DevOps\Create_VM\powershell\setenv.bat
Add-PSSnapin "VMware.VimAutomation.Core" | Out-Null
#Connect-VIServer -Server 172.18.81.250 -Protocol https -User "pbhattacharya" -Password "M3dfusion!"
Connect-VIServer -Server $iniContent.vcenter_host -Protocol https -User $iniContent.vcenter_user -Password $iniContent.vcenter_password
$args | foreach{
	$vm = Get-View -ViewType VirtualMachine -Filter @{ "Name" = "$_" }
	if (!$vm)
	{
		Write-Host "No VM named $_ exists"
		continue
	}
	if ($vm.Runtime.PowerState -ne "PoweredOff")
	{
		$ipAddress= $vm.guest.IPAddress
        Write-Host "Stoping the VM" -ForegroundColor Red
		Stop-VM -VM $_ -Confirm:$false
	}
	Write-Host “Going to permanently destroy the vm of name  $_”
	Remove-VM $_ -DeletePermanently -Confirm:$false
    if ($? -eq $true){
    $emailSmtpServer = "strongmail.dev.medfusion.net"
    $emailfrom = "infosys@medfusion.com"
    $emailto = "devops@medfusion.com;itops@medfusion.com"
    $emailSubject = "Deleted virtual machine $_ "
    $emailbody =  "The following VM has been deleted: $_  `n The following IP address has been reclaimed: $ipAddress"
    $secpasswd = ConvertTo-SecureString "M3dfusion!" -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential("phattacharya@medfusion.com",$secpasswd)
    sendMail $emailSmtpServer $emailfrom $emailto $emailSubject $emailbody $mycreds
    }
    
}
return 0
