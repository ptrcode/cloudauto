<#	
	.NOTES
	===========================================================================
	 Created on:   	3/26/2015 11:42 PM
	 Created by:   	papu
	 Organization: 	Medfusion
	 Filename:   vmwareCheckByName.ps1  	
	===========================================================================
	.DESCRIPTION
		A description of the file.
	The script will stop the vm if powered on and then permanently delete from disks without confirmation 
	It has to be run like
	.\vmwareCheckByName.ps1 vm1 
	where vm1 is the name of the vm
#>
Connect-VIServer -Server '172.18.81.250' -Protocol https -User 'pbhattacharya' -Password M3dfusion!
$VMName = Get-VM -name $args[0]
if (!$VMname)
{
	return 1
}
else
{	
	return 0
}

