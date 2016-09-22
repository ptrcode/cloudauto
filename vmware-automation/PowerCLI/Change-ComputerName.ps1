
Param(
  [string]$Name
)

if ([string]::IsNullOrEmpty($Name)) { 
	Write-Host "Useage: Change-ComputerName -Name <name>"
	Exit 
}

[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
$computerName = Get-WmiObject Win32_ComputerSystem
$computername.Rename($Name)
