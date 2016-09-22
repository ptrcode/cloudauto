function Invoke-ChangeComputerName {
 	Param(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$ComputerName=$(throw "BuildName is mandatory, please provide a value."),
		[Parameter()]
		[ValidateNotNullOrEmpty()]   
		[string]$VmName=$(throw "BuildName is mandatory, please provide a value."),
		[Parameter()]
		[ValidateNotNullOrEmpty()]   
		[PSObject]$GuestCred=$(throw "GuestCred is mandatory, please provide a value.")
	)

	$VM = Get-VM $VmName
	
	$scriptString = "
		[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
		`$Name = ""$ComputerName""
		`$computerName = Get-WmiObject Win32_ComputerSystem
		`$computerName.Rename(`$Name)
	"
	
	Write-Host $scriptString
	
	Invoke-VMScript -VM $VM -GuestCredential $GuestCred -ScriptType PowerShell -ScriptText $scriptString

}