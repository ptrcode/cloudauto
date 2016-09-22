Param(
	[string]$FolderName
)

if ([string]::IsNullOrEmpty($FolderName)) {
	$FolderName = Read-host "Enter the name of the Folder you wish to create"	
}

(get-view (get-view -ViewType datacenter -Filter @{"name"=(Get-Datacenter)[0].Name}).VmFolder).CreateFolder($FolderName)