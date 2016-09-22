$FolderName = Read-host "Enter the name of the Folder you wish to create"

New-Folder -Name $FolderName -Location (Get-Datacenter)[0]