Param(
	[string]$ServerName,
  [PSObject]$Credential
)

Connect-VIServer -Server $ServerName -Protocol https -Credential $Credential
