cd "%ProgramFiles(x86)%"\VMware\Infrastructure\vSphere PowerCLI\Scripts\
C:
powershell .\Initialize-PowerCLIEnvironment.ps1
cd D:\buildagent\workspace\root\DevOps\Create_VM
D:
powershell powershell\createvms.ps1 %1 %2