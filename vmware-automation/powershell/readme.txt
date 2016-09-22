
readme.txt


Project Brief : 


The powersheel script Will take the consolidated vm provisioning parameters from CSV file and then provision them.

Included Files:


Prerequisite --

          vmware powercli 5.8 Relese2 should be installed in the windows machine.

          This has been tested in windows 7 machine with vmware powercli 5.8 Relese2 installed.

     How To Run createvm.ps1:

     To run the script - you need to initialize the vmware power cli environment. Open a command prompt window and go to

     cd C:\Program Files (x86)\VMware\Infrastructure\vSphere PowerCLI\Scripts>

     Then run C:\Program Files (x86)\VMware\Infrastructure\vSphere PowerCLI\Scripts> .\Initialize-PowerCLIEnvironment.ps1

     Note : If you get any security issue to run the script , run 
     Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

     

     Once the environment is successfully initialized , you will see the output as follows:

     PS C:\Program Files (x86)\VMware\Infrastructure\vSphere PowerCLI\Scripts> .\Init
     ialize-PowerCLIEnvironment.ps1
          Welcome to the VMware vSphere PowerCLI!

          Log in to a vCenter Server or ESX host:              Connect-VIServer
          To find out what commands are available, type:       Get-VICommand
          To show searchable help for all PowerCLI commands:   Get-PowerCLIHelp
          Once you've connected, display all virtual machines: Get-VM
          If you need more help, visit the PowerCLI community: Get-PowerCLICommunity

           Copyright (C) 1998-2013 VMware, Inc. All rights reserved.


Then you will be set to run the script : Run it as follows:

          cd "directory where script resides"

          .\createvms.ps1  "full path of the INI input file"
  "full path of the CSV input file"

That should create the VM's.

Note -- currently we are creating the VMs from dev-rhel5-test & devop-rhel6.5-test template -- 

This template has vmware tools installed and also has a custom script embedded in the template. We call that script from powercli script to provision the networking etc.




