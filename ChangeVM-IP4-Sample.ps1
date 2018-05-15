#######################################################################
#
# Purpose:  Run script through VMware Tools
# Author:   Willis Gronwall
# v.2  -    03/24/2015
#
# Instruction: changeVM-IP -VISRV <viserver> -CSVBUILD <csvfilename> -VMAdminUser <local admin>
# 
# Required CSV Fields
# Name,DestName,DestIP,DestMask,DestGW,DNS1,DNS2
#
# Blog post - https://www.taos.com/modifying-vms-in-bulk-with-invoke-vmscript/
#
########################################################################

<#
.Synopsis
   This function is designed enable configuration of VMs which do not have a working network connection.
.DESCRIPTION
   The follow blog post provides a detailed description:
   https://www.taos.com/modifying-vms-in-bulk-with-invoke-vmscript/

   Required CSV Fields:
   Name,DestName,DestIP,DestMask,DestGW,DNS1,DNS2
.EXAMPLE
   changeVM-IP -VISRV <viserver> -CSVBUILD <csvfilename> -VMAdminUser <local admin>
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
function changeVM-IP {
  param (
    [Parameter(Mandatory=$True)]
    [string]
    $VISRV,
    [Parameter(Mandatory=$True)]
    [string]
    $CSVBUILD,
    $VMAdminUser,
    $vSphereUser
  )

  # If a different user is specified
  if ($vSphereUser) {
    $cred = Get-Credential $vSphereUser
    Connect-VIServer $VISRV -Credentials $cred
  } Else {
    Connect-VIServer $VISRV
  }
  
  $VMs = Import-Csv $CSVBUILD
  # Creds used to run the script
  $vmCred = Get-Credential $VMAdminUser

  <#
  This script throws an error when attempting to collect the script output from the host after running successfully. (Failed to Authenticate to the Guest OS)
    This is because the cached creds used are no longer valid after the domain/name change. 
      Not sure if there is a good workaround for that but you can run it a second time without incident and you will see the script output.
  DNS will not work when the NIC is in a disconnected state as it requires IP to be enabled.
  This is designed to be PowerShell v2 compatible - would be easier in v3 or v4 (Set-NetAdapter, Remove-Computer, Add-Computer, etc. have limited/no functionality in v2)
  Scans for VMware adapters based on ServiceName; if more than one is found the first is selected
  #>

  # Base script used in loop below
  $baseScript = @'
    $wmiNet = Get-WmiObject Win32_NetworkAdapterConfiguration | ? {$_.ServiceName -match "vmx.*|E1.*"}
    if ($wmiNet.Count -ge 2) {
      $wmiNet = $wmiNet[0]
    }
    $wmiNet.EnableStatic("$($VM.DestIP)","$($VM.DestMask)")
    $wmiNet.SetGateways("$($VM.DestGW)", 1)
    $wmiNet.SetDNSServerSearchOrder(@("$($VM.DNS1)","$($VM.DNS2)"))
    $wmiName = Get-WmiObject Win32_ComputerSystem
    $wmiName.UnjoinDomainOrWorkgroup()
    sleep 1
    $wmiName.Rename("$VM.DestName")
    ipconfig /all
    shutdown -r -t 30
'@

  foreach ($VM in $VMs) {
    $VMObject = Get-VM -Name "$($VM.Name)"
    # Modifies base script
    $script = $baseScript.Replace('$MACAddr',$MACAddr).Replace('$($VM.DestIP)',$VM.DestIP).Replace('$($VM.DestMask)',$VM.DestMask).Replace('$($VM.DestGW)',$VM.DestGW).Replace('$($VM.DNS1)',$VM.DNS1).Replace('$($VM.DNS2)',$VM.DNS2).Replace('$VM.DestName',$VM.DestName)
    $params = @{
      Server = $VISRV
      VM = $VMObject
      ScriptText = $script
      GuestCredential = $vmCred
      ScriptType = "PowerShell"
      Confirm = $false
    }
    Invoke-VMScript @params
  }
}
