<#
.Synopsis
   This function is designed to automate the virtual machine deployment process, including IP allocations.
.DESCRIPTION
   This must be run in PowerCLI with a vcenter connection (Connect-VIServer)

   ### TO DO ###
   1. Expand on help section
   2. Add a separate parameter set for more manual configs (specifying datastore, etc.)
.EXAMPLE
   deploy-NewVM -VMname <VMname> -OperatingSystem "Windows Server 2012 R2" -NumCPU 2 -MemoryGB 4 -DiskGB 100 -Cluster <ClusterName> -Production?:$true -Network <PortgroupName> -ticket <TicketNumber>
.EXAMPLE
   "test-vm1","test-vm2","test-vm3","test-vm4" | % {
     deploy-NewVM -VMname $_ -OperatingSystem "Windows Server 2012 R2" -NumCPU 2 -MemoryGB 4 -DiskGB 100 -Cluster <ClusterName> -Production?:$true -Network <PortgroupName> -ticket <TicketNumber>
   }
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
function deploy-NewVM {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory=$true)]
    [string]$VMname,
    [Parameter(Mandatory=$true)]
    [ValidateSet("Windows Server 2016","Windows Server 2012 R2","Linux","Mac")]
    $OperatingSystem = "Windows Server 2016",
    [Parameter(Mandatory=$true)]
    [int]$NumCPU,
    [Parameter(Mandatory=$true)]
    [int]$MemoryGB,
    [Parameter(Mandatory=$true)]
    [int] $DiskGB,
    [Parameter(Mandatory=$true)]
    [ValidateScript({
      try {
        Get-Cluster $_
      } catch {return $false}
    })]
    $Cluster,
    [Parameter(Mandatory=$true)]
    [bool]$Production?,
    $ticket,
    $IpamServer = "ipam-server-name", # Edit IPAM Server Hostname
    $DhcpServer = "dhcp-server-name", # Edit DHCP Server Hostname
    $folder = "VM-Folder", # Edit Folder
    $domain = "company.local" # Edit Domain
  )
  # Dynamic Parameter Validation - https://blogs.technet.microsoft.com/pstips/2014/06/09/dynamic-validateset-in-a-dynamic-parameter/
  # Note that the placement of the network parameter when running the function sometimes matters
  # Putting it toward the front tends to help if there are issues
  DynamicParam {
    $ParameterName = 'Network'
    $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
    $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
    
    $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
    $ParameterAttribute.Mandatory = $true

    $AttributeCollection.Add($ParameterAttribute)

    $arrSet = Get-Cluster $Cluster | Get-View | select -ExpandProperty network | % {Get-view $_} | select -ExpandProperty name
    $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($arrSet)

    $AttributeCollection.Add($ValidateSetAttribute)

    $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
    $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
    return $RuntimeParameterDictionary
  }

  process {

    # Select a template to use, edit with organization specific clusters and templates
    $template=''
    switch ($OperatingSystem) {
      "Windows Server 2016" {
        switch ($Cluster) {
          "Cluster1" {
            $template = "tmpl-win-srv-2016"
          }
          default {
            Write-Warning "No template found within cluster, using default template"
            $template = "tmpl-win-srv-2016"
          }
        }
      }
      "Windows Server 2012 R2" {
        switch ($Cluster) {
          "Cluster1" {
            $template = "tmpl-win-srv-2012"
          }
          default {
            Write-Warning "No template found within cluster, using default template"
            $template = "tmpl-win-srv-2012"
          }
        }
      }
      "Linux" {
        switch ($Cluster) {
          "Cluster1" {
            $template = "tmpl-centos-7"
          }
          default {
            Write-Warning "No template found within cluster, using default template"
            $template = "tmpl-centos-7"
          }
        }
      }
      "Mac" {
        switch ($Cluster) {
          "Cluster1" {
            $template = "tmpl-macos-sierra"
          }
          default {
            Write-Warning "No template found within cluster, using default template"
            $template = "tmpl-macos-sierra"
          }
        }
      }
    }
    $template = Get-Template $template
    
    # Select a datastore
    
    $datastore = ''
    $DSClusters = Get-Cluster $Cluster | Get-Datastore | Get-DatastoreCluster
    
    # If more than one datastore cluster is returned
    if ($DSClusters.count -gt 1) {
      switch ($Production?) {
        $true {
          # Prod
          $datastore = ($DSClusters | ? {$_.Name -notlike "*dev*"} | 
            Sort-Object -Property FreeSpaceGB -Descending)[0] | Get-Datastore | 
              Sort-Object -Property FreeSpaceGB -Descending | select -First 1
        }
        $false {
          # Dev
          $datastore = ($DSClusters | ? {$_.Name -like "*dev*"} | 
            Sort-Object -Property FreeSpaceGB -Descending)[0] | Get-Datastore | 
              Sort-Object -Property FreeSpaceGB -Descending | select -First 1
        } default {
          # Prod
          $datastore = ($DSClusters | ? {$_.Name -notlike "*dev*"} | 
            Sort-Object -Property FreeSpaceGB -Descending)[0] | Get-Datastore | 
              Sort-Object -Property FreeSpaceGB -Descending | select -First 1
        }
      }
    }
    
    elseif ($DSClusters) {
      # A single datastore cluster is returned
      $datastore = $DSClusters | Get-Datastore | Sort-Object -Property FreeSpaceGB -Descending | select -First 1
    }
    
    else {
      # No datastore cluster is returned
      $DSoptions = Get-Cluster $Cluster | Get-Datastore | ? {$_.Name -notmatch "local"}
      $vsan = $DSoptions | ? {$_.name -like "*vsan*"}
      $msa = $DSoptions | ? {$_.name -like "*msa*"}
      
      if ($vsan) {
        # Select vsan over msa
        $datastore = ($vsan | Sort-Object -Property FreeSpaceGB -Descending)[0]
      } elseif ($msa) {
        $datastore = ($msa | Sort-Object -Property FreeSpaceGB -Descending)[0]
      }
      else {
        # No vsan or msa
        $datastore = ($DSoptions | Sort-Object -Property FreeSpaceGB -Descending)[0]
      }
    }
    
    # Select a cluster
    $clusterObject = Get-Cluster $Cluster
    
    # Select a folder location, edit with organization specific folder
    $location = Get-Folder $folder
    
    # Network Configuration
    
    # Get IP from Microsoft IPAM server
    # Assumes the use of site and vlan attributes
    $portgroup = Get-VDPortgroup $PSBoundParameters.network
    [string]$vlan = Get-VDPortgroup $PSBoundParameters.network | 
      select -ExpandProperty VlanConfiguration | select -ExpandProperty VlanId
    $site = $Cluster.Split("-")[0] # edit as needed
    $ipamRange = Get-IpamRange -CimSession $IpamServer -AddressFamily IPv4 | 
      ? {$_.CustomFields.vlan -eq "$vlan" -and $_.CustomFields.Site -eq "$site"}
    $gateway = ([regex]"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").Match(($ipamRange | select -ExpandProperty gateway)).value
    # An IpamRange object is required in order to use Find-IpamFreeAddress
    # This means we either need to share a range with DHCP for statics, or create a separate range for statics.
    # ManagedByService and ServiceInstace attributes on the address should match that of the range
      # If these do not align, Find-IpamFreeAddress will return the unmatched "In-Use" addresses.
      # Here, we are importing the attributes directly from the range via pipeline.
    $availableIP = $ipamRange | Find-IpamFreeAddress -CimSession $IpamServer -TestReachability -NumAddress 10 | 
      ? {$_.PingStatus -eq "NoReply" -and $_.DnsRecordStatus -eq "NotFound"} | select -First 1
    
    # Check for DHCP lease
    $lease = Get-DhcpServerv4Lease -ComputerName $DhcpServer -IPAddress $availableIP.IpAddress.IPAddressToString -ErrorAction SilentlyContinue
    if (!($lease)) {
      $subnetNumber = $ipamRange | Get-IpamSubnet | select -ExpandProperty SubnetNumber
      $dhcpExclusionParams = @{
        ComputerName = "$DhcpServer"
        ScopeId = $subnetNumber
        StartRange = "$($availableIP.IpAddress.IPAddressToString)"
        EndRange = "$($availableIP.IpAddress.IPAddressToString)"
      }
      # Check for existing DHCP exclusion
      $exclusion = Get-DhcpServerv4ExclusionRange -ComputerName "$DhcpServer" -ScopeId $subnetNumber | 
        ? {$_.StartRange -eq "$($availableIP.IpAddress.IPAddressToString)" -and $_.EndRange -eq "$($availableIP.IpAddress.IPAddressToString)"}
      if (!($exclusion)) {
        # Nothing found, continue
      } else {
        # Exclusion found, exit script
        Throw "Existing DHCP exclusion detected for IP $($availableIP.IpAddress.IPAddressToString).  Exiting."
      }
    } else {
      # Lease found, exit script
      Throw "Conflicting DHCP lease detected for IP $($availableIP.IpAddress.IPAddressToString).  Exiting."
    }
    
    # Check for DNS Records
    $forward = Resolve-DnsName -Name "$($VMname).$domain" -DnsOnly -ErrorAction SilentlyContinue
    $reverse = Resolve-DnsName -Name "$($availableIP.IpAddress.IPAddressToString)" -DnsOnly -ErrorAction SilentlyContinue
    if ($forward -or $reverse) {
      # DNS records found, exit script
      Throw "Existing forward and/or reverse DNS records exist for $($VMname).$domain, $($availableIP.IpAddress.IPAddressToString).  Exiting"
    } else {
      # Nothing found, continue
    }
    
    # Select VM customization spec, edit with organization specific specs
    $spec = ''
    $tempSpec = ''
    switch ($OperatingSystem) {
      "Windows Server 2016" {
        $spec = Get-OSCustomizationSpec "win-srv-2016-domain"
      }
      "Windows Server 2012 R2" {
        $spec = Get-OSCustomizationSpec "win-srv-2012-domain"
      }
      "Linux" {
        $spec = Get-OSCustomizationSpec "centos-7-spec"
      }
      "Mac" {
        $spec = Get-OSCustomizationSpec "macos-sierra-spec"
      }
    }
    # Generate non-persistent spec modeled after the parent
    $tempSpec = New-OSCustomizationSpec -Spec $spec -Type NonPersistent
    # Start modifying the temp spec
    $tempSpec = Set-OSCustomizationSpec $tempSpec -AutoLogonCount 0
    $networksettings = Get-OSCustomizationNicMapping -OSCustomizationSpec $tempSpec
    $networkParams = @{
      OSCustomizationNicMapping = $networksettings
      Dns = $ipamRange.DnsServers.IPAddressToString
      IpMode = "UseStatic"
      IpAddress = $availableIP.IpAddress.IPAddressToString
      SubnetMask = $ipamRange.SubnetMask.IPAddressToString
      DefaultGateway = "$gateway"
    }
    $networksettings = Set-OSCustomizationNicMapping @networkParams
    
    # New-VM splat
    $newVMparams = @{
      Name = $VMname
      ResourcePool = $clusterObject
      Template = $template
      Datastore = $datastore
      DiskStorageFormat = "Thin"
      Location = $location
      Notes = "$ticket"
    }
    
    # Set-VM splat
    $setVMparams = @{
      NumCpu = $NumCPU
      MemoryGB = $MemoryGB
      OSCustomizationSpec = $tempSpec
      Confirm = $false
    }
    
    # Create VM
    $vm = New-VM @newVMparams | Set-VM @setVMparams
    
    # Configure disk
    Get-HardDisk $vm | Set-HardDisk -CapacityGB $DiskGB -Confirm:$false
    
    # Set portgroup
    Get-VM $vm | Get-NetworkAdapter | Set-NetworkAdapter -Portgroup $portgroup -Confirm:$false
    
    # Start VM
    Start-VM $VM -Confirm:$false
    
    # Connect nic
    Get-VM $vm | Get-NetworkAdapter | Set-NetworkAdapter -Connected:$true -StartConnected:$true -Confirm:$false
    
    # Cleanup temp spec
    $tempSpec | Remove-OSCustomizationSpec -Confirm:$false
    
    # Add IP to IPAM
    $ipamAddrSettings = @{
      CimSession = "$IpamServer"
      IpAddress = "$($availableIP.IpAddress.IPAddressToString)"
      Description = "$VMname"
      DeviceName = "$VMname"
      ForwardLookupZone = "$domain"
      ReverseLookupZone = "10.in-addr.arpa" # Edit as needed
      AssignmentType = "Static"
      DeviceType = "VM"
    }
    $ipamRange | Add-IpamAddress @ipamAddrSettings
    
    # Add DHCP exclusion
    Add-DhcpServerv4ExclusionRange @dhcpExclusionParams
    
    # Create DNS Records
    Add-DnsServerResourceRecord -ZoneName "$domain" -A -Name $VMname -AllowUpdateAny -IPv4Address "$($availableIP.IpAddress.IPAddressToString)" -CreatePtr
  }
  
}

