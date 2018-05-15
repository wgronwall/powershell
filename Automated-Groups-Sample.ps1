#######################################################################
#
# Purpose:  Automated distribution group membership
# Author:   Willis Gronwall
# v.1  -    06/23/2015
#
# This script will compare membership and add/remove users individually based on the specified logic
# A computational improvement over dynamic DLs which process against every message
#
########################################################################

$transcriptPath = "C:\scripts\Automated-DLs.log"
Start-Transcript -Path $transcriptPath

# Select a DC to work on, helping to avoid replication delays
$dc = Get-ADDomainController

function create-Group {
  param (
    [string] $groupName = $null,
    [string] $dc = $null
  )
  if ( ! (Get-DistributionGroup $groupName -ea silentlycontinue)) {
    $params = @{
      "Name" = $groupName;
      "OrganizationalUnit" = "company.com/Company/Groups/Exchange/Automated";
      "DomainController" = $dc.HostName;
    }
    New-DistributionGroup @params
  }
}

function update-Membership {
  param (
    [string] $groupName = $null,
    $members = $null
  )
  create-Group -groupName $groupName -dc $dc.HostName
  $membersDN = $members | select -ExpandProperty DistinguishedName
  $currentMembersDN = Get-DistributionGroupMember $groupName -ResultSize unlimited | select -ExpandProperty DistinguishedName
  if ($currentMembersDN -eq $null) {
    # No current members, simply add the new ones
    foreach ($userDN in $membersDN) {
      Add-DistributionGroupMember -Identity $groupName -Member $userDN -DomainController "$($dc.HostName)" -Confirm:$false
    }
  }
  # Compare current and proposed membership, only addng and/or removing the delta.
  try {
    $comparison = Compare-Object $membersDN $currentMembersDN
  } catch {
    Write-Error "Comparison Failed, $groupName may not have any existing members.  Adding new memebers and proceeding..."
    # If there are no current members, the above logic already added the new memebers.
  }
  $additions = $comparison | ? {$_.SideIndicator -eq "<="} | select -ExpandProperty InputObject
  $removals = $comparison | ? {$_.SideIndicator -eq "=>"} | select -ExpandProperty InputObject
  # Add/Remove users from group
  foreach ($userDN in $additions) {
    Add-DistributionGroupMember -Identity $groupName -Member $userDN -DomainController "$($dc.HostName)" -Confirm:$false
  }
  foreach ($userDN in $removals) {
    Remove-DistributionGroupMember -Identity $groupName -Member $userDN -DomainController "$($dc.HostName)" -Confirm:$false
  }
}

# Function to generate org list for a given manager
function get-IndirectReport {
  param (
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [ValidateScript({ Get-ADUser $_ })]
    $Identity
  )
  $managerDN = Get-ADUser $Identity | select -ExpandProperty distinguishedname
  Get-ADUser -Filter * -ResultSetSize $null -Properties Manager | ? {$_.Manager -eq $managerDN} | 
    ForEach-Object {
      $_
      get-IndirectReport -Identity $_
    }
}

$users = Get-ADUser -Filter * -ResultSetSize $null -Properties canonicalName,
  UserPrincipalName,EmailAddress,Mail,Manager,Department,Description,employeetype | 
    ? {$_.Enabled -eq $true -and $_.canonicalName -notlike "company.com/Users/*" -and $_.canonicalName -like "*user*"}

#All FTEs Globally
$FTE_Users = $users | ? {$_.employeetype -eq "Employee"}
update-Membership "Company Employees" $FTE_Users

#All Contractors Globally
$Contractors = $users | ? {$_.employeetype -eq "Contractor"}
update-Membership "Company Contractors" $Contractors

#CSV format: Name    (Could just be a txt file)
$officesfile = "c:\scripts\automated-DL-offices.csv"
$officesCSV = Import-Csv $officesfile

#FTEs and Contractors by Office.  Offices chosen by CSV input file.
foreach ($office in $officesCSV) {
  $localFTEs = $FTE_Users | ? {$_.Office -eq "$($office.Name)" -or $_.CanonicalName -like "company.com/Company/Users/$($office.Name)*"}
  $localContractors = $Contractors | ? {$_.Office -eq "$($office.Name)" -or $_.CanonicalName -like "company.com/Company/Users/$($office.Name)*"}
  update-Membership "$($office.Name) Employees" $localFTEs
  update-Membership "$($office.Name) Contractors" $localContractors
}

#CSV format: DeptName,DLName
$deptsfile = "c:\scripts\automated-DL-dept.csv"
$deptCSV = Import-CSV $deptsfile

#Users based on Department.  Departments chosen by CSV input file.
foreach ($dept in $deptCSV) {
  $deptUsers = $users | ? {$_.Department -eq "$($dept.DeptName)"}
  update-Membership "$($dept.DLName)" $deptUsers
}

#CSV format: MgrName,DLName
$Mgrfile = "c:\scripts\automated-DL-mgr.csv"
$MgrCSV = Import-CSV $Mgrfile

#Direct and indirect reports (org lists) based on Manager.  Managers chosen by CSV input file.
foreach ($Mgr in $MgrCSV) {
  $reports = get-IndirectReport -Identity "$($Mgr.MgrName)"
  #Add the Manager to the object
  $reports += Get-ADUser "$($Mgr.MgrName)"
  update-Membership "$($Mgr.DLName)" $reports
}

Stop-Transcript
