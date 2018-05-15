<#
.Synopsis
   This function is designed to setup user accounts in Active Directory as well as associated mailboxes in Office 365.
.DESCRIPTION
   CSV Format is as follows:

   FirstName,LastName,EmploymentStatus,Office,Username,EmailEnabled,Manager,Title,Email,Country,PostalCode,State,City,Address

   If an established office (SF, BOS) is provided, then 'Country,PostalCode,State,City,Address' will be populated automatically.

   Username is optional.  If left blank the following format will be used: first letter FirstName + LastName

   Email is optional.  If left blank it will be populated based on the username + domain

   Title, Country, PostalCode, State, City, and Address are all optional.


   ---------------
   Accepted Values
   ---------------
   
   The following parameters are configured to accept only the specifcied values as input.


   EmploymentStatus
     
     FTE, Contractor, Vendor


   Office
     
     SF, BOS, Remote


   EmailEnabled

     $true, $false
.EXAMPLE
   new-CompanyUser -CSVlocation C:\new-users.csv
.EXAMPLE
   new-CompanyUser -FirstName Andrew -LastName Smith -EmploymentStatus FTE -Office SF -EmailEnabled $true -Manager "Jane Smith" -Title "Software Engineer"
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
function new-CompanyUser {
  [CmdletBinding(DefaultParameterSetName="Solo")]
  param (
    [Parameter(Mandatory=$true,ParameterSetName = "Solo")]
    [string]$FirstName,
    [Parameter(Mandatory=$true,ParameterSetName = "Solo")]
    [string]$LastName,
    [Parameter(Mandatory=$true,ParameterSetName = "Solo")]
    [ValidateSet("FTE","Contractor","Vendor")]
    [string]$EmploymentStatus,
    [Parameter(Mandatory=$true,ParameterSetName = "Solo")]
    [ValidateSet("SF","BOS","Remote")]
    [string]$Office,
    [Parameter(ParameterSetName = "Solo")]
    [string]$Username,
    [Parameter(Mandatory=$true,ParameterSetName = "Solo")]
    [bool]$EmailEnabled,
    [Parameter(Mandatory=$true,ParameterSetName = "Solo")]
    [ValidateScript({try {
      if ($_ -match "[\s]") {
        # Handles spaces in name
		$_=((Get-ADUser -Filter {Displayname -eq $_}).samaccountname).ToLower()
	  }
      Get-ADUser $_
    } catch {return $false}})]
    [string]$Manager,
    [Parameter(ParameterSetName = "Solo")]
    [string]$Title,
    [Parameter(ParameterSetName = "Solo")]
    [string]$Email,
    [Parameter(ParameterSetName = "Solo")]
    [string]$Role,
    [Parameter(Mandatory=$true,ParameterSetName = "CSV")]
    [string]$CSVlocation
  )

  switch ($PSCmdlet.ParameterSetName) {
    "Solo" {
      switch ($Office) {
        "SF" {
          $Path = "OU=SFO,OU=Users,OU=Company,DC=corp,DC=company,DC=com"
          $country = "US"
          $postalCode = ""
          $state = "CA"
          $city = "San Francisco"
          $addr = ""
        } "BOS" {
          $Path = "OU=BOS,OU=Users,OU=Company,DC=corp,DC=company,DC=com"
          $country = "US"
          $postalCode = ""
          $state = "MA"
          $city = "Boston"
          $addr = ""
        } "Remote" {
          $Path = "OU=Remote,OU=Users,OU=Company,DC=corp,DC=company,DC=com"
        }
      }

      $displayname = $firstName + " " + $lastName

      # Select Username, verify that it is unique
      if (!($username)) {
        $username = "$($firstname.ToLower().Chars(0))" + "$($lastName.ToLower())"
      }
      $notUniqueUser = try {Get-ADUser $username} catch {$false}
      if ($notUniqueUser) {
      Throw "Username is not unique, please specify a unique username."
      }

      $UPN = $Username + "@company.com"
      if (!($Email)) {
        # Default Email Address
        $Email = $UPN
      }

      # Handle spaces in Manager name
      if ($Manager -match "[\s]") {
		$Manager = ((Get-ADUser -Filter {Displayname -eq $Manager}).samaccountname).ToLower()
	  }

      # Department from Manager
      $department = Get-ADUser $Manager -Properties department |
        select -ExpandProperty department
      
      # Audit information
      $admin = whoami
      $date = Get-Date
      $info = "User created by $admin on $date"

      # Temp Password
      $pass = read-host "Enter a temporary password" -AsSecureString

      $params = @{
        enabled = $true
        accountpassword = $pass
        ChangePasswordAtLogon = $true
        GivenName = "$FirstName"
        Surname = "$LastName"
        DisplayName = "$displayname"
        Name = "$displayname"
        EmailAddress = "$Email"
        UserPrincipalName = "$UPN"
        SamAccountName = "$Username"
        StreetAddress = "$addr"
        City = "$city"
        State = "$state"
        PostalCode = "$postalCode"
        Country = "$country"
        Department = "$department"
        Manager = "$Manager"
        Office = "$Office"
        Title = "$Title"
        Path = "$Path"
      }

      # Create and Configure Acct
      New-ADUser @params
      Set-ADUser $Username -Replace @{info="$info"} | Out-Null
      Get-ADUser "$Username"

      # Add FTE to group, set attribute
      if ($EmploymentStatus -eq "FTE"){
        Add-ADGroupMember -Identity "Company Employee" -Members $Username | Out-Null
        Set-ADUser -Identity $Username -Company "Company" -Description "Company Employee" | Out-Null
      }

      # Setup Exchange Online
      if ($EmailEnabled -eq $true) {
        Write-Host "Waiting for replication"
        Start-Sleep 5
        $remoteEmail = $Username + "@company.mail.onmicrosoft.com"
        
        $params = @{
          Identity = "$Username"
          Alias = "$Username"
          RemoteRoutingAddress = "$remoteEmail"
        }
        
        switch ($EmploymentStatus) {
          "FTE" {
            Enable-RemoteMailbox @params | Out-Null
          } default {
            Enable-RemoteMailbox @params -PrimarySMTPAddress $UPN | Out-Null
          }
        }
        #set-mailbox -identity $UPN -retentionpolicy "1 Year Hold" -LitigationHoldEnabled $true
      }
    }

    "CSV" {
      $import = import-csv $csvlocation
      # Temp Password
      $pass = read-host "Enter a temporary password" -AsSecureString
      
      foreach ($newuser in $import) {
        if ($newuser.office -like "SF*" -or $newuser.office -like "San Fran*") {
          $Path = "OU=SFO,OU=Users,OU=Company,DC=corp,DC=company,DC=com"
          $newuser.Office = "SF"
          $newuser.Country = "US"
          $newuser.PostalCode = ""
          $newuser.State = "CA"
          $newuser.City = "San Francisco"
          $newuser.Address = ""
        } elseif ($newuser.office -like "BOS*") {
          $Path = "OU=BOS,OU=Users,OU=Company,DC=corp,DC=company,DC=com"
          $newuser.Office = "BOS"
          $newuser.Country = "US"
          $newuser.PostalCode = ""
          $newuser.State = "MA"
          $newuser.City = "Boston"
          $newuser.Address = ""
        } elseif ($newuser.office -like "Remote*") {
          $Path = "OU=Remote,OU=Users,OU=Company,DC=corp,DC=company,DC=com"
          $newuser.Office = "Remote"
        }

        $displayname = $newuser.FirstName + " " + $newuser.LastName

        # Select Username, verify that it is unique
        if (!($newuser.Username)) {
          $newuser.Username = "$($newuser.FirstName.ToLower().Chars(0))" +
            "$($newuser.LastName.ToLower())"
        }
        $notUniqueUser = try {Get-ADUser $newuser.Username} catch {$false}
        if ($notUniqueUser) {
          Write-Error -Message "Username is not unique for $displayname, please specify a unique username."
          Break
        }

        $UPN = $newuser.Username + "@company.com"

        if (!($newuser.Email)) {
          # Default Email Address
          $newuser.Email = $UPN
        }


        $Mgr = "$($newuser.Manager)"
        # Handle spaces in Manager name
        if ($Mgr -match "[\s]") {
		  $Mgr = ((Get-ADUser -Filter {Displayname -eq $Mgr}).samaccountname).ToLower()
	    }
        # Verify that manager exists
        try {
          Get-ADUser $Mgr | Out-Null
        } catch {
          Write-Error -Message "The manager $Mgr was not found while attempting to create a user account for $displayname, please specify a valid manager."
          Break
        }

        # Department from Manager
        $department = Get-ADUser $Mgr -Properties department |
          select -ExpandProperty department

        # Audit information
        $admin = whoami
        $date = Get-Date
        $info = "User created by $admin on $date"

        $params = @{
          enabled = $true
          accountpassword = $pass
          ChangePasswordAtLogon = $true
          GivenName = "$($newuser.FirstName)"
          Surname = "$($newuser.LastName)"
          DisplayName = "$displayname"
          Name = "$displayname"
          EmailAddress = "$($newuser.Email)"
          UserPrincipalName = "$UPN"
          SamAccountName = "$($newuser.Username)"
          StreetAddress = "$($newuser.Address)"
          City = "$($newuser.City)"
          State = "$($newuser.State)"
          PostalCode = "$($newuser.PostalCode)"
          Country = "$($newuser.Country)"
          Department = "$department"
          Manager = "$Mgr"
          Office = "$($newuser.Office)"
          Title = "$($newuser.Title)"
          Path = "$Path"
        }

        # Create and configure acct
        New-ADUser @params
        Set-ADUser "$($newuser.Username)" -Replace @{info="$info"} | Out-Null
        Get-ADUser "$($newuser.Username)"

        # Add FTE to group, set attribute
        if ($newuser.EmploymentStatus -eq "FTE"){
          Add-ADGroupMember -Identity "Company Employee" -Members $newuser.Username | Out-Null
          Set-ADUser -Identity "$($newuser.Username)" -Company "Company" -Description "Company Employee" |
            Out-Null
        }

        # Setup Exchange Online
        $mailstatus = "$($newuser.EmailEnabled)"
        if ($mailstatus -eq "true" -or $mailstatus -eq "yes") {
          Write-Host "Waiting for replication"
          Start-Sleep 5
          $remoteEmail = $newuser.Username + "@company.mail.onmicrosoft.com"

          $params = @{
            Identity = "$($newuser.Username)"
            Alias = "$($newuser.Username)"
            RemoteRoutingAddress = "$remoteEmail"
          }

          switch ($newuser.EmploymentStatus) {
            "FTE" {
              Enable-RemoteMailbox @params | Out-Null
            } default { 
              Enable-RemoteMailbox @params -PrimarySMTPAddress $UPN | Out-Null
            }
          }
          #set-mailbox -identity $UPN -retentionpolicy "1 Year Hold" -LitigationHoldEnabled $true
        }
      }
    }
  }
}
