#######################################################################
#
# Purpose:  Collect meeting information via Exchange API, notify facilities of room division maintenance
# Author:   Willis Gronwall
# v.1  -    09/03/2015
#
# Use primary SMTP Address of the room
# Requires FullAccess with InheritanceType All
#
########################################################################

Start-Transcript -Path "C:\scripts\Booking-Notification.txt"

# Setup Exchange API
Add-Type -Path "C:\Program Files\Microsoft\Exchange\Web Services\2.2\Microsoft.Exchange.WebServices.dll"
$ExchangeVersion = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2010_SP2
$service = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService($ExchangeVersion)
$uri=[system.URI] "https://webmail.company.com/ews/exchange.asmx"
$service.Url = $uri

# Grab credentials via Secret Server API
$secretId = 100
$secretAPI = 'https://secret-server.company.com/SecretServer/winauthwebservices/sswinauthwebservice.asmx'
$ws = New-WebServiceProxy -uri $secretAPI -UseDefaultCredential 
$userName = ($ws.GetSecret($secretId, $false, $null)).Secret.Items[1].Value
$securePassword = ($ws.GetSecret($secretId, $false, $null)).Secret.Items[2].Value | ConvertTo-SecureString -AsPlainText -Force

# Configure Creds
$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $userName,$securePassword
$service.Credentials = $creds.GetNetworkCredential()

$meetings1 = @()
$meetings2 = @()

# Target room1
$mailbox = "room1@company.com"
$folderid = new-object Microsoft.Exchange.WebServices.Data.FolderId([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Calendar,$mailbox)
$Calendar = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($service,$folderid)

$moreItems = $true
$view = New-Object Microsoft.Exchange.WebServices.Data.ItemView(500, 0)

# Configure search filter, target next 24 hours
$searchFilter = $Null
$filters = @()
$filters += New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsGreaterThanOrEqualTo([Microsoft.Exchange.WebServices.Data.AppointmentSchema]::Start, (Get-Date))
$filters += New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsLessThanOrEqualTo([Microsoft.Exchange.WebServices.Data.AppointmentSchema]::Start, (Get-Date).AddDays(1))
$searchFilter = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+SearchFilterCollection([Microsoft.Exchange.WebServices.Data.LogicalOperator]::And)
foreach ($filter in $filters) {
  $searchFilter.Add($filter)
}

# Collect room1 meetings
while ($moreItems) {
  $results1 = $Calendar.FindItems($searchFilter, $view)
  $moreItems = $results1.MoreAvailable
  $view.Offset = $results1.NextPageOffset 
  foreach ($meeting in $results1) {
    $meetings1 += @($meeting)
  }
}

# Target room2
$mailbox = "room2@company.com"
$folderid = new-object Microsoft.Exchange.WebServices.Data.FolderId([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Calendar,$mailbox)
$Calendar = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($service,$folderid)

$moreItems = $true
$view = New-Object Microsoft.Exchange.WebServices.Data.ItemView(500, 0)

# Collect room2 meetings
while ($moreItems) {
  $results2 = $Calendar.FindItems($searchFilter, $view)
  $moreItems = $results2.MoreAvailable
  $view.Offset = $results2.NextPageOffset
  foreach ($meeting in $results2) {
    $meetings2 += @($meeting)
  }
}

# Find overlap, send email notification
foreach ($appt1 in $meetings1) {
  $meetings2 | ForEach-Object {
    if ($_.Start -eq $appt1.Start -and $_.Subject -eq $appt1.Subject) {
      $mtg1 = $appt1 | select start,end,subject,location | fl | Out-String
      $mtg2 = $_ | select start,end,subject,location | fl | Out-String
      $email_sender = "Room_Notification@company.com"
      $email_recipient = "maintenance@company.com"
      $email_subject = "Booking Notification"
      $email_body = "Room1 and Room2 have been booked together today.  The room division requires maintenance.`r"
      $email_body += "$mtg1"
      $email_body += "$mtg2"   
      $email_body += "- IT Team" + ".`r"
      Send-MailMessage -To $email_recipient -From $email_sender -Subject $email_subject -Body $email_body -SmtpServer smtp.company.com
    }
  }
}

Stop-Transcript
