<#
.Synopsis
   This function is designed to securely extract a copy of the NTDS.dit file.  The encryption processes using native powershell and requires no third party tooling to be installed on DCs.
.DESCRIPTION
   Once extracted, the file can be transfered to a node where the hashes will be processed and run through a password cracking utility.

   The purpose is to expose particularly weak passwords so that adjustments can be made to the custom password filter.

   Some requirements:
   1) Run this function using a domain admin account from an appropriately secured server
   2) Make sure you have a valid certificate for encryption, and that the public key for that cert is present in Cert:\LocalMachine\My\ on the target DC

.EXAMPLE
   encryptHashes -targetDC <hostname of DC> -thumbprint <thumbprint>
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
function encryptHashes {
  param(
    [Parameter(Mandatory=$true)]
    $targetDC,
    [Parameter(Mandatory=$true)]
    $thumbprint
  )

  # Establish a connection to the remote Domain Controller
  Invoke-Command -ComputerName $targetDC -ScriptBlock {

    # Select certs for encryption
    # We're only using one, but multiple decryption keys are possible
    # $Using:thumbprint - syntax used in order to access the parameter within Invoke-Command
    $validCerts = @(
      Get-ChildItem -Path Cert:\LocalMachine\My | ? {
        $_.NotBefore -lt (Get-Date) -and $_.NotAfter -gt (Get-Date) -and
        $_.Thumbprint -eq "$Using:thumbprint"
      }
    )
    # Verify cert
    if ($validCerts -eq $null) {
      throw "Certificate with thumbprint $Using:thumbprint not found in Cert:\LocalMachine\My\"
    }

    # Create prerequisite directories, also clear them of data.
    $workingdir = "C:\Windows\ntds-ifm"
    if (Test-Path $workingdir\raw) {
      Remove-Item -Path $workingdir\raw -Recurse -Force
    }
    New-Item -Path "$workingdir" -Name "raw" -ItemType Directory

    if (Test-Path $workingdir\zip) {
      Remove-Item -Path $workingdir\zip -Recurse -Force
    }
    New-Item -Path "$workingdir" -Name "zip" -ItemType Directory

    if (Test-Path $workingdir\encrypted) {
      Remove-Item -Path $workingdir\encrypted -Recurse -Force
    }
    New-Item -Path "$workingdir" -Name "encrypted" -ItemType Directory

    # Create IFM (Install From Media)
    ntdsutil "activate instance ntds" "ifm" "create full $workingdir\raw" q q

    # Create Zip file
    $inputDir = "$workingdir\raw"
    $fileName = "$("IFM-" + (Get-Date -Format yyyy-MM-ddThh-mm-ss))"
    Add-Type -AssemblyName "system.io.compression.filesystem"
    [io.compression.zipfile]::CreateFromDirectory($inputDir, "$workingdir\zip\$fileName.zip")

    # Delete raw files
    Remove-Item -Path $workingdir\raw -Recurse -Force

    ##### Begin Encryption #####

    try {
      # Create a new instance of AesCryptoServiceProvider.  It automatically generates a random Key and IV (Initialization Vector)
      $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider

      # Using .NET Streams, make a new, encrypted copy of the file.  This is a buffered approach that doesn't have to hold the
      # entire file in memory at any time, even if it is very large.
      $inputStream = New-Object System.IO.FileStream("$workingdir\zip\$fileName.zip", [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
      $outputStream = New-Object System.IO.FileStream("$workingdir\encrypted\$fileName-e.zip", [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)

      # .NET Streams use this "Decorator" pattern.  After obtaining the low-level stream (such as a FileStream or MemoryStream), you then wrap it
      # in one or more layers of higher-level streams, such as this CryptoStream.  CryptoStream transforms the data for us into an encrypted
      # form, and writes it to the underlying FileStream.
      $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($outputStream, $aes.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)

      # Now we perform our buffered read / write on the streams.  In this case, we'll read 256 bytes at a time, though you can use just about any size buffer you like.
      $buffer = New-Object byte[](256)

      # $inputStream.Read() returns the number of bytes that were read into the buffer, which can be anywhere from 0 to $buffer.Length.
      # As long as this return value is greater than zero, we write that many bytes to the CryptoStream (and from there, automatically to the output FileStream.)
      while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $cryptoStream.Write($buffer, 0, $read)
      }

      # Generate a collection of copies of the AES key and IV, each protected with one of the RSA certificates.
      $encryptedKeys = New-Object object[]($validCerts.Count)

      for ($i = 0; $i -lt $validCerts.Count; $i++) {
        $encryptedKeys[$i] = New-Object psobject -Property @{
          Thumbprint = $validCerts[$i].Thumbprint
          # To encrypt the key and IV using RSA, we use the PublicKey.Key.Encrypt() method on the certificate.
          Key = $validCerts[$i].PublicKey.Key.Encrypt($aes.Key, $true)
          IV  = $validCerts[$i].PublicKey.Key.Encrypt($aes.IV, $true)
        }
      }

      # Save all of our protected copies of the AES key/IV to a file.
      $outputObject = New-Object psobject -Property @{
        Keys    = $encryptedKeys
      }

      $keyXml = "$workingdir\encrypted\$fileName-e.txt"
      $outputObject | Export-Clixml -Path $keyXml
    }
    finally {
      # Cleanup consists of calling Dispose() on the various streams and other .NET objects which implement the IDisposable interface.
      # These objects automatically take care of clearing out sensitive data like encryption keys from memory when you call Dispose().
      if ($cryptoStream -ne $null) {
        $cryptoStream.Dispose()
        $cryptoStream = $null
      }

      if ($outputStream -ne $null) {
        $outputStream.Dispose()
        $outputStream = $null
      }

      if ($inputStream -ne $null) {
        $inputStream.Dispose()
        $inputStream = $null
      }

      if ($aes -ne $null) {
        $aes.Dispose()
        $aes = $null
      }
    }

    # Delete Zip
    Remove-Item -Path $workingdir\zip -Recurse -Force

  # End of script block
  }

  # Copy encrypted hashes from remote Domain Controller
  $remote1 = New-PSSession -ComputerName $targetDC
  Copy-Item -FromSession $remote1 -Path "C:\Windows\ntds-ifm\encrypted\" -Destination C:\temp\ -Recurse
}




<#
.Synopsis
   This function is designed to decrypt the zip file generated by the encryptHashes function.
.DESCRIPTION
   Some requirements:
   1) A server appropriately secured to be working on AD hashes
   2) The encrypted document and key file from encryptHashes
   3) A certificate (with private key) that matches the thumbprint used for encryption and stored in Cert:\CurrenUser\My\

.EXAMPLE
   decryptHashes -keypath "C:\temp\encrypted\key.txt" -encryptedfilepath "C:\temp\encrypted\hashes-e.zip" -outfile "C:\temp\encrypted\hashes.zip"
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
function decryptHashes {
  param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({
      Test-Path $_ -PathType leaf
    })]
    [string]$keypath,
    [Parameter(Mandatory=$true)]
    [ValidateScript({
      Test-Path $_ -PathType leaf
    })]
    [string]$encryptedfilepath,
    [Parameter(Mandatory=$true)]
    [string]$outfile
  )
  # To read the data back in later, you need one of the certificates that was used to encrypt the AES key (with that certificate's private key).
  # As with the encryption portion of the code, we'll use try/finally to make sure that the cleanup code executes.

  # Make sure the Cert is imported into Cert:\CurrentUser\My and that it matches the thumbprint from the keys file
  $validCerts = @(
    Get-ChildItem -Path Cert:\CurrentUser\My | ? {
      $_.PrivateKey -is [System.Security.Cryptography.RSACryptoServiceProvider] -and
      $_.NotBefore -lt (Get-Date) -and $_.NotAfter -gt (Get-Date)
    }
  )

  try {
    $object = Import-Clixml -Path $keypath

    # Check our data to make sure this certificate was used to encrypt a copy of the AES key, and that we can decrypt it
    $found = $false
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider

    foreach ($targetCertificate in $validCerts) {
      foreach ($encryptedKey in $object.Keys) {
        if ($targetCertificate.Thumbprint -eq $encryptedKey.Thumbprint) {
          # To decrypt the AES key, we use the PrivateKey.Decrypt() method on the certificate object.
          $aes.Key = $targetCertificate.PrivateKey.Decrypt($encryptedKey.Key, $true)
          $aes.IV  = $targetCertificate.PrivateKey.Decrypt($encryptedKey.IV, $true)
          $found = $true
          break
        }
      }
    }
  
    if (-not $found) {
      throw "No certificate (with private key) matching thumbprint '$($encryptedKey.Thumbprint)' was found in Cert:\CurrentUser\My."
    }

    # Now we can use the $aes object and .NET Streams to decrypt our file back to its original form.  The code is very similar to that used in the encryption process.
    $inputStream = New-Object System.IO.FileStream("$encryptedfilepath", [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
    $outputStream = New-Object System.IO.FileStream("$outfile", [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)

    # The difference is that this time, the CryptoStream is doing the reading, and is wrapped around $inputStream.  $outputStream is doing the writing.
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($inputStream, $aes.CreateDecryptor(), [System.Security.Cryptography.CryptoStreamMode]::Read)
    $buffer = New-Object byte[](256)
    
    while (($read = $cryptoStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
      $outputStream.Write($buffer, 0, $read)
    }
  }

  finally {
    if ($cryptoStream -ne $null) {
      $cryptoStream.Dispose()
      $cryptoStream = $null
    }

    if ($outputStream -ne $null) {
      $outputStream.Dispose()
      $outputStream = $null
    }

    if ($inputStream -ne $null) {
      $inputStream.Dispose()
      $inputStream = $null
    }

    if ($aes -ne $null) {
      $aes.Dispose()
      $aes = $null
    }
  }
}

