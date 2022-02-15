function Generate-MachineKey {
  # https://gist.github.com/pinalbhatt/a3a201c4bf6ea114a9ad
  [CmdletBinding()]
  param (
    [ValidateSet("AES", "DES", "3DES")]
    [string]$decryptionAlgorithm = 'AES',
    [ValidateSet("MD5", "SHA1", "HMACSHA256", "HMACSHA384", "HMACSHA512")]
    [string]$validationAlgorithm = 'HMACSHA256'
  )
  process {
    function BinaryToHex {
        [CmdLetBinding()]
        param($bytes)
        process {
            $builder = new-object System.Text.StringBuilder
            foreach ($b in $bytes) {
              $builder = $builder.AppendFormat([System.Globalization.CultureInfo]::InvariantCulture, "{0:X2}", $b)
            }
            $builder
        }
    }
    switch ($decryptionAlgorithm) {
      "AES" { $decryptionObject = new-object System.Security.Cryptography.AesCryptoServiceProvider }
      "DES" { $decryptionObject = new-object System.Security.Cryptography.DESCryptoServiceProvider }
      "3DES" { $decryptionObject = new-object System.Security.Cryptography.TripleDESCryptoServiceProvider }
    }
    $decryptionObject.GenerateKey()
    $decryptionKey = BinaryToHex($decryptionObject.Key)
    $decryptionObject.Dispose()
    switch ($validationAlgorithm) {
      "MD5" { $validationObject = new-object System.Security.Cryptography.HMACMD5 }
      "SHA1" { $validationObject = new-object System.Security.Cryptography.HMACSHA1 }
      "HMACSHA256" { $validationObject = new-object System.Security.Cryptography.HMACSHA256 }
      "HMACSHA385" { $validationObject = new-object System.Security.Cryptography.HMACSHA384 }
      "HMACSHA512" { $validationObject = new-object System.Security.Cryptography.HMACSHA512 }
    }
    $validationKey = BinaryToHex($validationObject.Key)
    $validationObject.Dispose()
    [string]::Format([System.Globalization.CultureInfo]::InvariantCulture,
      "<machineKey decryption=`"{0}`" decryptionKey=`"{1}`" validation=`"{2}`" validationKey=`"{3}`" />",
      $decryptionAlgorithm.ToUpperInvariant(), $decryptionKey,
      $validationAlgorithm.ToUpperInvariant(), $validationKey)
  }
}

function Generate-WebConfig() {
    $webconfig = '
    <?xml version="1.0"?>
    <configuration>
      <system.web>
    '
    $script:key = Generate-MachineKey

    $webconfig += $script:key

    $webconfig += '
        <compilation debug="true" targetFramework="4.7.2"/>
        <httpRuntime targetFramework="4.7.2"/>
      </system.web>
	    <runtime>
		    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
			    <dependentAssembly>
				    <assemblyIdentity name="System.Text.Json" publicKeyToken="CC7B13FFCD2DDD51" culture="neutral"/>
				    <bindingRedirect oldVersion="0.0.0.0-5.0.0.2" newVersion="5.0.0.2"/>
			    </dependentAssembly>
			    <dependentAssembly>
				    <assemblyIdentity name="System.Runtime.CompilerServices.Unsafe" publicKeyToken="B03F5F7F11D50A3A" culture="neutral"/>
				    <bindingRedirect oldVersion="0.0.0.0-5.0.0.0" newVersion="5.0.0.0"/>
			    </dependentAssembly>
		    </assemblyBinding>
	    </runtime>
     <system.serviceModel>
      <bindings />
      <client />
     </system.serviceModel>
    </configuration>
    '

  return $webconfig
}

function Generate-AppConfig() {
  $appconfig = '
    <appSettings>
		<add key="AzureAuthorityUri" value="' + $script:AzureAuthorityUri + '">
		<add key="AzureApplicationId" value="' + $script:AzureApplicationId + '"/>
		<add key="AzureClientSecret" value="' + $script:AzureApplicationSecret + '"/>
	</appSettings>
  '
  return $appconfig
}

function Get-AppConfigInput() {
    #Write-Host "Input Azure Authority Uri: (https://login.microsoftonline.com/your-tenant-id/v2.0/)";
    $script:AzureAuthorityUri = Read-host "Input Azure Authority Uri: (https://login.microsoftonline.com/your-tenant-id/v2.0/) ";
    $script:AzureAuthorityUri = $script:AzureAuthorityUri.trim().trim('/');
    $script:AzureAuthorityUri = $script:AzureAuthorityUri + '/';

    #Write-Host "Input Azure Application (Client) Id: (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)";
    $script:AzureApplicationId = Read-host "Input Azure Application (Client) Id: (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) ";
    $script:AzureApplicationId = $script:AzureApplicationId.Trim();

    #Write-Host "Input Azure Client Secret Value: (Located in Azure Active Directory -> App Registrations -> App Name -> Certificates & Secrets)";
    $script:AzureApplicationSecret = Read-host "Input Azure Client Secret Value: (Located in Azure Active Directory -> App Registrations -> App Name -> Certificates & Secrets) ";
    $script:AzureApplicationSecret = $script:AzureApplicationSecret.Trim();
}

Write-Host "########################################################################################"
Write-Host "Setting up Azure Extension for SQL Server Reporting Services..."
Write-Host "########################################################################################"
Write-Host "NOTE: This has only been tested with SQL Server 2016."

Write-Host " "

Get-AppConfigInput
Write-Host "------------------------------------------------------------------------------------------------------------------------------------------"

Write-Host "Generating extension web configuration..."
$webConfig = Generate-WebConfig

Write-Host "Generating extension app configuration..."
$appConfig = Generate-AppConfig



Write-Host "Generating SSRS web configuration..." 