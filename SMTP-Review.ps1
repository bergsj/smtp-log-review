param (
    [string] $LogFilePath = "D:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\Logs\FrontEnd\ProtocolLog\SmtpReceive\*.log",
    [string] $OutputFile = ".\SMTP-Review-IPaddressesUsingConnectors.json",
    [ValidateSet("Json","Csv")]
    [string] $OutputType = "Json",
    [switch] $ReverseLookup
)

# Initalize variables
$data = @()
$int = 0

# Retrieve the logfiles from the LogFilePath variable and count them
$LogFiles = Get-Item  $LogFilePath
$count = @($logfiles).count

# Retrieve the contents of all the logfiles in one read operation. Not line by line, but file by file (faster processing). And loop through the data blocks (files)
$filecontents = Get-Content $LogFiles -ReadCount 0
foreach ($content in $filecontents){

	$int = $int + 1
	$Percent = $int/$count * 100
	Write-Progress -Activity "Collecting Log details" -Status "Processing log File $int of $count" -PercentComplete $Percent 

    # Remove the first 4 lines of commentary, remove the hash from the header line, convert the log to CSV in memory and group them by SMTP connector
    $FileContent = $content | Select-Object -Skip 4
    $FileContent[0] = $FileContent[0].Replace("#","")
    $datasource = $FileContent | ConvertFrom-Csv -Delimiter "," | Group-Object connector-id

    # Loop through all SMTP connector data blocks
    $datasource | ForEach-Object {
            
            $connectorName = $_.Name
            
            # Without filtering on only success emails
            # $ipData = $_.Group."remote-endpoint" | ConvertFrom-Csv -Delimiter ":" -Header 'Host','Port' | Group-Object Host | Select Name, Count
            
            # With filtering on success emails
            $searchString = "250 2.1.5 Recipient OK"
            $ipData = $_.Group | Group-Object session-id | ForEach-Object { $_.Group | ForEach-Object { if ($_.data -match $searchString){ $_."remote-endpoint" } } } | ConvertFrom-Csv -Delimiter ":" -Header 'Host','Port' | Group-Object Host | Select-Object Name, Count

            # Try to find the current connector in the output datasource
            $connector = $data | Where-Object ConnectorName -eq $connectorName
            
            if (-not $connector){
                # If this is the first time we see this connector in the output datasource, add the entire object including the IP address data
                $arrayObject = @()
                $arrayObject += $ipData

                $data += @([pscustomobject]@{
                                ConnectorName = $connectorName;
                                IpData = $arrayObject
                            })
            }
            else{
                # The connector already exists, so loop through IP address data
                $ipData | ForEach-Object {
                    
                    # Try to find the current IP address in the output datasource
                    $ipEntry = $connector.IpData | Where-Object Name -eq $_.Name #$ipData | Where-Object Name -eq $_.Name
                    
                    if (-not $ipEntry){
                        # If this is the first time we see this IP address, add the entire object as IP address data block

                        $connector.IpData += $_
                    }
                    else{
                        # The IP address already exists, so increase the existing count with the current count
                        
                        $ipEntry.Count += $_.Count
                    }
                }
                
            }

        }
}

# Convert the output data object to JSON and save to file
# $data | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile

# Convert the output data object to CSV and save to file
$data | ForEach-Object { $connectorName = $_.ConnectorName; $_.IpData | Select-Object @{Name = 'ConnectorName'; Expression = {$connectorName}},Name,Count } | Export-CSV -NoTypeInformation -Path $OutputFile

# If parameter ReverseLookup is used, perform DNS reverse lookup on all IP addresses

if ($ReverseLookup){

    $int = 0
    $count = (($data.IpData.Name) | Select-Object -Unique).Count   
    $dnsnames = @()
  
	$int = $int + 1
	$Percent = $int/$count * 100
    Write-Progress -Activity "Performing reverse DNS lookup" -Status "Processing IP address $int of $count" -PercentComplete $Percent
    
    # Loop through all unique IP address from the data object
    foreach ($ipAddress in (($data.IpData.Name) | Select-Object -Unique)) {
        
        # Try to resolve the hostname from the IP address
        $resolvedComputer = (Resolve-DNSName $ipAddress -ErrorAction SilentlyContinue)
        $dnsnames += @([pscustomobject]@{
                        name=$ipAddress;
                        record=$resolvedComputer.NameHost
                    })
    }
    
    $leafBase = (Split-Path $OutputFile -Leaf).Split(".")[0] # (Split-Path $OutputFile -LeafBase) -LeafBase not available in PowerShell 5.1
    $extention = (".{0}" -f (Split-Path $OutputFile -Leaf).Split(".")[1]) # (Split-Path $OutputFile -Extension)  -Extension not available in PowerShell 5.1
    $dnsnames  | ConvertTo-Json | Out-File -FilePath ("{0}\{1}-dns{2}" -f (Split-Path $OutputFile -Parent), $leafBase, $extention)

}
