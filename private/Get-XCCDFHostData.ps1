function Get-XCCDFHostData {
    <#
    .SYNOPSIS
        Gets host info from XCCDF

    .PARAMETER XCCDFData
        XCCDF data as loaded from the Import-XCCDF

    .PARAMETER Filter
        If provided, this will be used to select a specific IP/MAC pair from the XCCDF file. Consider filtering on interface_name, ipv4 or mac and check for nulls

    .EXAMPLE
        Get-XCCDFHostData -XCCDFData $XCCDFData

    .EXAMPLE
        Get-XCCDFHostData -XCCDFData $XCCDFData -Filter {$_.ipv4 -ne $null -and $_.ipv4 -like "192.133.*"}
#>
    [CmdletBinding()]
    param(
        [Alias("XMLData")]
        [xml]$XCCDFData,
        [scriptblock]$Filter
    )
    process {
        #Init variables with empty string
        $HostName, $HostIP, $HostMAC, $HostGUID, $HostFQDN = ""
        #Load info
        $Facts = Get-XCCDFTargetFacts -XCCDF $XCCDFData
        $HostName = $XCCDFData.Benchmark.TestResult.target
        $HostFQDN = $Facts.FQDN
        $HostGUID = $Facts.GUID

        if ($Filter -eq $null) {
            #If no filter provided, we use first target-address for the host info
            $HostIP = (@() + ($XCCDFData.Benchmark.TestResult.'target-address' | Where-Object -FilterScript { $_ -and $_ -ne "" }))[0] #Grab first IP, that is not blank, from targets
            $HostMAC = $Facts.Interfaces | Where-Object -FilterScript { $_.IPv4 -eq $HostIP } #Try and get matching MAC for the specified IP
            if ($HostMAC -and $HostMAC.MAC -and $HostMAC.MAC -ne "") {
                $HostMAC = $HostMAC.MAC #If we succeed, ensure we return the MAC itself
            } elseif ($Facts.Interfaces.Length -gt 0) {
                #If we fail, default to old style of grabing first available MAC, even if it does not match ip, from the XCCDF file
                $HostMAC = $Facts.Interfaces[0].Mac
            }
        } else {
            #If we have a filter, use that to select the IP and MAC reported
            $SelectedInterface = (@() + ($Facts.Interfaces | Where-Object -FilterScript:$Filter))
            if ($SelectedInterface.Length -eq 0) {
                Write-Warning -Message "Filter did not match any interfaces. IP and MAC will be blank"
            } else {
                if ($SelectedInterface.Length -gt 1) {
                    Write-Warning -Message "Filter matched multiple interfaces, first interface matched will be used"
                }
                $HostIP = $SelectedInterface[0].ipv4
                $HostMAC = $SelectedInterface[0].mac
            }
        }
        #Note, XCCDF Does not have a role field, so it will not be filled
        #Return host info
        [PSCustomObject]@{
                HostName = $HostName
                HostIP   = $HostIP
                HostMac  = $HostMAC
                HostFQDN = $HostFQDN
                HostGUID = $HostGUID
            }
    }
}
