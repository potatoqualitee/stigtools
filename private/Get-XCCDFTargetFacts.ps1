function Get-XCCDFTargetFacts {
<#
    .SYNOPSIS
        Gets all target facts from an XCCDF

    .PARAMETER XCCDF
        XCCDF data as loaded from the Import-XCCDF

    .EXAMPLE
        Get-XCCDFTargetFacts -XCCDF $XCCDFData
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [xml]$XCCDF
    )
    process {
    $results = [PSCustomObject]@{
        Interfaces = @()
    }

    $facts = $XCCDF.Benchmark.TestResult.'target-facts'.fact

    $interface = $null

    for ($i = 0; $i -lt $facts.Length; $i++) {
        if ($facts[$i].Name -eq "urn:scap:fact:asset:identifier:interface_name") {
            if ($interface) {
                $results.Interfaces += $interface
            }
            $interface = New-Object -TypeName PSObject
        }
        if ($interface) {
            $interface | Add-Member -Name $facts[$i].Name.Replace("urn:scap:fact:asset:identifier:","") -MemberType NoteProperty -Value $facts[$i]."#text"
        } else {
            $results | Add-Member -Name $facts[$i].Name.Replace("urn:scap:fact:asset:identifier:","") -MemberType NoteProperty -Value $facts[$i]."#text"
        }
    }
    if ($interface) {
        $results.Interfaces += $interface
    }

    $results
    }
}
