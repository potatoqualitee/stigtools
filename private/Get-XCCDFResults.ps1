function Get-XCCDFResults {
<#
    .SYNOPSIS
        Returns stig results from an XCCDF file

    .PARAMETER XCCDF
        XCCDF data as loaded from the Import-XCCDF

    .EXAMPLE
        Get-XCCDFResults -XCCDF (Import-XCCDF -Path C:\XCCDF\Results.xml)
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [xml]$XCCDF
    )
    process {
        #Grab rule results
        $results = $XCCDF.Benchmark.TestResult.'rule-result'
        #Loop through them
        foreach ($result in $results) {
            #Get IP
            if ($result.idref -match "(SV-.*_rule)") {
                $result.idref = $Matches[1]
            }
            #Return ID and result
            [PSCustomObject]@{
                RuleID = $result.idref
                Result = $result.result
            }
        }
    }
}