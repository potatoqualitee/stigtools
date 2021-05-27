function Get-XCCDFInfo {
<#
    .SYNOPSIS
        Gets general info from the XCCDF (Release, Title, Description)

    .PARAMETER XCCDF
        XCCDF data as loaded from the Import-XCCDF

    .EXAMPLE
        Get-XCCDFInfo -XCCDF $XCCDFData
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [xml]$XCCDF
    )
    process {
        $version = ($XCCDF.Benchmark.'plain-text' | Where-Object { $_.id -eq 'release-info' }).'#text'
        [PSCustomObject]@{
            Title       = $XCCDF.Benchmark.title
            Description = $XCCDF.Benchmark.description
            Release     = $version
            Version     = $XCCDF.Benchmark.version
            ID          = $XCCDF.Benchmark.id
        }
    }
}