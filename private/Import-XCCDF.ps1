function Import-XCCDF {
    <#
    .SYNOPSIS
        Load an XCCDF file into a [xml]

    .PARAMETER Path
        Path to the XCCDF file

    .EXAMPLE
        Import-XCCDF -Path C:\XCCDF\Results.xml
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path $PSItem })]
        [string]$Path
    )
    process {
        [xml](Get-Content -Encoding UTF8 -Path $Path)
    }
}