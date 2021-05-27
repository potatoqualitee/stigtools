function Import-CCIList {
    <#
    .SYNOPSIS
        Imports the CCIList XML from DISA

    .PARAMETER Path
        Path to the CCIList XML

    .NOTES
        Downloaded from https://iase.disa.mil/stigs/cci/pages/index.aspx

    .EXAMPLE
        Import-CCIList -Path "C:\Test\U_CCI_List.xml"
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path $PSItem })]
        [string]$Path
    )
    process {
        [xml](Get-Content -Path $Path)
    }
}
