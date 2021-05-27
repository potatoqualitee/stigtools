function Import-StigCKL {
<#
    .SYNOPSIS
        Load a CKL file as an [xml] element. This can then be passed to other functions in this module.

    .PARAMETER Path
        Full path to the CKL file

    .EXAMPLE
        Import-StigCKL -Path "C:\CKLs\MyCKL.ckl"
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path $PSItem})]
        [string]$Path
    )
    [xml](Get-Content -Path $Path -Encoding UTF8)
}
