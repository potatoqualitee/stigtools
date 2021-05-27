function Repair-Checklist {
    <#
    .SYNOPSIS
        Opens and re-saves a CKL, may fix formatting issues

    .PARAMETER FilePath
        Full path to the CKL file

    .EXAMPLE
        Repair-Checklist -FilePath C:\temp\output\WORKSTATION_U_Windows_Firewall_STIG_V1R7.ckl
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateScript({ Test-Path -Path $PSItem })]
        [Alias("FullName")]
        [string[]]$FilePath
    )
    process {
        foreach ($file in $FilePath) {
            $CKLData = Import-StigCKL -Path $file
            Export-StigCKL -CKLData $CKLData -Path $file
            Get-ChildItem -Path $file
        }
    }
}