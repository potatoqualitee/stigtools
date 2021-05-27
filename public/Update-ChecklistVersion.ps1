function Update-CKLVersion {
    <#
    .SYNOPSIS
        Attempts to convert a checklist in 1.x version to a compatible 2.6 version checklist

    .DESCRIPTION
        Attempts to convert a checklist in 1.x version to a compatible 2.6 version checklist

    .PARAMETER Source
        Full path to the CKL file to convert

    .PARAMETER Destination
        Full path to the save location for the upgraded ckl

    .EXAMPLE
        Update-CKLVersion -Source C:\CKLs\MyChecklist.ckl -Destination C:\CKLs\UpgradedMyChecklist.ckl
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateScript( { Test-Path -Path $PSItem })]
        [Alias("FullName")]
        [string]$Source,
        [parameter(Mandatory)]
        [string]$Destination
    )
    process {
        $Content = Get-Content -Path $Source -Raw -Encoding UTF8
        $Content = $Content.Replace("<STIG_INFO>","<STIGS><iSTIG><STIG_INFO>").Replace("</CHECKLIST>","</iSTIG></STIGS></CHECKLIST>")
        $Content = $Content -replace "<SV_VERSION>DISA STIG Viewer : .*</SV_VERSION>",""
        $null = $Content | Out-File $Destination -Encoding UTF8
        Get-ChildItem -Path $Destination
    }
}