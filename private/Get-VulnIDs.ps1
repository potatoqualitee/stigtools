function Get-VulnIDs {
    <#
    .SYNOPSIS
        Returns all VulnIDs contained in the CKL

    .PARAMETER CKLData
        Data as return from the Import-StigCKL

    .EXAMPLE
        Get-VulnIDs -CKLData $CKLData
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [Alias("XMLData")]
        [xml]$CKLData
    )
    process {
        #Return an array of all VulnIDs
        @() + (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE = 'Vuln_Num']").Node.ATTRIBUTE_DATA
    }
}