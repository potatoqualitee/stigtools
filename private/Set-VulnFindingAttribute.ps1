function Set-VulnFindingAttribute {
    <#
    .SYNOPSIS
        Sets a vuln's finding attribute (Status, Comments, Details, etc)

    .DESCRIPTION
        Sets a stig's vuln attribute (Status, Comments, Details, etc), literally a direct child of VULN element of a stig item from the XML data of the CKL

    .PARAMETER CKLData
        Data as return from the Import-StigCKL

    .PARAMETER VulnID
        Vuln_Num of the Vuln to Set

    .PARAMETER RuleID
        Rule_ID of the Vuln to Set

    .PARAMETER Attribute
        The Attribute you wish to Set

    .PARAMETER Value
        The new value for the Attribute

    .EXAMPLE
        Set-VulnFindingAttribute -CKLData $CKLData -VulnID V-1111 -Attribute COMMENTS -Value "This was checked by script"
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [Alias("XMLData")]
        [xml]$CKLData,
        [string]$VulnID,
        [string]$RuleID,
        [Parameter(Mandatory)]
        [ValidateSet("SEVERITY_JUSTIFICATION", "SEVERITY_OVERRIDE", "COMMENTS", "FINDING_DETAILS", "STATUS")]
        [string]$Attribute,
        [Parameter(Mandatory)]
        [string]$Value
    )
    process {
        $settings = $null
        if ($VulnID) {
            $settings = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE = 'Vuln_Num' and ATTRIBUTE_DATA = '$VulnID']").Node.ParentNode
        } elseif ($RuleID) {
            $settings = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE = 'Rule_ID' and ATTRIBUTE_DATA = '$RuleID']").Node.ParentNode
            if (-not $settings) {
                $settings = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE = 'Rule_Ver' and ATTRIBUTE_DATA = '$RuleID']").Node.ParentNode
            }
        }
        if ($settings) {
            $settings.$Attribute = $Value
            $true
        } else {
            Write-Error "Vuln $VulnID$RuleID not found"
        }
        $false
    }
}