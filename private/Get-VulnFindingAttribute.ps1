function Get-VulnFindingAttribute {
<#
    .SYNOPSIS
        Gets a vuln's finding attribute (Status, Comments, Details, etc)

    .DESCRIPTION
        Gets a stig's vuln attribute (Status, Comments, Details, etc), literally a direct child of VULN element of a stig item from the XML data of the CKL

    .PARAMETER CKLData
        Data as return from the Import-StigCKL

    .PARAMETER VulnID
        Vuln_Num of the Vuln to get

    .PARAMETER RuleID
        Rule_ID of the Vuln to get

    .PARAMETER Attribute
        The Attribute you wish to get

    .EXAMPLE
        Get-VulnFindingAttribute -CKLData $CKLData -VulnID V-1111 -Attribute COMMENTS
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
        [string]$Attribute
    )
    process {
        if ($VulnID) {
            #If we have vulnid get property that way
            $results = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE = 'Vuln_Num' and ATTRIBUTE_DATA = '$VulnID']").Node.ParentNode.$Attribute
        } elseif ($RuleID) {
            #If we have ruleid, get property that way
            $results = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE = 'Rule_ID' and ATTRIBUTE_DATA = '$RuleID']").Node.ParentNode.$Attribute
            if (-not $results) {
                $results = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE = 'Rule_Ver' and ATTRIBUTE_DATA = '$RuleID']").Node.ParentNode.$Attribute
            }
        } else {
            Write-Error "VulnID or RuleID must be set!"
        }
        if ($results) {
            $results
        }
    }
}