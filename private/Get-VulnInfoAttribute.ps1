function Get-VulnInfoAttribute {
    <#
    .SYNOPSIS
        Gets a vuln's informational attribute

    .DESCRIPTION
        Gets a vuln's info attribute, literally "ATTRIBUTE_DATA" from the requested "STIG_DATA" element in the XML data of the CKL. This gets information on a specific vuln (Fix text, severity, title)

    .PARAMETER CKLData
        Data as return from the Import-StigCKL

    .PARAMETER VulnID
        Vuln_Num of the Vuln to query

    .PARAMETER RuleID
        Rule_ID of the Vuln to query

    .PARAMETER Attribute
        The Attribute you wish to query.

    .EXAMPLE
        Get-VulnInfoAttribute -CKLData $CKLData -Attribute "Version"
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
        [ValidateSet("Vuln_Num", "Severity", "Group_Title", "Rule_ID", "Rule_Ver", "Rule_Title", "Vuln_Discuss", "IA_Controls",
            "Check_Content", "Fix_Text", "False_Positives", "False_Negatives", "Documentable", "Mitigations", "Potential_Impact",
            "Third_Party_Tools", "Mitigation_Control", "Responsibility", "Security_Override_Guidance", "Check_Content_Ref",
            "Class", "STIGRef", "TargetKey", "CCI_REF")]
        [string]$Attribute
    )
    process {
        if ($VulnID) {
            $results = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE = 'Vuln_Num' and ATTRIBUTE_DATA = '$VulnID']").Node.ParentNode.SelectNodes("descendant::STIG_DATA[VULN_ATTRIBUTE = '$Attribute']").Attribute_Data
        } elseif ($RuleID) {
            $results = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE = 'Rule_ID' and ATTRIBUTE_DATA = '$RuleID']").Node.ParentNode.SelectNodes("descendant::STIG_DATA[VULN_ATTRIBUTE = '$Attribute']").Attribute_Data
            if (-not $results) {
                $results = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE = 'Rule_Ver' and ATTRIBUTE_DATA = '$RuleID']").Node.ParentNode.SelectNodes("descendant::STIG_DATA[VULN_ATTRIBUTE = '$Attribute']").Attribute_Data
            }
        } else {
            Write-Error "VulnID or RuleID must be set!"
        }
        if (-not $results) {
            Write-Error "Specified attribute ($Attribute) was not found for $($VulnID)$RuleID"
        }
        $results
    }
}