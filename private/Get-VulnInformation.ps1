function Get-VulnInformation {
    <#
    .SYNOPSIS
        Returns an array of the vulns in the CKL file and all it's associated informational properties (Vuln_ID, Rule_ID, CCI_REF etc)

    .PARAMETER CKLData
        CKL data as loaded from the Import-StigCKL

    .PARAMETER NoAliases
        Aliases are added for backwards compatibility with obsolete Get-CKLVulnInformation, this turns those off

    .EXAMPLE
        Get-VulnInformation -CKLData $CKLData

    .EXAMPLE
        Get-VulnInformation -CKLData $CKLData -NoAliases
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [Alias("XMLData")]
        [xml]$CKLData,
        [switch]$NoAliases
    )
    process {
        $VulnIDs = Get-VulnIDs -CKLData $CKLData
        foreach ($VulnID in $VulnIDs) {
            $VulnInfo = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE = 'Vuln_Num' and ATTRIBUTE_DATA = '$VulnID']").Node.ParentNode.SelectNodes("descendant::STIG_DATA")
            $result = @{ }

            foreach ($Attribute in $VulnInfo) {
                if ($result.ContainsKey($Attribute.VULN_ATTRIBUTE)) {
                    if ($result[$Attribute.VULN_ATTRIBUTE].GetType().BaseType -eq "System.Array") {
                        $result[$Attribute.VULN_ATTRIBUTE] += $Attribute.ATTRIBUTE_DATA
                    } else {
                        $result[$Attribute.VULN_ATTRIBUTE] = @($result[$Attribute.VULN_ATTRIBUTE], $Attribute.ATTRIBUTE_DATA)
                    }
                } else {
                    $result += @{
                        $Attribute.VULN_ATTRIBUTE = $Attribute.ATTRIBUTE_DATA
                    }
                }
            }
            $result = [PSCustomObject]$result

            #Add some aliases
            if (-not $NoAliases) {
                Add-Member -InputObject $result -MemberType AliasProperty -Name Description -Value "Vuln_Discuss" -SecondValue System.String
                Add-Member -InputObject $result -MemberType AliasProperty -Name Title -Value "Rule_Title" -SecondValue System.String
                Add-Member -InputObject $result -MemberType AliasProperty -Name Version -Value "Rule_Ver" -SecondValue System.String
                Add-Member -InputObject $result -MemberType AliasProperty -Name FixText -Value "Fix_Text" -SecondValue System.String
                Add-Member -InputObject $result -MemberType AliasProperty -Name CheckText -Value "Check_Content" -SecondValue System.String
            }
            $result
        }
    }
}