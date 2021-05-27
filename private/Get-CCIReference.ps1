function Get-CCIReference {
<#
    .SYNOPSIS
        Gets the references for the specified CCI ID (Generally IA Control Policies)

    .PARAMETER CCIData
        CCIList data as returned by Import-CCIList

    .PARAMETER CCIID
        ID of the CCI to get the references for

    .EXAMPLE
        Get-CCIReference -CCIData $CCIData -CCIID CCI-000001
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [xml[]]$CCIData,
        [Parameter(Mandatory)]
        [string]$CCIID
    )
    process {
        $definition = (Select-XML -Xml $CCIData -XPath "//*[local-name() = 'cci_item' and @id = '$CCIID']").Node.definition
        $results = @() + (Select-XML -Xml $CCIData -XPath "//*[local-name() = 'cci_item' and @id = '$CCIID']/*[local-name() = 'references']/*[local-name() = 'reference']").Node
        foreach ($result in $results) {
            [PSCustomObject]@{
                Title      = $result.Title
                Version    = $result.Version
                Index      = $result.Index
                Location   = $result.Location
                Definition = $definition
            }
        }
    }
}