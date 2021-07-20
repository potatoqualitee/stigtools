function Get-VulnCheckResult {
<#
    .SYNOPSIS
        Gets the status of a single vuln check, or an array of the status of all vuln checks in a CKL

    .PARAMETER CKLPath
        The path to the checklist

    .PARAMETER CKLData
        Data as return from the Import-StigCKL

    .PARAMETER VulnID
        Vuln_Num of the Vuln to Get

    .PARAMETER RuleID
        Rule_ID of the Vuln to Get

    .PARAMETER NoAliases
        To help align function outputs and inputs, aliases are added. This will prevent aliases from being added to output

    .EXAMPLE
        Get-VulnCheckResult -CKLData $CKLData -VulnID V-11111
#>
    [CmdletBinding()]
    param
    (
        [ValidateScript( { Test-Path -Path $PSItem })]
        [string]$CKLPath,
        [Alias("XMLData")]
        [xml]$CKLData,
        [string]$VulnID,
        [string]$RuleID,
        [switch]$NoAliases
    )
    process {
        if (-not ($PSBoundParameters.CKLPath -or $PSBoundParameters.CKLData)) {
            throw "You must specify CKLPath or CKLData"
        }

        if ($PSBoundParameters.CKLPath) {
            $CKLData = Import-STIGCKL -Path $CKLPath
        }

        Write-Verbose -Message "VulnID $VulnID"
        Write-Verbose -Message "RuleID $RuleID"
        Write-Verbose -Message "Attribute $Attribute"

        if ($VulnID -or $RuleID) {
            $Status = Get-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID -RuleID $RuleID -Attribute "STATUS"
            $Finding = Get-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID -RuleID $RuleID -Attribute "FINDING_DETAILS"
            $Comments = Get-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID -RuleID $RuleID -Attribute "COMMENTS"
            if (-not $VulnID) {
                $VulnID = Get-VulnInfoAttribute -CKLData $CKLData -RuleID $RuleID -Attribute "Vuln_Num"
            }

            if ($NoAliases) {
                [PSCustomObject]@{
                    Status   = $Status
                    Finding  = $Finding
                    Comments = $Comments
                    VulnID   = $VulnID
                }
            } else {
                [PSCustomObject]@{
                    Status   = $Status
                    Finding  = $Finding
                    Comments = $Comments
                    VulnID   = $VulnID
                    Details  = $Finding
                    Result   = $Status
                }
            }
        } else {
            $VulnIDs = Get-VulnIDs -CKLData $CKLData
            foreach ($VulnID in $VulnIDs) {
                $Status = Get-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID -Attribute "STATUS"
                $Finding = Get-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID -Attribute "FINDING_DETAILS"
                $Comments = Get-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID -Attribute "COMMENTS"
                if ($NoAliases) {
                    [PSCustomObject]@{
                        Status   = "" + $Status
                        Finding  = "" + $Finding
                        Comments = "" + $Comments
                        VulnID   = "" + $VulnID
                    }
                } else {
                    [PSCustomObject]@{
                        Status   = "" + $Status
                        Finding  = "" + $Finding
                        Comments = "" + $Comments
                        VulnID   = "" + $VulnID
                        Details  = "" + $Finding
                        Result   = "" + $Status
                    }
                }
            }
        }
    }
}