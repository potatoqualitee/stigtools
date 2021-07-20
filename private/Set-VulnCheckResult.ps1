function Set-VulnCheckResult {
    <#
    .SYNOPSIS
        Sets the findings information for a single vuln

    .DESCRIPTION
        This is one of the main tools in this module, this will set the result for a given vuln to what you specify

    .PARAMETER CKLData
        Data as return from the Import-StigCKL

    .PARAMETER VulnID
        Vuln_Num of the Vuln to Set

    .PARAMETER RuleID
        Rule_ID of the Vuln to Set

    .PARAMETER Details
        Finding details

    .PARAMETER Comments
        Finding comments

    .PARAMETER Result
        Final Result (Open, Not_Reviewed, Not_Applicable, or NotAFinding)

    .EXAMPLE
        Set-VulnCheckResult -CKLData $CKLData -VulnID V-11111 -Details "Not set correctly" -Comments "Checked by xyz" -Result Open
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [Alias("XMLData")]
        [xml]$CKLData,
        [string]$VulnID,
        [string]$RuleID,
        [Alias("Finding")]
        [string]$Details,
        [string]$Comments,
        [Parameter(Mandatory)]
        [ValidateSet("Open","NotAFinding","Not_Reviewed", "Not_Applicable")]
        [Alias("Status")]
        [string]$Result
    )
    process {
        #If we have what we need
        if ($VulnID -or $RuleID) {
            if ($Result) {
                $xml = Set-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID -RuleID $RuleID -Attribute "STATUS" -Value $Result
                if (-not $xml) {
                    Write-Warning "Failed to write: status of vuln $VulnID rule $RuleID"
                }
            }
            if ($Details) {
                if ($Details -eq "") {
                    $Details = " " #Add whitespace to prevent blank string error
                }
                $xml = Set-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID -RuleID $RuleID -Attribute "FINDING_DETAILS" -Value $Details
                if (-not $xml) {
                    Write-Warning "Failed to write: details of vuln $VulnID rule $RuleID"
                }
            }
            if ($Comments) {
                if ($Comments -eq "") {
                    $Comments = " " #Add whitespace to prevent blank string error
                }
                $xml = Set-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID -RuleID $RuleID -Attribute "COMMENTS" -Value $Comments
                if (-not $xml) {
                    Write-Warning "Failed to write: comments of vuln $VulnID rule $RuleID"
                }
            }
        } else {
            #Write error if we were not passed a vuln or rule
            Write-Error "VulnID or RuleID must be set!"
        }
    }
}