function Get-CCIVulnReference {
    <#
    .SYNOPSIS
        Gets the references for the specified CCI IDs associated with the specified VulnID

    .PARAMETER CCIPath
        The path to the CCI List

    .PARAMETER CKLPath
        The path to the checklist

    .PARAMETER CCIData
        CCIList data as returned by Import-CCIList

    .PARAMETER CKLData
        CKLData as loaded from the Import-STIGCKL function

    .PARAMETER VulnID
        VulnID to get the references for (Do not use with RuleID)

    .PARAMETER RuleID
        RuleID to get the references for (Do not use with VulnID)

    .EXAMPLE
        Get-CCIVulnReference -CCIData $CCIData -CKLData $CKLData -VulnID V-11111
#>
    [CmdletBinding()]
    param(
        [ValidateScript( { Test-Path -Path $PSItem })]
        [string]$CCIPath,
        [ValidateScript( { Test-Path -Path $PSItem })]
        [string]$CKLPath,
        [xml]$CCIData,
        [Parameter(ValueFromPipeline)]
        [xml]$CKLData,
        [string]$VulnID,
        [string]$RuleID
    )
    process {
        if ($PSBoundParameters.VulnID -and $PSBoundParameters.RuleID) {
            throw "You cannot specify both VulnID and RuleID"
        }

        if (-not ($PSBoundParameters.CCIPath -or $PSBoundParameters.CCIData)) {
            throw "You must specify CCIPath or CCIData"
        }

        if (-not ($PSBoundParameters.CKLPath -or $PSBoundParameters.CKLData)) {
            throw "You must specify CKLPath or CKLData"
        }

        if ($PSBoundParameters.CCIPath) {
            $CCIData = Import-CCIList -Path $CCIPath
        }

        if ($PSBoundParameters.CKLPath) {
            $CKLData = Import-STIGCKL -Path $CKLPath
        }

        $ids = @() + (Get-VulnInfoAttribute -CKLData $CKLData -VulnID $VulnID -RuleID $RuleID -Attribute CCI_REF)
        $keys = @()
        foreach ($id in $ids) {
            $results = Get-CCIReference -CCIData $CCIData -CCIID $id
            foreach ($result in $results) {
                $key = $result.Title + $result.Version + $result.Index
                if (-not $keys.Contains($key)) {
                    $keys += $key
                    $result
                }
            }
        }
    }
}