function Merge-XCCDFToCKL {
    <#
    .SYNOPSIS
        Adds XCCDF results into a loaded CKL data

    .PARAMETER CKLData
        CKL Data as loaded by Import-StigCKL

    .PARAMETER XCCDFData
        XCCDF data as loaded from the Import-XCCDF

    .PARAMETER NoCommentsOnOpen
        Will not write custom comments over previous comments if the check is open

    .EXAMPLE
        Merge-XCCDFToCKL -CKLData $CKLData -XCCDFData $XCCDFDataData
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [Alias("XMLData")]
        [xml]$CKLData,
        [Parameter(Mandatory)]
        [xml]$XCCDFData,
        [switch]$NoCommentsOnOpen
    )
    process {
        #Grab the results from the XCCDF Data
        $Results = Get-XCCDFResults -XCCDF $XCCDFData
        $PrevResults = $null
        if ($NoCommentsOnOpen) {
            $PrevResults = Get-VulnCheckResult -CKLData $CKLData
        }
        $progresscount = 0

        Write-Progress -Activity "Importing XCCDF Results to CKL" -PercentComplete (($progresscount * 100) / $Results.Count)
        #Loop through them
        foreach ($Result in $Results) {
            #Convert result to CKL result
            $Res = "Open"
            if ($Result.result -eq "pass") {
                $Res = "NotAFinding"
            }

            $Details = "Checked by SCAP tool"
            $Comments = "Checked by SCAP tool"

            if ($NoCommentsOnOpen) {
                $PrevResult = $PrevResults | Where-Object { $_.RuleID -eq $Result.RuleID }
                if ($PrevResult -and $PrevResult.Status -ne "NotAFinding") {
                    $Details = $PrevResult.Finding
                    $Comments = $PrevResult.Comments
                }
            }

            #Set it in the CKL
            Set-VulnCheckResult -CKLData $CKLData -RuleID $Result.RuleID -Result $Res -Details $Details -Comments $Comments
            $progresscount++

            Write-Progress -Activity "Importing XCCDF Results to CKL" -PercentComplete (($progresscount * 100) / $Results.Count)
        }
        #Add machine into from XCCDF
        Merge-XCCDFHostDataToCKL -CKLData $CKLData -XCCDF $XCCDFData
        Write-Progress -Activity "Importing XCCDF Results to CKL" -PercentComplete 100 -Completed
    }
}