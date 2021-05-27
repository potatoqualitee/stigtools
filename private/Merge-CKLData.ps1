function Merge-CKLData {
    <#
    .SYNOPSIS
        Merges two loaded CKLs

    .PARAMETER SourceCKL
        The CKL that contains the data to merge, as from Import-StigCKL

    .PARAMETER DestinationCKL
        The CKL that the data should merge into, as from Import-StigCKL

    .PARAMETER IncludeNR
        If this is set, Items marks at "Not_Reviewed" will overwrite the destination, otherwise only answered items are merged

    .EXAMPLE
        Merge-CKLData -SourceCKL $OriginalInfo -DestinationCKL $NewCKL
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [XML]$SourceCKL,
        [Parameter(Mandatory)]
        [XML]$DestinationCKL,
        [switch]$IncludeNR,
        [switch]$DontCopyHostInfo,
        [switch]$DontOverwriteVulns
    )
    process {
        #Get the stig results form the source
        Write-Progress -Activity "Merging" -CurrentOperation "Loading old results"
        $StigResults = Get-VulnCheckResult -CKLData $SourceCKL
        $DestinationIDs = (Get-VulnCheckResult -CKLData $DestinationCKL).VulnID
        $I = 0

        Write-Progress -Activity "Merging" -CurrentOperation "Writing results" -PercentComplete (($I * 100) / $StigResults.Length)
        #Import them into the destination
        foreach ($Result in $StigResults) {
            if ($DestinationIDs.Contains($Result.VulnID)) {
                if ($Result.Status -ne "Not_Reviewed" -or $IncludeNR) {
                    if ($DontOverwriteVulns) {
                        $PrevResult = Get-VulnCheckResult -CKLData $DestinationCKL -VulnID $Result.VulnID
                        if (-not $PrevResult -or $PrevResult.Status -eq "Not_Reviewed") {
                            Set-VulnCheckResult -CKLData $DestinationCKL -VulnID $Result.VulnID -Details $Result.Finding -Comments $Result.Comments -Result $Result.Status
                        }
                    } else {
                        Set-VulnCheckResult -CKLData $DestinationCKL -VulnID $Result.VulnID -Details $Result.Finding -Comments $Result.Comments -Result $Result.Status
                    }
                }
            } else {
                Write-Warning "$($Result.VulnID) does not exist in the destination. Maybe removed in a newer version?"
            }
            $I++

            Write-Progress -Activity "Merging" -PercentComplete (($I * 100) / $StigResults.Length)
        }
        #Copy over host info
        if (-not $DontCopyHostInfo) {
            $HostInfo = Get-ChecklistHostData -CKLData $SourceCKL
            Set-CKLHostData -CKLData $DestinationCKL -Host $HostInfo.HostName -FQDN $HostInfo.HostFQDN -Mac $HostInfo.HostMAC -IP $HostInfo.HostIP -Role $HostInfo.Role
        }
        Write-Progress -Activity "Merging" -PercentComplete 100 -Completed
    }
}