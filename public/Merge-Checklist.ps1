function Merge-Checklist {
    <#
    .SYNOPSIS
        Merges two CKL files and saves it as a new CKL

    .PARAMETER SourceCKLFile
        The CKL file path that contains the data to merge

    .PARAMETER DestinationCKLFile
        The CKL file path that the data should merge into

    .PARAMETER IncludeNR
        If this is set, Items marks at "Not_Reviewed" will overwrite the destination, otherwise only answered items are merged

    .PARAMETER DontCopyHostInfo
        Does not overwrite desination's host data

    .PARAMETER DontOverwriteVulns
        Does not overwrite desination's vuln findings. Result is only Not_Reviewed checks are filled.

    .EXAMPLE
        Merge-Checklist -DestinationCKLFile "C:\CKLS\Blank.ckl" -DestinationCKLFile "C:\CKLS\Answered.ckl" -SaveFilePath "C:\CKLS\Merged.ckl"

    .EXAMPLE
        Merge-Checklist -DestinationCKLFile "C:\CKLS\ManualChecks.ckl" -DestinationCKLFile "C:\CKLS\ScapResults.ckl" -SaveFilePath "C:\CKLS\MergedChecks.ckl" -DontCopyHostInfo -DontOverwriteVulns

    .EXAMPLE
        Merge-Checklist -DestinationCKLFile "C:\CKLS\Blank.ckl" -DestinationCKLFile "C:\CKLS\Answered.ckl" -SaveFilePath "C:\CKLS\Merged.ckl" -IncludeNR
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path $PSItem })]
        [string]$DestinationCKLFile,
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path $PSItem })]
        [string]$SourceCKLFile,
        [Parameter(Mandatory)]
        [string]$SaveFilePath,
        [switch]$IncludeNR,
        [switch]$DontCopyHostInfo,
        [switch]$DontOverwriteVulns
    )
    process {
        #Load both inputs
        $DestinationCKL = Import-StigCKL -Path $DestinationCKLFile
        $SourceCKL = Import-StigCKL -Path $SourceCKLFile
        #Merge 'em
        Merge-CKLData -SourceCKL $SourceCKL -DestinationCKL $DestinationCKL -IncludeNR:$IncludeNR -DontCopyHostInfo:$DontCopyHostInfo -DontOverwriteVulns:$DontOverwriteVulns
        #Save output
        Export-StigCKL -CKLData $DestinationCKL -Path $SaveFilePath
        Get-ChildItem $SaveFilePath
    }
}