function Export-NonReviewedReport {
<#
    .SYNOPSIS
        Saves a report of checklists that still have some non-reviewed entries

    .DESCRIPTION
        Saves a report of checklists that still have some non-reviewed entries

    .PARAMETER Path
        Directory to report on

    .PARAMETER Directory
        Location to save the output csv report

    .PARAMETER Recurse
        Search entire directory structure or just specified folder

    .OUTPUT
        One CSV report with details on non-reviewed checks

    .EXAMPLE
        Export-NonReviewedReport.ps1 -Path C:\CKLs -Directory C:\Reports\myreport.csv -recurse
#>
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Directory,
        [switch]$Recurse
    )
    process {
        $Files = Get-ChildItem -Path $Path -Filter "*.ckl" -Recurse:$Recurse
        $FormattedData = @()

        Write-Progress -Activity "Processing" -PercentComplete 0
        $Completed = 0
        #Loop through each of the CKL files
        foreach ($File in $Files) {
            Write-Progress -Activity "Processing" -Status "$($File.Name)" -PercentComplete (($Completed / $Files.Length) * 100)

            #Load CKL
            $CKLData = Import-StigCKL -Path $File.FullName
            #Load results
            $Results = Get-VulnCheckResult -CKLData $CKLData
            #Grab non-revieweds
            $NR = @() + ($Results | Where-Object { $_.Status -eq "Not_Reviewed" })

            $Report = ""
            foreach ($Item in $NR) {
                $Report += $Item.VulnID + "
 "
            }
            if ($Report -ne "") {
                $FormattedData += [PSCustomObject]@{
                    File        = $File.FullName
                    NotReviewed = $Report
                }
            }
            #Increment Progress
            $Completed++

        }

        $FormattedData | Export-Csv -Path $Directory -NoTypeInformation
        Write-Progress -Activity "Processing" -Completed
    }
}