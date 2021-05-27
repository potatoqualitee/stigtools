function Export-MetricsReport {
<#
    .SYNOPSIS
        Grabs metrics per service for multiple checklists

    .DESCRIPTION
        Generates high-level metrics on checklist by service. Note that your directory must be in a specific format. All checklists located in a child of the parent folder are counted as one service

    .PARAMETER Path
        Parent of the service directories. Example structure
            Parent
                |-IIS
                |-OS
                |-Some other Service

    .PARAMETER Destination
        Location to save the output csv files containing the metrics.

    .OUTPUT
        One CSV file for each subfolder of $Path. Each CSV is intended to represent one service.

    .EXAMPLE
        Export-MetricsReport.ps1 -Path C:\CKLs -Destination C:\Reports
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Destination
    )
    process {
        $services = Get-ChildItem -Path $Path -Directory
        Write-Progress -Activity "Processing" -PercentComplete 0
        $completed = 0
        #Loop through each of the CKL directories, remember each should be named after the service they are for (IIS, Windows OS, etc)
        foreach ($service in $services) {
            Write-Progress -Activity "Processing" -Status "Processing $($service.BaseName)" -PercentComplete (($completed / $services.Length) * 100)
            $metrics = Get-StigMetrics -CKLDirectory $service.FullName
            foreach ($category in $metrics.CategoryScores.Keys) {
                [PSCustomObject]@{
                    Category      = $category
                    Open          = $metrics.CategoryScores[$category].Open
                    Total         = $metrics.CategoryScores[$category].Total
                    NotAFinding   = $metrics.CategoryScores[$category].NotAFinding
                    UniqueTotal   = $metrics.CategoryScores[$category].UniqueTotal
                    NotApplicable = $metrics.CategoryScores[$category].NotApplicable
                    NotReviewed   = $metrics.CategoryScores[$category].NotReviewed
                } | Export-Csv -Path (Join-Path -Path $Destination -ChildPath ($service.Name + ".csv")) -NoTypeInformation
            }
            $completed++

        }
        Write-Progress -Activity "Processing" -Completed
    }
}