function Set-NRtoOpen {
<#
    .SYNOPSIS
        Sets all NotReviewed in a checklist to Open

    .DESCRIPTION
        Loads a checklist, and sets all Not_Reviewed to Open, then saves it

    .PARAMETER Path
        Full path to the checklist file

    .EXAMPLE
        Set-NRtoOpen -Path C:\CKLs\MyChecklist.ckl
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path $PSItem })]
        [Alias("FullName")]
        [string[]]$Path
    )
    process {
        #If pointing to a single CKL, set children to an array that only contains that one ckl
        if ($Path.EndsWith(".ckl")) {
            $files = Get-ChildItem -Path $Path
        } else {
            #Otherwise, load all CKL files from that path and put it into an array
            $files = Get-ChildItem -Path $Path -Filter "*.CKL"
            if (-not $files) {
                Write-Error "No CKL files found in directory"
                return
            }
        }

        $progresscount = 0
        Write-Progress -Activity "Setting CKLs" -PercentComplete (($progresscount * 100) / $files.Length) -Id 1

        foreach ($file in $files) {
            $name = $file.BaseName
            Write-Progress -Activity "Setting CKLs" -PercentComplete (($progresscount * 100) / $files.Length) -Id 1
            $ckldata = Import-StigCKL -Path $file
            Write-Progress -Activity $name -Status "Loading Stigs" -PercentComplete 0 -Id 2
            $stigs = Get-VulnCheckResult -XMLData $ckldata
            Write-Progress -Activity $name -Status "Starting Loop" -PercentComplete (($progresscount * 100) / $files.Length) -Id 2
            $stigcount = 0
            foreach ($stig in $stigs) {
                Write-Progress -Activity $name -Status "$($stig.VulnID)" -PercentComplete (($stigcount * 100) / $stigs.Length) -Id 2
                if ($stig.Status -eq "Not_Reviewed" -or $stig.Status -eq "NotReviewed") {
                    Write-Host "$($stig.VulnID) is being marked open"
                    Set-VulnCheckResult -XMLData $ckldata -VulnID $stig.VulnID -Result Open
                }
                $stigcount++
            }
            Export-StigCKL -XMLData $ckldata -Path $file
            Write-Progress -Activity $name -Status "Complete" -PercentComplete 100 -Id 2 -Completed
            Get-ChildItem -Path $file
            $progresscount++
        }
        Write-Progress -Activity "Setting CKLs" -PercentComplete 100 -Id 1 -Completed
    }
}