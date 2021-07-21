function Update-VulnResult {
    <#
    .SYNOPSIS
        Updates Vulnerability results for a checklist file

    .DESCRIPTION
        Loads a checklist, and sets the new status, then saves it

    .PARAMETER Path
        Full path to the checklist file

    .PARAMETER VulnID
        Vuln_Num of the Vuln to Set

    .PARAMETER Result
        Final Result (Open, Not_Reviewed, Not_Applicable, or NotAFinding)

    .EXAMPLE
        Read-Checklist -Path .\tests\nessus\win10.ckl -VulnsOnly | Update-VulnResult -Path .\tests\nessus\win11.ckl, .\tests\nessus\win12.ckl

        Updates win11 and win12 with the results of win10
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateScript( { Test-Path -Path $PSItem })]
        [Alias("FullName")]
        [string[]]$Path,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$VulnID,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet("Open","NotAFinding","Not_Reviewed", "Not_Applicable")]
        [Alias("Status")]
        [string]$Result
    )
    begin {
        Write-Progress -Activity "Setting CKLs" -PercentComplete 0 -Id 1
        #If pointing to a single CKL, set children to an array that only contains that one ckl
        if ($Path.EndsWith(".ckl")) {
            $files = Get-ChildItem -ErrorAction SilentlyContinue -Path $Path
        } else {
            #Otherwise, load all CKL files from that path and put it into an array
            $files = Get-ChildItem -Path $Path -Filter "*.CKL"
            if (-not $files) {
                Write-Error "No CKL files found in directory"
                return
            }
        }
        $hash = @{ }

        foreach ($file in $files) {
            $hash[$file.FullName] = Import-StigCKL -Path $file.FullName
        }
        $progresscount = 0
    }
    process {
        foreach ($file in $files) {
            # just guess that it has about 300 checks
            if ((($i++) % 3) -eq 0) { $progresscount++ }
            Set-VulnCheckResult -XMLData $hash[$file.FullName] -VulnID $VulnID -Result $Result
            Write-Progress -Activity "Setting CKLs" -PercentComplete $progresscount -Id 1
            if ($progresscount -eq 100) {
                $progresscount = 0
            }
        }
    }
    end {
        foreach ($file in $files) {
            Export-StigCKL -XMLData $hash[$file.FullName] -Path $file.FullName
            Get-ChildItem -Path $file.FullName
        }
        Write-Progress -Activity "Setting CKLs" -PercentComplete 100 -Id 1 -Completed
    }
}