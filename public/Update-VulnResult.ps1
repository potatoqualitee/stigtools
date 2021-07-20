function Update-VulnResult {
    <#
    .SYNOPSIS
        Sets all NotReviewed in a checklist to Open

    .DESCRIPTION
        Loads a checklist, and sets all Not_Reviewed to Open, then saves it

    .PARAMETER Path
        Full path to the checklist file

    .EXAMPLE
        Update-VulnResult -Path C:\CKLs\MyChecklist.ckl
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateScript( { Test-Path -Path $PSItem })]
        [Alias("FullName")]
        [string[]]$Path,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$VulnID,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$RuleID,
        [Alias("Finding")]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Details,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Comments,
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