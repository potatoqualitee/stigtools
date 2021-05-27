function Get-StigMetrics {
    <#
    .SYNOPSIS
        Returns a complex object of metrics on the statuses of the checks in a directory of checklists, or a checklist

    .PARAMETER Path
        Path to folder container the ckls to pull metrics on

    .EXAMPLE
        Get-StigMetrics -Path C:\temp\output\WORKSTATION_U_Windows_Firewall_STIG_V1R7.ckl
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateScript( { Test-Path -Path $PSItem })]
        [Alias("CKLDirectory", "FullName")]
        [string[]]$Path
    )
    process {
        foreach ($file in $Path) {
            if ((Get-Item $file) -is [System.Io.FileInfo] -and $file -like "*.ckl") {
                $files = @() + (Get-Item $file)
            } else {
                #AllChecklists
                $files = Get-ChildItem -Path $file -Filter "*.ckl" -Recurse
            }
            $IndividualStigs = @{}
            $Open = 0
            $NAF = 0
            $NA = 0
            $NR = 0
            $Categories = @{
                Cat1 = [PSCustomObject]@{
                    UniqueTotal   = 0
                    Total         = 0
                    Open          = 0
                    NotReviewed   = 0
                    NotApplicable = 0
                    NotAFinding   = 0
                }

                Cat2 = [PSCustomObject]@{
                    UniqueTotal   = 0
                    Total         = 0
                    Open          = 0
                    NotReviewed   = 0
                    NotApplicable = 0
                    NotAFinding   = 0
                }

                Cat3 = [PSCustomObject]@{
                    UniqueTotal   = 0
                    Total         = 0
                    Open          = 0
                    NotReviewed   = 0
                    NotApplicable = 0
                    NotAFinding   = 0
                }
            }

            Write-Progress -Activity "Aggregating Data" -Status "Starting" -PercentComplete 0
            $processed = 0

            foreach ($file in $files) {
                Write-Progress -Activity "Aggregating Data" -Status $file.Name -PercentComplete (($processed / $files.Length) * 100)
                $CKLData = Import-StigCKL -Path $file.FullName
                $Results = Get-VulnCheckResult -CKLData $CKLData
                #Add to grand totals
                $Open += (@() + ($Results | Where-Object { $_.Status -eq "Open" })).Count
                $NAF += (@() + ($Results | Where-Object { $_.Status -eq "NotAFinding" })).Count
                $NA += (@() + ($Results | Where-Object { $_.Status -eq "Not_Applicable" })).Count
                $NR += (@() + ($Results | Where-Object { $_.Status -eq "Not_Reviewed" })).Count
                #Add to sub totals
                foreach ($Stig in $Results) {
                    #Convert Cat to match table
                    $Cat = Get-VulnInfoAttribute -CKLData $CKLData -VulnID $Stig.VulnID -Attribute Severity
                    if ($Cat -eq "low") {
                        $Cat = "Cat3"
                    } elseif ($Cat -eq "medium") {
                        $Cat = "Cat2"
                    } elseif ($Cat -eq "high" -or $Cat -eq "critical") {
                        $Cat = "Cat1"
                    }
                    #Increment total for cat
                    $Categories[$Cat].Total += 1


                    #Add stig if not already being tracked
                    if (-not $IndividualStigs.ContainsKey($Stig.VulnID)) {
                        $IndividualStigs += @{
                            $Stig.VulnID = ([PSCustomObject]@{
                                    VulnID        = $Stig.VulnID
                                    Open          = 0
                                    NotApplicable = 0
                                    NotAFinding   = 0
                                    NotReviewed   = 0
                                    Category      = $Cat
                                })
                        }
                        $Categories[$Cat].UniqueTotal += 1

                    }
                    #Track it
                    if ($Stig.Status -eq "Open") {
                        $IndividualStigs[$Stig.VulnID].Open++

                        $Categories[$Cat].Open += 1

                    } elseif ($Stig.Status -eq "Not_Applicable") {
                        $IndividualStigs[$Stig.VulnID].NotApplicable++

                        $Categories[$Cat].NotApplicable += 1

                    } elseif ($Stig.Status -eq "NotAFinding") {
                        $IndividualStigs[$Stig.VulnID].NotAFinding++

                        $Categories[$Cat].NotAFinding += 1

                    } elseif ($Stig.Status -eq "Not_Reviewed") {
                        $IndividualStigs[$Stig.VulnID].NotReviewed++

                        $Categories[$Cat].NotReviewed += 1

                    }
                }
                $processed++

            }
            Write-Progress -Activity "Finalizing Data" -PercentComplete 100
            #Looks odd but cleans up the output
            $IndividualScores = @()
            foreach ($Value in $IndividualStigs.Values) {
                if ($Value.Open) {
                    $status = "Open"
                } elseif ($Value.NotApplicable) {
                    $status = "NotApplicable"
                } elseif ($Value.NotAFinding) {
                    $status = "NotAFinding"
                } elseif ($Value.NotReviewed) {
                    $status = "NotReviewed"
                }
                $IndividualScores += [PSCustomObject]@{
                    FileName = $file.BaseName
                    VulnID   = $Value.VulnID
                    Status   = $status
                }
            }
            $FindingScores = [PSCustomObject]@{
                FileName      = $file.BaseName
                Open          = $Open
                NotApplicable = $NA
                NotAFinding   = $NAF
                NotReviewed   = $NR
                Total         = $Open + $NAF + $NA + $NR
            }
            Write-Progress -Activity "Finalizing Data" -PercentComplete 100 -Completed
            #return the output
            [PSCustomObject]@{
                FileName             = $file.BaseName
                TotalFindingScores   = $FindingScores
                IndividualVulnScores = $IndividualScores
                CategoryScores       = $Categories
            }
        }
    }
}