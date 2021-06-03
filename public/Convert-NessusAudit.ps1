function Convert-NessusAudit {
    <#
    .SYNOPSIS
        Converts Nessus audit result files to a CKL file

    .DESCRIPTION
        Loads a set of audit files and saves them as checklists in the format of a given a template file

    .PARAMETER TemplatePath
        Full path to the CKL file. This file should be blank, or only contain answers that are not included in the XCCDF file

    .PARAMETER Name
        Optional name for Stig file, otherwise, it's built off of the hostname and checklist

    .PARAMETER Path
        Path to a folder containing the audit files to convert. Will automatically be set to the user's profile\scc\results\scap directory (Default SCAP Directory)

    .PARAMETER Destination
        Path to a folder to save the new CKL files

    .EXAMPLE
        $params = @{
            TemplatePath = "$home\Downloads\U_MS_SQL_Server_Instance_2012_V1R20_Manual_STIG.ckl"
            Path = "$home\Downloads\DISA STIG MSSQL 2012 Instance-OS v1r20\2.nessus"
            Destination = "C:\temp"
        }
        Convert-NessusAudit @params


    .EXAMPLE
        $params = @{
            TemplatePath = "$home\Downloads\win10\win10.ckl"
            Path = "$home\Downloads\win10\1.nessus"
            Destination = "$home\Downloads\win10"
        }
        Convert-NessusAudit @params

    .EXAMPLE
        $params = @{
            TemplatePath = "$home\Downloads\esx\esx.ckl"
            Path = "$home\Downloads\esx\1.nessus"
            Destination = "$home\Downloads\esx"
        }
        Convert-NessusAudit @params
    #>
    param(
        [Parameter(Mandatory)]
        [ValidateScript( { Test-Path -Path $PSItem })]
        [string]$TemplatePath,
        [string]$Name,
        [Parameter(ValueFromPipeline, Mandatory)]
        [ValidateScript( { Test-Path -Path $PSItem })]
        [Alias("FullName")]
        [string[]]$Path,
        [string]$Destination
    )
    process {
        $ckldata = Import-StigCKL -Path $TemplatePath

        Write-Progress -Activity "Converting" -PercentComplete 0
        $completedcount = 0
        $files = Get-ChildItem -Path $Path
        if (-not $PSBoundParameters.Name) {
            $Name = (Get-ChildItem -Path $TemplatePath).BaseName.Replace("_Manual-xccdf","")
        }

        foreach ($file in $files) {
            $xml = [xml](Get-Content -Path $file.FullName)
            $reports = $xml.NessusClientData_v2.Report.ReportHost.ReportItem | Where-Object PluginFamily -eq "Policy Compliance"
            Write-Verbose "Processing $($reports.count) results"
            foreach ($report in $reports) {
                $initialresult = $report.'compliance-result'
                #"Open","NotAFinding","Not_Reviewed", "Not_Applicable"
                $result = switch ($initialresult) {
                    "PASSED" { "NotAFinding" }
                    "FAILED" { "Open" }
                    "WARNING" { "Not_Reviewed" }
                    "ERROR" { "Not_Reviewed" }
                }

                $details = $report.'compliance-actual-value'
                $comments = $report.'compliance-policy-value'
                $vulnid = $report.'compliance-reference' -Split '\|' | Select-Object -Last 1

                if ($vulnid -eq "V-41047") {
                    # ADD SUPPORT FOR DUPES
                    # ADD SUPPORT FOR HOST NAMES
                    write-warning $result
                }
                $params = @{
                    CKLData  = $ckldata
                    VulnID   = $vulnid
                    Details  = $details
                    Comments = $comments
                    Result   = $result
                }
                if ($vulnid) {
                    Write-Verbose "Writing $vulnid"
                    Set-VulnCheckResult @params
                } else {
                    $report.'compliance-reference' | Out-Host
                }
            }
            $completedcount++
            Write-Progress -Activity "Converting $filename" -PercentComplete (($completedcount * 100) / $files.Count)
            $newfilename = Join-Path -Path $Destination -ChildPath "$((Get-ChildItem -Path $TemplatePath).BaseName)-$($file.BaseName).ckl"
            Export-StigCKL -XMLData $ckldata -Path $newfilename
            Get-ChildItem -Path $newfilename
        }
        Write-Progress -Activity "Converting" -PercentComplete 100 -Completed
    }
}