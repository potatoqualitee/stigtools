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
        Write-Progress -Activity "Converting" -PercentComplete 0
        $completedcount = 0
        $files = Get-ChildItem -Path $Path
        if (-not $PSBoundParameters.Name) {
            $Name = (Get-ChildItem -Path $TemplatePath).BaseName.Replace("_Manual-xccdf","")
        }

        foreach ($file in $files) {
            $xml = [xml](Get-Content -Path $file.FullName)
            $hosts = $xml.NessusClientData_v2.Report.ReportHost
            foreach ($device in $hosts) {
                $allitems = @()
                $ckldata = Import-StigCKL -Path $TemplatePath
                $hostname = ($device.HostProperties.tag | Where-Object Name -eq 'host-fqdn').'#text'
                if (-not $hostname) {
                    $hostname = ($device.HostProperties.tag | Where-Object Name -eq 'host-ip').'#text'
                }
                if (-not $hostname) {
                    $hostname = $device.name
                }
                $reports = $device.ReportItem | Where-Object PluginFamily -eq "Policy Compliance"

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

                    if (-not $vulnid) {
                        continue
                    }

                    $allitems += [PSCustomObject]@{
                        CKLData  = $ckldata
                        VulnID   = $vulnid
                        Details  = $details
                        Comments = $comments
                        Result   = $result
                    }
                }

                $groups = $allitems | Group-Object VulnID

                foreach ($group in $groups) {
                    if ($group.count -eq 1) {
                        $params = @{
                            CKLData  = $group.Group.ckldata
                            VulnID   = $group.Group.vulnid
                            Details  = $group.Group.details
                            Comments = $group.Group.comments
                            Result   = $group.Group.result
                        }
                        Write-Verbose "Writing $($group.Name)"
                        Set-VulnCheckResult @params
                    } else {
                        # V-41047 should be open
                        if ($group.Group.Result -contains "Open") {
                            $result = "Open"
                        } elseif ($group.Group.Result -contains "NotAFinding") {
                            $result = "NotAFinding"
                        } else {
                            $result = "Not_Reviewed"
                        }
                        $details = $group.Group.Details -join "`n"
                        $comments = $group.Group.Comments -join "`n"
                        $params = @{
                            CKLData  = $ckldata
                            VulnID   = $group.Name
                            Details  = $details
                            Comments = $comments
                            Result   = $result
                        }
                        Set-VulnCheckResult @params
                    }
                }
                $completedcount++
                Write-Progress -Activity "Converting $filename for $hostname" -PercentComplete (($completedcount * 100) / $files.Count)
                $newfilename = Join-Path -Path $Destination -ChildPath "$($xml.NessusClientData_v2.Report.name)-$hostname.ckl"
                Export-StigCKL -XMLData $ckldata -Path $newfilename
                Get-ChildItem -Path $newfilename
            }
        }
        Write-Progress -Activity "Converting" -PercentComplete 100 -Completed
    }
}