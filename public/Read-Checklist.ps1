function Read-Checklist {
    <#
    .SYNOPSIS
        Reads a checklist file

    .PARAMETER Path
        Full file path to the checklist File

    .EXAMPLE
        Read-Checklist -Path C:\temp\output\winserver_U_Windows_Firewall_STIG_V1R7.ckl

        Reads C:\temp\output\winserver_U_Windows_Firewall_STIG_V1R7.ckl

    .EXAMPLE
        Get-ChildItem C:\temp\output | Read-Checklist

        Reads all checklists in C:\temp\output
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [Alias("FullName")]
        [psobject[]]$Path
    )
    process {
        if (-not $Path.FullName) {
            $files = Get-ChildItem -Path $Path -Filter *.ckl
        } else {
            $files = $Path
        }
        try {
            foreach ($file in $files) {
                $xml = [xml](Get-Content -Path $file.FullName -Raw -Encoding UTF8)
                $output = @{}
                $computer = $xml.Checklist.Asset
                $sidata = $xml.Checklist.Stigs.iSTIG.STIG_INFO.SI_DATA
                $vulns = $xml.Checklist.Stigs.iSTIG.Vuln

                $output.ComputerName = $computer.HOST_NAME
                $output.HostIP = $computer.HOST_IP
                $output.ComputerObject = $computer
                $output.Classifcation = ($sidata | Where-Object SID_Name -eq classification).SID_DATA
                $output.FileName = ($sidata | Where-Object SID_Name -eq filename).SID_DATA
                $output.Description = ($sidata | Where-Object SID_Name -eq description).SID_DATA
                $output.ReleaseInfo = ($sidata | Where-Object SID_Name -eq releaseinfo).SID_DATA
                $output.Title = ($sidata | Where-Object SID_Name -eq title).SID_DATA

                $allvulns = @()
                foreach ($vuln in $vulns) {
                    $currentcount = 0
                    $data = $vuln.STIG_DATA

                    1..$($data.Count / 25) | ForEach-Object {
                        $object = @{
                            Status = $vuln.STATUS
                            Comments = $vuln.COMMENTS
                            Finding  = $vuln.FINDING_DETAILS
                        }
                        1..25 | ForEach-Object {
                            $currentcount++
                            $index = $currentcount
                            $item = $data[$index]
                            $name = $item.VULN_ATTRIBUTE
                            if ($name) {
                                $name = $name.Replace("_","").Replace(" ","")
                                $object.$name = $item.ATTRIBUTE_DATA.ToString().Trim().TrimEnd("`n")

                                if ($name -eq "RuleID") {
                                    $vulnid = $item.ATTRIBUTE_DATA.ToString().Trim()
                                    $vulnid = $vulnid.TrimStart("S").Split("r") | Select-Object -First 1
                                    $object.VulnID = $vulnid
                                }
                            }
                        }
                        $allvulns += [pscustomobject]$object
                    }
                }
                $output.Vulns = $allvulns
                [pscustomobject]$output | Select-Object ComputerName, HostIP, ComputerObject, Classifcation, FileName, Description, ReleaseInfo, Title, Vulns
            }
        } catch {
            Write-Warning -Message "Can't process $file`: $PSItem"
        }
    }
}