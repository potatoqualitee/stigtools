function New-ScapMap {
    <#
.SYNOPSIS
    Automatically builds the SCAP Mapping JSON file as required by Start-CSUpdate.ps1
#>
    [CmdletBinding()]
    Param
    (
        $Staging = "C:\Users\Public\Staging",
        [Parameter(Mandatory)]$CKLDirectory,
        [Parameter(Mandatory)]$ScapRepository
    )
    process {
        #Ensure we have pre-req module imported
        if ((Get-Module | Where-Object -FilterScript { $_.Name -eq "StigSupport" }).Count -le 0) {
            Write-Error "Please import StigSupport.psm1 before running this script"
            exit 1
        }

        #Library Paths
        $LibraryPath = "$Staging\Library"
        $SubLibraryPath = $LibraryPath + "\STIGS"

        #Cache files
        $ScapFiles = Get-ChildItem -Path $ScapRepository -Filter "*Benchmark.xml" -Recurse
        $ManualFiles = Get-ChildItem -Path $SubLibraryPath -Filter "*manual-xccdf.xml" -Recurse

        #Create initial table based on the manual files, as this is a hard requirement
        $MappingTable = @{
        }
        foreach ($ManualFile in $ManualFiles) {
            $ManualXCCDF = Import-XCCDF -Path $ManualFile.FullName
            if ($ManualXCCDF) {
                $ManualData = Get-XCCDFInfo -XCCDF $ManualXCCDF
                if ($ManualData.Title -and $ManualData.Title -ne "" -and -not $MappingTable.ContainsKey($ManualData.Title) -and $ManualData.ID -and $ManualData.ID -ne "") {
                    $MappingTable += @{
                        $ManualData.Title = [PSCustomObject]@{
                            SCAP   = ""
                            Manual = $ManualFile.Name.Replace(".","\.")
                            ID     = $ManualData.ID
                        }
                    }
                } else {
                    Write-Verbose "Skipping $($ManualFile.FullName) as it did not have required info"
                }
            } else {
                Write-Warning "Skipping $($ManualFile.FullName) as it could not be loaded"
            }
        }

        #Then add scap files where possible
        foreach ($ScapFile in $ScapFiles) {
            $BenchmarkData = Import-XCCDF -Path $ScapFile.FullName
            $BenchmarkXCCDF = $BenchmarkData.'data-stream-collection'.component | Where-Object { $_.id -like "*Benchmark-xccdf.xml" }
            $BenchmarkTitle = $BenchmarkXCCDF.Benchmark.title
            if ($BenchmarkTitle -ne "" -and $BenchmarkTitle -and $MappingTable.ContainsKey($BenchmarkTitle)) {
                $MappingTable[$BenchmarkTitle].SCAP = $ScapFile.Name.Replace(".","\.")
            }
        }

        $MappingTable.Values | ConvertTo-Json | Out-File (Join-Path -Path $ScapRepository -ChildPath "ScapMappings.json")
    }
}