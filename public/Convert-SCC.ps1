function Convert-SCC {
    <#
    .SYNOPSIS
        Converts SCC results to CKL files using the STIG Library

    .DESCRIPTION
        Converts SCC results to CKL files using the STIG Library. Download the STIG Library using Save-STIGLibrary

    .PARAMETER LibraryPath
        Full path to the root of the STIG Library

    .PARAMETER ResultsPath
        Path to the SCC results

    .PARAMETER Destination
        Path to a folder to save the new CKL files

    .EXAMPLE
        Convert-SCC -LibraryPath C:\temp\stigs -ResultsPath $home\SCC\Sessions\2021-05-20_125120 -Destination C:\temp\output
    #>
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateScript({ Test-Path -Path $PSItem })]
        [Alias("FullName")]
        [string[]]$ResultsPath,
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path $PSItem })]
        [string]$LibraryPath,
        [string]$Destination
    )
    begin {
        function Get-Name {
            param(
                [string]$FileName,
                [int]$First
            )
            process {
                $name = $FileName -Split "_" | Select-Object -First $First
                if ($name -match "-") {
                    $name = "$name" -Split "-" | Select-Object -First 1
                }
                # fix internet explorer
                ($name -join "_").Replace("IE_", "IE").Replace("Windows Firewall","Windows_Firewall")
            }
        }
    }
    process {
        $stigfiles = Get-ChildItem -Path $LibraryPath -Recurse -Filter "*Manual-xccdf.xml"
        $results = Get-ChildItem -Path $ResultsPath -Recurse -Filter "*XCCDF-Results*"

        foreach ($result in $results) {
            $filename = $result.BaseName -Split "XCCDF-Results_" | Select-Object -First 1 -Skip 1

            # First try with 3 words
            $name = Get-Name -Filename $filename -First 3
            $stig = $stigfiles | Where-Object FullName -match $name
            if (-not $stig) {
                $name = Get-Name -Filename $filename -First 2
                $stig = $stigfiles | Where-Object FullName -match $name
                if (-not $stig) {
                    Write-Warning "Couldn't find the matching stig file $name"
                    continue
                }
            }

            $ckl = Convert-ManualXCCDF -Path $stig.FullName -Destination (New-TempDirectory).FullName | Select-Object -First 1
            $params = @{
                TemplatePath    = $ckl.FullName
                Path            = $result.FullName
                Destination     = $Destination
                WarningAction   = "SilentlyContinue"
                ErrorAction     = "SilentlyContinue"
                ErrorVariable   = "converterror"
            }

            Convert-XCCDF @params

            foreach ($item in ($converterror | Sort-Object -Unique)) {
                Write-Warning -Message "Error for $($name): $item"
            }
        }
    }
}