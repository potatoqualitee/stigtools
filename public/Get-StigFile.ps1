function Get-StigFile {
    <#
    .SYNOPSIS
        Pulls list of STIG benchmarks and their download links

    .DESCRIPTION
        Pulls list of STIG benchmarks and their download links

    .EXAMPLE
        PS C:\> Get-StigLink

        Get links for all stig files

    .EXAMPLE
        PS C:\> Get-StigLink -Pattern sql

        Get links for all stig files matching the term "sql"

#>
    [CmdletBinding()]
    param (
        [parameter(ValueFromPipeline)]
        [string]$Pattern
    )
    begin {
        function Get-StigFileLink {
            # Thank you Joseph Warren
            $StigLibrary = Invoke-WebRequest -Uri 'https://public.cyber.mil/stigs/downloads/' -UseBasicParsing
            foreach ($Stig in $StigLibrary.links) {
                if ($Stig.href -like "*/zip/*") {

                    [string]$Name = (($Stig.outerHTML) | ForEach-Object { [regex]::matches( $_ , '(?<=</span>\s+)(.*?)(?=\s+</a>)' ) } | Select-Object -ExpandProperty value).trim()
                    [int]$Version = (($Name) | ForEach-Object { [regex]::matches( $_ , '(?<=Ver\s+)(\d+)' ) } | Select-Object -ExpandProperty value)
                    [int]$Release = (($Name) | ForEach-Object { [regex]::matches( $_ , '(?<=,\s+Rel\s+)(\d+)' ) } | Select-Object -ExpandProperty value) #.trim()
                    [string]$Date = $null#(($Stig.outerHTML) | ForEach-Object { [regex]::matches( $_ , '(?<=<td class="updated_column">\s+)(.*?)(?=\s+</span>)' ) } | Select-Object -ExpandProperty value) #-replace "<span style=""display:none;"">",""

                    [PSCustomObject]@{
                        Name    = $Name -replace '[^ -x7e]', ''
                        URI     = $Stig.href
                        Version = $Version
                        Release = $Release
                        Date    = $Date
                    }
                }
            }
        }
    }
    process {
        try {
            $results = Get-StigFileLink -ErrorAction Stop | Select-Object -Property * -ExcludeProperty Date
            if ($Pattern) {
                $results | Where-Object Name -match $Pattern
            } else {
                $results
            }
        } catch {
            throw $PSItem
        }
    }
}