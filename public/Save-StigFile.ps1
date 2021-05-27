function Save-StigFile {
<#
    .SYNOPSIS
        Saves STIG benchmark files

    .DESCRIPTION
        Saves STIG benchmark files. Accepts pipeline input

    .PARAMETER Uri
        Uri to file. Accepts pipeline input

    .PARAMETER Path
        Path to save file

    .EXAMPLE
        PS C:\> Save-StigFile

        Save a stig file

    .EXAMPLE
        PS C:\> Get-StigFile -Pattern sql | Save-StigFile

        Saves stig files matching sql

#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string[]]$Uri,
        [Parameter(Mandatory)]
        [string]$Path
   )
    process {
        try {
            foreach ($resource in $Uri) {
                $filename = Split-Path -Path $resource -Leaf
                Invoke-WebRequest -Uri $resource -OutFile (Join-Path -Path $Path -ChildPath $filename) -ErrorAction Stop
                Get-ChildItem -Path (Join-Path -Path $Path -ChildPath $filename) -ErrorAction Stop
            }
        } catch {
            throw $PSItem
        }
    }
}