function Save-StigLibrary {
    <#
    .SYNOPSIS
        Downloads and extracts the NON-FOUO STIG Library

    .DESCRIPTION
        Downloads and extracts the NON-FOUO STIG Library

    .PARAMETER Staging
        The directory the library will be downloaded and extracted to.

    .PARAMETER Path
        Path to a directory. If set, this script will also extract the stig library to this location. This allows you to use the script to also maintain an up-to-date repository of stigs

    .PARAMETER Uri
        URL to the STIG Library to download (Defaults to the assumed location of the current NON-FOUO library)

    .EXAMPLE
        Save-StigLibrary -Path C:\temp\newstigs

        Saves and unzips the newest stig library to C:\temp\newstigs
#>
    [CmdletBinding()]
    param(
        [parameter(Mandatory)]
        [string]$Path,
        [uri]$Uri
    )
    process {
        if (-not (Test-Path -Path $Path)) {
            $null = New-Item -Type Directory -Path $Path
        }

        $zip = Join-Path -Path $Path -ChildPath library.zip

        if ($PSBoundParameters.Uri) {
            $null = Invoke-WebRequest -Uri $Uri -OutFile $zip -ErrorAction Stop
        } else {
            Write-Verbose "Using automatic search for STIG library"
            Write-Warning "This will take a moment..."

            try {
                $ProgressPreference = "SilentlyContinue"
                $page = Invoke-WebRequest -UseBasicParsing -Uri https://public.cyber.mil/stigs/compilations/ -ErrorAction Stop
                $Uri = $page.Links | Where-Object href | Select-Object -ExpandProperty href | Where-Object { $PSItem -match "STIG_Lib" -and $PSitem.EndsWith(".zip") }
                $null = Invoke-WebRequest -Uri $Uri -OutFile $zip -ErrorAction Stop
            } catch {
                throw "Failed to download library, 404, please specify the direct path to the latest library"
            }
        }

        #Extract it to the staging directory
        try {
            Write-Verbose "Extracting library to $Path"
            $null = Expand-Archive -Path $zip -DestinationPath $Path -ErrorAction Stop -Force
            $null = Remove-Item $zip
        } catch {
            throw "Failed to unzip the library $PSItem"
        }

        $zipfiles = Get-ChildItem -Path $Path -Filter "*.zip" -Recurse
        foreach ($zipfile in $zipfiles) {
            $basename = $zipfile.BaseName
            $newdir = New-Item -Type Directory -Path (Join-Path -Path $Path -ChildPath $basename)
            $null = Expand-Archive -Path $zipfile.FullName -DestinationPath $newdir -Force
            $null = $zipfile | Remove-Item
        }
        Get-ChildItem $Path
    }
}