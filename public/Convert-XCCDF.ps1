function Convert-XCCDF {
    <#
    .SYNOPSIS
        Converts a SCAP XCCDF File to a CKL file

    .DESCRIPTION
        Loads a set of XCCDF files and saves them as checklists in the format of a given a template file

    .PARAMETER TemplatePath
        Full path to the CKL file. This file should be blank, or only contain answers that are not included in the XCCDF file

    .PARAMETER Name
        Optional name for Stig file, otherwise, it's built off of the hostname and checklist

    .PARAMETER Path
        Path to a folder containing the XCCDF files to convert. Will automatically be set to the user's profile\scc\results\scap directory (Default SCAP Directory)

    .PARAMETER Destination
        Path to a folder to save the new CKL files

    .EXAMPLE
        $params = @{
            TemplatePath = "C:\CKLs\U_WINDOWS_SERVER_2012_R2.ckl"
            Path = "C:\Users\John.Doe\SCC\Results\SCAP"
            Destination = "C:\Users\John.Doe\Scap Results"
        }
        Convert-XCCDF @params
    #>
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path $PSItem })]
        [string]$TemplatePath,
        [string]$Name,
        [Parameter(ValueFromPipeline)]
        [ValidateScript({ Test-Path -Path $PSItem })]
        [Alias("FullName")]
        [string[]]$Path,
        [string]$Destination
    )
    process {
        if (-not $Path) {
            $Path = Get-ChildItem -Path (Join-Path -Path $home -ChildPath scc) -Recurse -Include *Results* -Directory | Sort-Object -Descending | Select-Object -First 1
        }
        Write-Progress -Activity "Converting" -PercentComplete 0
        $completedcount = 0
        $files = Get-ChildItem -Path $Path -Recurse -Filter "*XCCDF*$Name*.xml"
        if (-not $PSBoundParameters.Name) {
            $Name = (Get-ChildItem -Path $TemplatePath).BaseName.Replace("_Manual-xccdf","")
        }
        foreach ($file in $files) {
            $filename = $file.FullName
            #Load CKL, Load XCCDF, Fill CKL based on XCCDF, then save to a new CKL with name of [machinename]_[Name].ckl
            $CKL = Import-StigCKL -Path $TemplatePath
            $XCCDF = Import-XCCDF -Path $filename
            $null = Merge-XCCDFToCKL -CKLData $CKL -XCCDF $XCCDF
            $MachineInfo = Get-XCCDFHostData -XCCDF $XCCDF
            $cklpath = Join-Path -Path $Destination -ChildPath "$($MachineInfo.HostName)_$Name.ckl"
            $null = Export-StigCKL -Path $cklpath -XMLData $CKL
            $completedcount++
            Write-Progress -Activity "Converting $filename" -PercentComplete (($completedcount * 100) / $files.Count)
            Get-ChildItem -Path $cklpath
        }
        Write-Progress -Activity "Converting" -PercentComplete 100 -Completed
    }
}