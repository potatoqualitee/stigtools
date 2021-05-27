function Export-StigCKL {
<#
    .SYNOPSIS
        Saves a loaded CKL file to disk

    .PARAMETER CKLData
        The loaded CKL Data as loaded by Import-StigCKL

    .PARAMETER Path
        Full path to the CKL file

    .PARAMETER AddHostData
        Automatically adds the running hosts information into the CKL before saving

    .EXAMPLE
        Export-StigCKL -CKLData $CKLData -Path "C:\CKLs\MyCKL.ckl"

    .EXAMPLE
        Export-StigCKL -CKLData $CKLData -Path "C:\CKLs\MyCKL.ckl" -AddHostData
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [Alias("XMLData")]
        [xml]$CKLData,
        [Parameter(Mandatory)]
        [string]$Path,
        [switch]$AddHostData
    )
    process {
        #Set XML Options to replicate those of the STIG Viewer application
        $XMLSettings = New-Object -TypeName System.XML.XMLWriterSettings
        $XMLSettings.Indent = $true
        $XMLSettings.IndentChars = "`t"
        $XMLSettings.NewLineChars = "`n"
        $XMLSettings.Encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList @($false)
        $XMLSettings.ConformanceLevel = [System.Xml.ConformanceLevel]::Document

        #Add Host data if requested
        if ($AddHostData) {
            $null = Set-CKLHostData -CKLData $CKLData -AutoFill
        }
        $XMLWriter = [System.XML.XmlWriter]::Create($Path, $XMLSettings)
        $CKLData.Save($XMLWriter)
        $XMLWriter.Flush()
        $XMLWriter.Dispose()
    }
}
