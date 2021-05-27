function Get-StigInfoAttribute {
    <#
    .SYNOPSIS
        Gets a stig info attribute

    .DESCRIPTION
        Gets a stig info attribute, literally value of a "SI_DATA" under the "STIG_INFO" elements from the XML data of the CKL. This contains general information on the STIG file itself. (Version, Date, Name)

    .PARAMETER FilePath
        Path to checklist file

    .PARAMETER Attribute
        The Attribute you wish to query.

    .EXAMPLE
        Get-StigInfoAttribute -FilePath C:\temp\output\WORKSTATION_U_Windows_Firewall_STIG_V1R7.ckl -Attribute "Version"
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateScript( { Test-Path -Path $PSItem })]
        [Alias("FullName")]
        [string[]]$FilePath,
        [Parameter(Mandatory)]
        [psobject]$Attribute
    )
    process {
        foreach ($file in $FilePath) {
            $CKLData = Import-StigCKL $file
            if ($Attribute) {
                $results = (Select-XML -Xml $CKLData -XPath "//SI_DATA[SID_NAME = '$Attribute']").Node.SID_DATA
            } else {
                Write-Error "Attribute must be set!"
            }

            if (-not $results) {
                Write-Error "Specified attribute ($Attribute) was not found"
            } else {
                $results
            }
        }
    }
}