function Get-ChecklistInfo {
    <#
    .SYNOPSIS
        Gets general info from the checklist (Release, Title, Description)

    .PARAMETER FilePath
        Path to checklist file

    .EXAMPLE
        Get-ChecklistInfo -FilePath C:\temp\output\WORKSTATION_U_Windows_Firewall_STIG_V1R7.ckl

        Gets general info from C:\temp\output\WORKSTATION_U_Windows_Firewall_STIG_V1R7.ckl

    .EXAMPLE
        Get-ChildItem C:\temp\checklists | Get-ChecklistInfo

        Gets general info from C:\temp\output\WORKSTATION_U_Windows_Firewall_STIG_V1R7.ckl
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateScript( { Test-Path -Path $PSItem })]
        [Alias("FullName")]
        [psobject[]]$FilePath
    )
    process {
        foreach ($file in $FilePath) {
            $CKLData = Import-StigCKL -Path $file
            [PSCustomObject]@{
                FileName    = $file.BaseName
                Title       = (Get-StigInfoAttribute -CKLData $CKLData -Attribute "title")
                Description = (Get-StigInfoAttribute -CKLData $CKLData -Attribute "description")
                Release     = (Get-StigInfoAttribute -CKLData $CKLData -Attribute "releaseinfo")
                ID          = (Get-StigInfoAttribute -CKLData $CKLData -Attribute "stigid")
            }
        }
    }
}