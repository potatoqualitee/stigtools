function Get-ChecklistHostData {
    <#
    .SYNOPSIS
        Gets the host information from the CKLData

    .PARAMETER FilePath
        Path to checklist file

    .EXAMPLE
        Get-ChecklistHostData -FilePath C:\temp\output\WORKSTATION_U_Windows_Firewall_STIG_V1R7.ckl

        Gets host data from C:\temp\output\WORKSTATION_U_Windows_Firewall_STIG_V1R7.ckl

    .EXAMPLE
        Get-ChildItem C:\temp\checklists | Get-ChecklistHostData

        Gets host data from C:\temp\output\WORKSTATION_U_Windows_Firewall_STIG_V1R7.ckl
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
                FileName = $file.BaseName
                HostName = $CKLData.CHECKLIST.ASSET.HOST_NAME
                HostIP   = $CKLData.CHECKLIST.ASSET.HOST_IP
                HostMAC  = $CKLData.CHECKLIST.ASSET.HOST_MAC
                HostGUID = $CKLData.CHECKLIST.ASSET.HOST_GUID
                HostFQDN = $CKLData.CHECKLIST.ASSET.HOST_FQDN
                Role     = $CKLData.CHECKLIST.ASSET.ROLE
            }
        }
    }
}