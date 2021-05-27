function Merge-XCCDFHostDataToCKL {
    <#
    .SYNOPSIS
        Adds XCCDF host info into a loaded CKL data

    .PARAMETER CKLData
        CKL Data as loaded by Import-StigCKL

    .PARAMETER XCCDF
        XCCDF data as loaded from the Import-XCCDF

    .EXAMPLE
        Merge-XCCDFHostDataToCKL -CKLData $CKLData -XCCDF $XCCDFData
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [Alias("XMLData")]
        [xml]$CKLData,
        [Parameter(Mandatory)]
        [xml]$XCCDF
    )
    process {
        #Get machine info
        $MachineInfo = Get-XCCDFHostData -XCCDF $XCCDF
        #Add it to CKL
        Set-CKLHostData -CKLData $CKLData -Host $MachineInfo.HostName -IP $MachineInfo.HostIP -Mac $MachineInfo.HostMAC -FQDN $MachineInfo.HostFQDN
    }
}