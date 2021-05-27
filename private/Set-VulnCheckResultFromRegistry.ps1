function Set-VulnCheckResultFromRegistry {
    <#
    .SYNOPSIS
        Sets a vuln status based on a registry check

    .PARAMETER CKLData
        CKL Data as loaded by Import-StigCKL

    .PARAMETER VulnID
        ID Of the STIG check to set

    .PARAMETER RegKeyPath
        Path to the registry key

    .PARAMETER RequiredKey
        Key name

    .PARAMETER RequiredValue
        Value the key should be to pass check

    .PARAMETER Comments
        Value to set Comments to

    .EXAMPLE
        Set-VulnCheckResultFromRegistry -CKLData $CKLData -RegKeyPath "HKLM:\SOFTWARE\COMPANY\DATA" -RequiredKey "PortStatus" -RequiredValue "Closed" -Comments "Checked by asdf"
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$VulnID,
        [Parameter(Mandatory)]
        [string]$RegKeyPath,
        [Parameter(Mandatory)]
        [string]$RequiredKey,
        [Parameter(Mandatory)]
        [string]$RequiredValue,
        [Parameter(Mandatory, ValueFromPipeline)]
        [Alias("XMLData")]
        [xml]$CKLData,
        [string]$Comments
    )
    process {
        if (-not $PSBoundParameters.Comments) {
            $Comments = " "
        }

        if (Test-Path -Path $RegKeyPath) {
            $properties = Get-ItemProperty -Path $RegKeyPath
            if ($properties.$RequiredKey -eq $RequiredValue) {
                $details = "Required key $RequiredKey is " + $RequiredValue.ToString()
                Set-VulnCheckResult -CKLData $CKLData -VulnID $VulnID -Details $details -Comments $Comments -Result NotAFinding
            } else {
                $details = "Required key $RequiredKey is "
                if (-not $properties.$RequiredKey) {
                    $details += "null"
                } else {
                    $details += $properties.$RequiredKey.ToString()
                }
                Set-VulnCheckResult -CKLData $CKLData -VulnID $VulnID -Details $details -Comments $Comments -Result Open
            }
        } else {
            $details = "Required key path $RegKeyPath does not exist"
            Set-VulnCheckResult -CKLData $CKLData -VulnID $VulnID -Details $details -Comments $Comments -Result Open
        }
    }
}