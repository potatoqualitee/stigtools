function Set-CKLHostData {
    <#
    .SYNOPSIS
        Sets host data in CKL. If any parameters are blank, they will be set to running machine

    .PARAMETER CKLData
        CKL Data as loaded by Import-StigCKL

    .PARAMETER Hostname
        Short host name

    .PARAMETER FQDN
        Fully qualified domain name

    .PARAMETER Mac
        Mac of the host

    .PARAMETER IP
        IP address of the host

    .PARAMETER TargetComments
        TargetComments of the host

    .PARAMETER TargetCommentsFromAD
        Fills target comments from the machines AD description, if exists and found.

    .PARAMETER IsWebOrDB
        Manually selects the Web or DB STIG setting. This is auto-set to true if webdbsite or webdbinstance is provided while this is $null

    .PARAMETER WebDBSite
        Sets the web or db site STIG for the CKL. Will autoset IsWebOrDB to true if this is provided and IsWebOrDB is not.

    .PARAMTER WebDBInstance
        Sets the web or db instance STIG for the CKL. Will autoset IsWebOrDB to true if this is provided and IsWebOrDB is not.

    .EXAMPLE
        Set-CKLHostData -CKLData $CKLData -AutoFill

    .EXAMPLE
        Set-CKLHostData -CKLData $CKLData -Hostname workstation -FQDN workstation.Some.Domain.com" -Mac "00-00-00-..." -IP 127.0.0.1
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [Alias("XMLData")]
        [xml]$CKLData,
        [string]$Hostname,
        [string]$FQDN,
        [string]$Mac,
        [string]$IP,
        [string]$TargetComments,
        [string]$WebDBSite,
        [string]$WebDBInstance,
        [bool]$IsWebOrDB,
        [ValidateSet("None", "Workstation", "Member Server", "Domain Controller", $null)]
        [string]$Role,
        [switch]$AutoFill,
        [switch]$TargetCommentsFromAD
    )
    process {
        if ($AutoFill) {
            if (-not $Hostname) {
                $Hostname = (Get-CimInstance -Class Win32_ComputerSystem).Name
            }
            if (-not $FQDN) {
                $FQDN = (Get-CimInstance -Class Win32_ComputerSystem -ComputerName $Hostname).Name + (Get-CimInstance -Class Win32_ComputerSystem -ComputerName $Hostname).Domain
            }
            if (-not $Mac) {
                $Mac = (@() + (Get-CimInstance win32_networkadapterconfiguration -ComputerName $Hostname | Where-Object -FilterScript { $PSItem.IPAddress }))[0].Macaddress
            }
            if (-not $IP) {
                $IP = (@() + (Get-CimInstance win32_networkadapterconfiguration -ComputerName $Hostname | Where-Object -FilterScript { $PSItem.IPAddress }))[0].IPAddress[0]
            }
            if (-not $Role) {
                $Role = "None"
                $PType = (Get-CimInstance -Class Win32_OperatingSystem -Property ProductType -ComputerName $Hostname).ProductType
                if ($PType -eq 1) {
                    $Role = "Workstation"
                }
                if ($PType -eq 3) {
                    $Role = "Member Server"
                }
                if ($PType -eq 2) {
                    $Role = "Domain Controller"
                }
            }
        }
        if ($TargetCommentsFromAD -and -not $TargetComments) {
            $ComputerData = Get-ADComputer -Identity $Computer -Properties Description -ErrorAction SilentlyContinue
            if ($ComputerData) {
                $TargetComments = $ComputerData.Description
            }
        }
        #Set the various properties
        if ($Hostname) {
            $CKLData.CHECKLIST.ASSET.HOST_NAME = $Hostname
        }
        if ($FQDN) {
            $CKLData.CHECKLIST.ASSET.HOST_FQDN = $FQDN
        }
        if ($IP) {
            $CKLData.CHECKLIST.ASSET.HOST_IP = $IP
        }
        if ($Mac) {
            $CKLData.CHECKLIST.ASSET.HOST_MAC = $Mac
        }
        if ($Role) {
            $CKLData.CHECKLIST.ASSET.ROLE = $Role
        }
        if ($TargetComments) {
            $CKLData.CHECKLIST.ASSET.TARGET_COMMENT = $TargetComments
        }
        if ($IsWebOrDB -eq $null -and ($WebDBSite -or $WebDBInstance)) {
            $CKLData.CHECKLIST.ASSET.WEB_OR_DATABASE = "true"
        } elseif ($IsWebOrDB) {
            $CKLData.CHECKLIST.ASSET.WEB_OR_DATABASE = $IsWebOrDB.ToString().ToLower()
        }
        if ($WebDBSite) {
            $CKLData.CHECKLIST.ASSET.WEB_DB_SITE = $WebDBSite
        }
        if ($WebDBInstance) {
            $CKLData.CHECKLIST.ASSET.WEB_DB_INSTANCE = $WebDBInstance
        }
    }
}