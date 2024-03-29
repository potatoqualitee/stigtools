#
# Module manifest for module 'stigtools'
#
# Generated by: Chrissy LeMaire
#
@{
    # Version number of this module.
    ModuleVersion     = '0.0.1'

    # ID used to uniquely identify this module
    GUID              = 'fb5793f9-9211-47e5-a1b3-1f04e254868f'

    # Author of this module
    Author            = 'Chrissy LeMaire'

    # Company or vendor of this module
    CompanyName       = 'Chrissy LeMaire'

    # Copyright statement for this module
    Copyright         = '2022 Chrissy LeMaire'

    # Description of the functionality provided by this module
    Description       = 'DISA STIG Automation toolkit (very alpha release)'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Format files (xml) to be loaded when importing this module
    # "xml\dbatools.Format.ps1xml"
    FormatsToProcess  = @()

    # Assemblies that must be imported into the global environment prior to importing this module
    RequiredModules   = @()

    # Script module or binary module file associated with this manifest.
    RootModule        = 'stigtools.psm1'

    FunctionsToExport = @(
        'Convert-NessusAudit',
        'Convert-ManualXCCDF',
        'Convert-SCC',
        'Convert-XCCDF',
        'Expand-StigLibrary',
        'Get-CCIVulnReference',
        'Get-ChecklistHostData',
        'Get-ChecklistInfo',
        'Get-StigFile',
        'Get-StigMetrics',
        'Merge-Checklist',
        'New-PoamTemplate',
        'Read-Checklist',
        'Repair-Checklist',
        'Save-StigFile',
        'Save-StigLibrary',
        'Set-ChecklistHostData',
        'Set-NRtoOpen',
        'Update-ChecklistVersion',
        'Update-VulnResult'
    )

    CmdletsToExport   = @()
    AliasesToExport   = @()

    PrivateData       = @{

        # PSData is module packaging and gallery metadata embedded in PrivateData
        # It's for rebuilding PowerShellGet (and PoshCode) NuGet-style packages
        # We had to do this because it's the only place we're allowed to extend the manifest
        # https://connect.microsoft.com/PowerShell/feedback/details/421837
        PSData = @{

            # The primary categorization of this module (from the TechNet Gallery tech tree).
            Category     = 'Security'

            # Keyword tags to help users find this module via navigations and search.
            Tags         = @('security', 'disa', 'stig', 'compliance')

            # The web address of an icon which can be used in galleries to represent this module
            IconUri      = 'https://user-images.githubusercontent.com/8278033/68308152-a886c180-00ac-11ea-880c-ef6ff99f5cd4.png'

            # Indicates this is a pre-release/testing version of the module.
            IsPrerelease = 'true'
        }
    }
}