function Get-XCCDFVulnInformation {
    <#
    .SYNOPSIS
        Returns an array of the vulns in the xccdf file (ID, Title, Version, Description/VulnDiscussion, FixText, CheckText)

    .PARAMETER XCCDF
        XCCDF data as loaded from the Import-XCCDF

    .PARAMETER Full
        If supplied, will pull all information in a less friendly format.

    .EXAMPLE
        Get-XCCDFVulnInformation -XCCDF $XCCDFData

    .EXAMPLE
        Get-XCCDFVulnInformation -XCCDF $XCCDFData -Full
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [xml]$XCCDF,
        [switch]$Full
    )
    process {
        $Results = @()
        $Groups = $XCCDF.Benchmark.Group
        foreach ($Group in $Groups) {
            if (-not $Full) {
                $Description = $Group.Rule.description

                #Description is weird, it is like further XML, but encoded and not as separate elements. idk, but this regex will extract what we want out of the mess
                if ($Description -match "<VulnDiscussion\>([\w\W]*)</VulnDiscussion>") {
                    $Description = $Matches[1]
                }
                $Results += [PSCustomObject]@{
                    ID          = $Group.id
                    Title       = $Group.Rule.Title
                    Version     = $Group.Rule.Version
                    Description = $Description
                    FixText     = $Group.Rule.fixtext.'#text'
                    CheckText   = $Group.Rule.check.'check-content'
                }
            } else {
                #Breakout Description
                $Description = $Group.Rule.description
                if ($Description -match "<VulnDiscussion\>([\w\W]*)</VulnDiscussion>") {
                    $Description = $Matches[1]
                }
                $FalsePositives = ""
                if ($Group.Rule.description -match "<FalsePositives\>([\w\W]*)</FalsePositives>") {
                    $FalsePositives = $Matches[1]
                }
                $FalseNegatives = ""
                if ($Group.Rule.description -match "<FalseNegatives\>([\w\W]*)</FalseNegatives>") {
                    $FalseNegatives = $Matches[1]
                }
                $Documentable = ""
                if ($Group.Rule.description -match "<Documentable\>([\w\W]*)</Documentable>") {
                    $Documentable = $Matches[1]
                }
                $Mitigations = ""
                if ($Group.Rule.description -match "<Mitigations\>([\w\W]*)</Mitigations>") {
                    $Mitigations = $Matches[1]
                }
                $SeverityOverrideGuidance = ""
                if ($Group.Rule.description -match "<SeverityOverrideGuidance\>([\w\W]*)</SeverityOverrideGuidance>") {
                    $SeverityOverrideGuidance = $Matches[1]
                }
                $PotentialImpacts = ""
                if ($Group.Rule.description -match "<PotentialImpacts\>([\w\W]*)</PotentialImpacts>") {
                    $PotentialImpacts = $Matches[1]
                }
                $ThirdPartyTools = ""
                if ($Group.Rule.description -match "<ThirdPartyTools\>([\w\W]*)</ThirdPartyTools>") {
                    $ThirdPartyTools = $Matches[1]
                }
                $MitigationControl = ""
                if ($Group.Rule.description -match "<MitigationControl\>([\w\W]*)</MitigationControl>") {
                    $MitigationControl = $Matches[1]
                }
                $Responsibility = ""
                if ($Group.Rule.description -match "<Responsibility\>([\w\W]*)</Responsibility>") {
                    $Responsibility = $Matches[1]
                }
                $IAControls = ""
                if ($Group.Rule.description -match "<IAControls\>([\w\W]*)</IAControls>") {
                    $IAControls = $Matches[1]
                }


                $Check = [pscustomobject]@{
                    System         = $Group.Rule.check.system
                    ContentRefName = $Group.Rule.check.'check-content-ref'.name

                    ContentRefHREF = $Group.Rule.check.'check-content-ref'.href
                    Content        = $Group.Rule.check.'check-content'
                }

                $Reference = [pscustomobject]@{
                    Title      = $Group.Rule.reference.title
                    Publisher  = $Group.Rule.reference.publisher

                    Type       = $Group.Rule.reference.type
                    Subject    = $Group.Rule.reference.subject
                    Identifier = $Group.Rule.reference.identifier
                }

                $Rule = [pscustomobject]@{
                    ID                       = $Group.Rule.id
                    Version                  = $Group.Rule.version
                    Severity                 = $Group.Rule.severity

                    Weight                   = $Group.Rule.weight
                    Title                    = $Group.Rule.title
                    Description              = $Description
                    Ident                    = $Group.Rule.ident.InnerText

                    IdentSystem              = $Group.Rule.ident.system
                    FixText                  = $Group.Rule.fixtext.InnerText
                    FixTextRef               = $Group.Rule.fixtext.fixref

                    FixID                    = $Group.Rule.fix.id
                    Check                    = $Check
                    Reference                = $Reference
                    FalsePositives           = $FalsePositives
                    FalseNegatives           = $FalseNegatives

                    Documentable             = $Documentable
                    Mitigations              = $Mitigations
                    SeverityOverrideGuidance = $SeverityOverrideGuidance
                    PotentialImpacts         = $PotentialImpacts

                    ThirdPartyTools          = $ThirdPartyTools
                    MitigationControl        = $MitigationControl
                    Responsibility           = $Responsibility
                    IAControls               = $IAControls
                }

                [pscustomobject]@{
                    ID          = $Group.id
                    Title       = $Group.title
                    Description = $Group.description
                    Rule        = $Rule
                }
            }
        }
    }
}