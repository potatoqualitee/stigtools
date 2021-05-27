function Convert-ManualXCCDF {
    <#
    .SYNOPSIS
        Will convert a manual xccdf to a blank checklist

    .PARAMETER Path
        Full file path to the XCCDF File

    .PARAMETER Destination
        Destination directory

    .PARAMETER Classification
        The classification. Defaults to: UNCLASSIFIED or CLASSIFIED

    .EXAMPLE
        Convert-ManualXCCDF -Path C:\Data\U_MyApp_Manual.xccdf -Destination C:\Data

        Creates C:\Data\U_MyApp_Manual.ckl from C:\Data\U_MyApp_Manual.xccdf
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateScript({ Test-Path -Path $PSItem })]
        [Alias("FullName")]
        [string[]]$Path,
        [string]$Destination,
        [ValidateSet("UNCLASSIFIED", "CLASSIFIED")]
        [string]$Classification
    )
    begin {
        function Add-SIDataNode {
            param(
                [Parameter(Mandatory)]
                [System.Xml.XmlDocument]$RootDocument,
                [Parameter(Mandatory)]
                [System.XML.XMLElement]$ParentNode,
                [Parameter(Mandatory)]
                [string]$Name,
                [string]$Data
            )
            $NewNode = $RootDocument.CreateElement("SI_DATA")
            Add-XMLTextNode -RootDocument $RootDocument -ParentNode $NewNode -Name "SID_NAME" -Text $Name
            if ($Data) {
                Add-XMLTextNode -RootDocument $RootDocument -ParentNode $NewNode -Name "SID_DATA" -Text $Data
            }
            $null = $ParentNode.AppendChild($NewNode)
        }

        function Add-STIGDataNode {
            param(
                [Parameter(Mandatory)]
                [System.Xml.XmlDocument]$RootDocument,
                [Parameter(Mandatory)]
                [System.XML.XMLElement]$ParentNode,
                [Parameter(Mandatory)]
                [string]$Name,
                [string]$Data
            )
            $NewNode = $RootDocument.CreateElement("STIG_DATA")
            Add-XMLTextNode -RootDocument $RootDocument -ParentNode $NewNode -Name "VULN_ATTRIBUTE" -Text $Name
            Add-XMLTextNode -RootDocument $RootDocument -ParentNode $NewNode -Name "ATTRIBUTE_DATA" -Text $Data
            $null = $ParentNode.AppendChild($NewNode)
        }

        function Add-XMLTextNode {
            param(
                [Parameter(Mandatory)]
                [System.Xml.XmlDocument]$RootDocument,
                [Parameter(Mandatory)]
                [System.XML.XMLElement]$ParentNode,
                [Parameter(Mandatory)]
                [string]$Name,
                [string]$Text
            )
            $NewNode = $RootDocument.CreateElement($Name)
            $null = $NewNode.AppendChild($RootDocument.CreateTextNode($Text))
            $null = $ParentNode.AppendChild($NewNode)
        }
    }
    process {
        foreach ($file in $Path) {
            try {
                $xccdf = Import-XCCDF -Path $file
                $xccdfdata = Get-XCCDFVulnInformation -XCCDF $xccdf -Full
                $xccdfheaddata = Get-XCCDFInfo -XCCDF $xccdf

                $xmldoc = New-Object System.Xml.XmlDocument
                $null = $xmldoc.AppendChild($xmldoc.CreateXmlDeclaration("1.0", "UTF = 8", $null))
                $null = $xmldoc.AppendChild($xmldoc.CreateComment("STIG Support Module"))
                $null = $xmldoc.AppendChild($xmldoc.CreateElement("CHECKLIST"))

                #Asset Data
                $assetnode = $xmldoc.CreateElement("ASSET")
                Add-XMLTextNode -RootDocument $xmldoc -ParentNode $assetnode -Name "ROLE" -Text "None"
                Add-XMLTextNode -RootDocument $xmldoc -ParentNode $assetnode -Name "ASSET_TYPE" -Text "Computing"
                Add-XMLTextNode -RootDocument $xmldoc -ParentNode $assetnode -Name "HOST_NAME" -Text ""
                Add-XMLTextNode -RootDocument $xmldoc -ParentNode $assetnode -Name "HOST_IP" -Text ""
                Add-XMLTextNode -RootDocument $xmldoc -ParentNode $assetnode -Name "HOST_MAC" -Text ""
                Add-XMLTextNode -RootDocument $xmldoc -ParentNode $assetnode -Name "HOST_FQDN" -Text ""
                Add-XMLTextNode -RootDocument $xmldoc -ParentNode $assetnode -Name "TECH_AREA" -Text ""
                Add-XMLTextNode -RootDocument $xmldoc -ParentNode $assetnode -Name "TARGET_KEY" -Text ($xccdfdata[0].Rule.Reference.Identifier)
                Add-XMLTextNode -RootDocument $xmldoc -ParentNode $assetnode -Name "WEB_OR_DATABASE" -Text "false"
                Add-XMLTextNode -RootDocument $xmldoc -ParentNode $assetnode -Name "WEB_DB_SITE" -Text ""
                Add-XMLTextNode -RootDocument $xmldoc -ParentNode $assetnode -Name "WEB_DB_INSTANCE" -Text ""
                $null = $xmldoc.LastChild.AppendChild($assetnode)

                #STIGS
                $stignode = $xmldoc.CreateElement("STIGS")
                $iSTIGNode = $xmldoc.CreateElement("iSTIG")
                $stiginfonode = $xmldoc.CreateElement("STIG_INFO")

                ##SI_DATA Stuff
                Add-SIDataNode -RootDocument $xmldoc -ParentNode $stiginfonode -Name "version" -Data $xccdfheaddata.Version

                if ($PSboundParameters.Classification) {
                    if ($Classification -eq "UNCLASSIFIED") {
                        $Class = "Unclass"
                    } else {
                        $Class = "Classified"
                    }
                }

                if (-not $PSBoundParameters.Classification -and $xccdf.'xml-stylesheet'.Contains("unclass")) {
                    $Classification = "UNCLASSIFIED"
                    $Class = "Unclass"
                }

                Add-SIDataNode -RootDocument $xmldoc -ParentNode $stiginfonode -Name "classification" -Data $Classification
                Add-SIDataNode -RootDocument $xmldoc -ParentNode $stiginfonode -Name "customname" -Data $null
                Add-SIDataNode -RootDocument $xmldoc -ParentNode $stiginfonode -Name "stigid" -Data $xccdfheaddata.ID
                Add-SIDataNode -RootDocument $xmldoc -ParentNode $stiginfonode -Name "description" -Data $xccdfheaddata.Description
                Add-SIDataNode -RootDocument $xmldoc -ParentNode $stiginfonode -Name "filename" -Data (Get-Item -Path $file).Name
                Add-SIDataNode -RootDocument $xmldoc -ParentNode $stiginfonode -Name "releaseinfo" -Data $xccdfheaddata.Release
                Add-SIDataNode -RootDocument $xmldoc -ParentNode $stiginfonode -Name "title" -Data $xccdfheaddata.Title
                Add-SIDataNode -RootDocument $xmldoc -ParentNode $stiginfonode -Name "uuid" -Data (New-Guid).ToString()
                Add-SIDataNode -RootDocument $xmldoc -ParentNode $stiginfonode -Name "notice" -Data $xccdf.Benchmark.notice.id
                Add-SIDataNode -RootDocument $xmldoc -ParentNode $stiginfonode -Name "source" -Data $null
                $null = $iSTIGNode.AppendChild($stiginfonode)

                ##VULN
                foreach ($Vuln in $xccdfdata) {
                    $VulnNode = $xmldoc.CreateElement("VULN")
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "Vuln_Num" -Data $Vuln.ID
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "Severity" -Data $Vuln.Rule.Severity
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "Group_Title" -Data $Vuln.Title
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "Rule_ID" -Data $Vuln.Rule.ID
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "Rule_Ver" -Data $Vuln.Rule.Version
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "Rule_Title" -Data $Vuln.Rule.Title
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "Vuln_Discuss" -Data $Vuln.Rule.Description
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "IA_Controls" -Data $Vuln.Rule.IAControls
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "Check_Content" -Data $Vuln.Rule.Check.Content
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "Fix_Text" -Data $Vuln.Rule.FixText
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "False_Positives" -Data $Vuln.Rule.FalsePositives
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "False_Negatives" -Data $Vuln.Rule.FalseNegatives
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "Documentable" -Data $Vuln.Rule.Documentable
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "Mitigations" -Data $Vuln.Rule.Mitigations
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "Potential_Impact" -Data $Vuln.Rule.PotentialImpacts
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "Third_Party_Tools" -Data $Vuln.Rule.ThirdPartyTools
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "Mitigation_Control" -Data $Vuln.Rule.MitigationControl
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "Responsibility" -Data $Vuln.Rule.Responsibility
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "Security_Override_Guidance" -Data $Vuln.Rule.SeverityOverrideGuidance
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "Check_Content_Ref" -Data $Vuln.Rule.Check.ContentRefName
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "Weight" -Data $Vuln.Rule.Weight
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "Class" -Data $Class
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "STIGRef" -Data ($xccdfheaddata.Title + " :: " + "Version " + $xccdfheaddata.Version + ", " + $xccdfheaddata.Release)
                    Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "TargetKey" -Data $Vuln.Rule.Reference.Identifier
                    foreach ($CCI in (@() + $Vuln.Rule.Ident)) {
                        Add-STIGDataNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "CCI_REF" -Data $CCI
                    }
                    Add-XMLTextNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "STATUS" -Text "Not_Reviewed"
                    Add-XMLTextNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "FINDING_DETAILS"
                    Add-XMLTextNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "COMMENTS"
                    Add-XMLTextNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "SEVERITY_OVERRIDE"
                    Add-XMLTextNode -RootDocument $xmldoc -ParentNode $VulnNode -Name "SEVERITY_JUSTIFICATION"
                    $null = $iSTIGNode.AppendChild($VulnNode)
                }

                $null = $stignode.AppendChild($iSTIGNode)
                $null = $xmldoc.LastChild.AppendChild($stignode)
                $filename = (Split-Path -Path $file -Leaf)
                $filename = $filename.Replace(([System.IO.Path]::GetExtension($filename)), ".ckl")
                $filename = Join-Path -Path $Destination -ChildPath $filename
                $null = Export-StigCKL -CKLData $xmldoc -Path $filename
                Get-ChildItem -Path $filename
            } catch {
                Write-Warning -Message "Can't process $file`: $PSItem"
            }
        }
    }
}