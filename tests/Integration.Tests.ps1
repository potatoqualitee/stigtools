Describe "Integration Tests" -Tag "IntegrationTests" {
    Context "command tests" {
        It "Convert-SCC converts files" {
            $params = @{
                LibraryPath     = "/home/runner/work/stigtools/stigtools/tests/stigs"
                ResultsPath     = "/home/runner/work/stigtools/stigtools/tests/SCC"
                Destination     = "/tmp"
                WarningVariable = "warning"
                WarningAction   = "SilentlyContinue"
            }
            $results = Convert-SCC @params

            $results.Count | Should -Be 6
            "$warning" | Should -Match "Vuln SV-221580r615937_rule not found"
        }

        It "Read-Checklist reads a checklist" {
            $results = Read-Checklist -Path /tmp/winserver_U_Windows_Firewall_STIG_V1R7.ckl
            $results.ComputerName | Should -Be "winserver"
            $results.HostIP | Should -Be "192.168.0.48"
            $results.Classifcation | Should -Be "UNCLASSIFIED"
            $results.Title | Should -Be "Windows Firewall with Advanced Security Security Technical Implementation Guide"
            $results.Vulns | Select-Object -First 1 -ExpandProperty Status | Should -Be "Open"
        }


        It "Set-NRtoOpen sets not reviewed to open" {
            $read = Read-Checklist -Path /tmp/winserver_U_Windows_Firewall_STIG_V1R7.ckl
            $nr = $read.vulns.status | Where-Object { $PSItem -eq "Not_Reviewed" }
            $results = Set-NRtoOpen -Path /tmp/winserver_U_Windows_Firewall_STIG_V1R7.ckl
            $read = Read-Checklist -Path /tmp/winserver_U_Windows_Firewall_STIG_V1R7.ckl
            $nr2 = $read.vulns.status | Where-Object { $PSItem -eq "Not_Reviewed" }
            $results.BaseName | Should -match "winserver_U_Windows_Firewall_STIG_V1R7"
            $nr.Count | Should -BeGreaterThan $nr2.Count
            $nr2 | Should -BeNull
        }
    }
}