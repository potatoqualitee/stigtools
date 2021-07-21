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


        It "Convert-NessusAudit converts an audit file to a stig checklist" {
            $params = @{
                TemplatePath = "/home/runner/work/stigtools/stigtools/tests/nessus/win10.ckl"
                Path         = "/home/runner/work/stigtools/stigtools/tests/nessus/1.nessus"
                Destination  = "/tmp"
            }
            $results = Convert-NessusAudit @params
            $results.BaseName | Should -match "Windows 10"
            $read = Read-Checklist -Path $results.FullName
            ($read.vulns.status | Where-Object { $PSItem -eq "Not_Reviewed" } | Measure-Object).Count | Should -Be 104
            ($read.vulns.status | Measure-Object).Count | Should -Be 285
        }


        It "Update-VulnResult updates from files" {
            $win10 = "/home/runner/work/stigtools/stigtools/tests/nessus/win10.ckl"
            $win11 = "/home/runner/work/stigtools/stigtools/tests/nessus/win11.ckl"
            $win12 = "/home/runner/work/stigtools/stigtools/tests/nessus/win12.ckl"
            $win11countbefore = ((Read-Checklist -Path $win11).vulns.status | Where-Object { $PSItem -eq "Not_Reviewed" } | Measure-Object).Count

            $win12countbefore = ((Read-Checklist -Path $win12).vulns.status | Where-Object { $PSItem -eq "Not_Reviewed" } | Measure-Object).Count

            $null = (Read-Checklist -Path /home/runner/work/stigtools/stigtools/tests/nessus/win10.ckl).Vulns | Update-VulnResult -Path $win11, $win12

            $win10count = ((Read-Checklist -Path $win10).vulns.status | Where-Object { $PSItem -eq "Not_Reviewed" } | Measure-Object).Count

            $win11countafter = ((Read-Checklist -Path $win11).vulns.status | Where-Object { $PSItem -eq "Not_Reviewed" } | Measure-Object).Count

            $win12countafter = ((Read-Checklist -Path $win12).vulns.status | Where-Object { $PSItem -eq "Not_Reviewed" } | Measure-Object).Count

            $win10count | Should -Not -Be $win11countbefore
            $win10count | Should -Not -Be $win12countbefore
            $win10count | Should -Be $win11countafter
            $win10count | Should -Be $win12countafter
        }
    }
}