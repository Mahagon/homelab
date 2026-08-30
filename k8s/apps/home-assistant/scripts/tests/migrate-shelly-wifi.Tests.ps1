$scriptPath = Join-Path $PSScriptRoot '..\migrate-shelly-wifi.ps1'
. $scriptPath

Describe 'Shelly migration pure helpers' {
    It 'requires an explicit Home Assistant URL when the environment fallback is absent' {
        $previousUrl = $env:HOME_ASSISTANT_URL
        $env:HOME_ASSISTANT_URL = $null
        $threw = $false
        try {
            Invoke-ShellyMigration -HomeAssistantUrl ''
        }
        catch {
            $threw = $_.Exception.Message -match 'Supply -HomeAssistantUrl or set the HOME_ASSISTANT_URL environment variable'
        }
        finally {
            $env:HOME_ASSISTANT_URL = $previousUrl
        }

        $threw | Should Be $true
    }

    It 'retries transient operations and returns the eventual result' {
        $counter = [pscustomobject]@{ Value = 0 }
        $result = Invoke-WithRetry -Description 'test operation' -Attempts 3 -DelaySeconds 0 -Operation {
            $counter.Value++
            if ($counter.Value -lt 3) { throw 'transient failure' }
            'success'
        }

        $counter.Value | Should Be 3
        $result | Should Be 'success'
    }

    It 'joins API paths without duplicate separators' {
        Join-ApiUri -BaseUri 'https://ha.example/' -Path '/api/test' | Should Be 'https://ha.example/api/test'
    }

    It 'normalizes common MAC address formats' {
        Normalize-MacAddress -MacAddress 'aa:bb:cc:11:22:33' | Should Be 'AABBCC112233'
        Normalize-MacAddress -MacAddress 'AA-BB-CC-11-22-33' | Should Be 'AABBCC112233'
    }

    It 'rejects malformed MAC addresses' {
        $threw = $false
        try { $null = Normalize-MacAddress -MacAddress 'not-a-mac' } catch { $threw = $true }
        $threw | Should Be $true
    }

    It 'calculates the expected Shelly HA1 SHA-256 value' {
        Get-Sha256Hex -Value 'admin:shellyplus1pm-ABCDEF123456:correct horse battery staple' |
            Should Be '0113d2cd6a5c4aecd44f1c3c2601516a2262241d81520800ff83083e4c382ee4'
    }

    It 'enumerates only usable hosts in a /30' {
        $hosts = @(Get-CidrHosts -Cidr '192.168.20.0/30')
        $hosts.Count | Should Be 2
        $hosts[0] | Should Be '192.168.20.1'
        $hosts[1] | Should Be '192.168.20.2'
    }

    It 'enumerates all usable hosts in a /24' {
        @(Get-CidrHosts -Cidr '192.168.20.0/24').Count | Should Be 254
    }

    It 'accepts adoption only when both target SSID and subnet match' {
        $targetDevice = [pscustomobject]@{ Host = '192.168.20.38' }
        $oldDevice = [pscustomobject]@{ Host = '192.168.178.64' }

        Test-ShellyTargetPlacement -Device $targetDevice -CurrentSsid 'CloudDenied' -TargetSsid 'CloudDenied' -TargetSubnet '192.168.20.0/24' | Should Be $true
        Test-ShellyTargetPlacement -Device $oldDevice -CurrentSsid 'CloudDenied' -TargetSsid 'CloudDenied' -TargetSubnet '192.168.20.0/24' | Should Be $false
        Test-ShellyTargetPlacement -Device $targetDevice -CurrentSsid 'skynet' -TargetSsid 'CloudDenied' -TargetSubnet '192.168.20.0/24' | Should Be $false
    }

    It 'rejects an excessively broad discovery subnet' {
        $threw = $false
        try { $null = Get-CidrHosts -Cidr '192.168.16.0/21' } catch { $threw = $true }
        $threw | Should Be $true
    }
}

Describe 'Shelly inventory and checkpoint behavior' {
    It 'flattens the top-level JSON config-entry array returned by Invoke-RestMethod' {
        Mock Invoke-HaRequest {
            Write-Output -NoEnumerate @(
                [pscustomobject]@{ entry_id = 'entry-1'; title = 'Kitchen' }
                [pscustomobject]@{ entry_id = 'entry-2'; title = 'Office' }
            )
        }

        $result = @(Get-HaEntries -HomeAssistantUrl 'https://ha.example' -Token 'test-token')

        $result.Count | Should Be 2
        $result[0].entry_id | Should Be 'entry-1'
        $result[1].entry_id | Should Be 'entry-2'
    }

    It 'reads a Shelly host from the supported Home Assistant reconfigure flow' {
        Mock Get-HaEntries {
            @([pscustomobject]@{ entry_id = 'entry-1'; title = 'Kitchen'; state = 'loaded' })
        }
        Mock Start-HaEntryFlow {
            [pscustomobject]@{
                type = 'form'
                step_id = 'reconfigure'
                flow_id = 'flow-1'
                data_schema = @(
                    [pscustomobject]@{ name = 'host'; default = '192.168.178.20' }
                    [pscustomobject]@{ name = 'port'; default = 80 }
                    [pscustomobject]@{ name = 'verify_ssl'; default = $false }
                )
            }
        }
        Mock Stop-HaEntryFlow {}

        $result = @(Get-HaShellyInventory -HomeAssistantUrl 'https://ha.example' -Token 'test-token')

        $result.Count | Should Be 1
        $result[0].Host | Should Be '192.168.178.20'
        $result[0].State | Should Be 'loaded'
        Assert-MockCalled Stop-HaEntryFlow 1 -Exactly
    }

    It 'filters titles with wildcards before applying the batch limit' {
        $inventory = @(
            [pscustomobject]@{ Title = 'Kitchen Plug'; EntryId = '1' }
            [pscustomobject]@{ Title = 'Office Light'; EntryId = '2' }
            [pscustomobject]@{ Title = 'Office Plug'; EntryId = '3' }
        )

        $result = @(Select-InventoryEntries -Inventory $inventory -DeviceTitle 'Office*' -Limit 1)
        $result.Count | Should Be 1
        $result[0].Title | Should Be 'Office Light'
    }

    It 'records resumable addresses without recording secrets' {
        $state = Read-MigrationState -Path (Join-Path $TestDrive 'missing-state.json')
        $entry = [pscustomobject]@{ EntryId = 'entry-1'; Title = 'Kitchen'; Host = '192.168.178.20' }
        $device = [pscustomobject]@{ Mac = 'AABBCCDDEEFF'; Generation = 2; Port = 80 }

        Set-MigrationCheckpoint -State $state -Entry $entry -Device $device -Phase 'transitioning' -NewIp $null -NewPort $null -OldSsid 'OldWlan' -ErrorMessage $null
        $entry.Host = '192.168.20.42'
        Set-MigrationCheckpoint -State $state -Entry $entry -Device $device -Phase 'discovered' -NewIp '192.168.20.42' -NewPort 80 -ErrorMessage $null
        $json = $state | ConvertTo-Json -Depth 10

        $state.devices[0].newIp | Should Be '192.168.20.42'
        $state.devices[0].newPort | Should Be 80
        $state.devices[0].oldIp | Should Be '192.168.178.20'
        $state.devices[0].oldSsid | Should Be 'OldWlan'
        $json | Should Not Match '(?i)password|token|secret'
    }

    It 'uses a discovered VLAN address when resuming' {
        $inventory = @([pscustomobject]@{ EntryId = 'entry-1'; Host = '192.168.178.20'; Port = 80 })
        $state = @{
            devices = @(@{ entryId = 'entry-1'; newIp = '192.168.20.42'; newPort = 443; phase = 'finalize_failed' })
        }

        $result = @(Resolve-InventoryFromState -Inventory $inventory -State $state)
        $result[0].Host | Should Be '192.168.20.42'
        $result[0].Port | Should Be 443
    }
}

Describe 'Shelly authentication routing' {
    It 'reads the current Gen1 primary SSID for safe fallback' {
        Mock Get-ShellySettings { [pscustomobject]@{ wifi_sta = [pscustomobject]@{ ssid = 'OldWlan' } } }
        $device = [pscustomobject]@{ Generation = 1 }

        Get-ShellyPrimarySsid -Device $device | Should Be 'OldWlan'
    }

    It 'reads the current Gen2+ primary SSID for safe fallback' {
        Mock Get-ShellySettings { [pscustomobject]@{ Wifi = [pscustomobject]@{ sta = [pscustomobject]@{ ssid = 'OldWlan' } } } }
        $device = [pscustomobject]@{ Generation = 3 }

        Get-ShellyPrimarySsid -Device $device | Should Be 'OldWlan'
    }

    It 'routes a protected Gen2 RPC through the digest HTTP helper' {
        Mock Invoke-ShellyDigestJsonRequest { [pscustomobject]@{ result = @{ ok = $true } } }
        $device = [pscustomobject]@{ Host = '192.0.2.10'; Port = 80; Protected = $true }

        $result = Invoke-ShellyRpc -Device $device -Method 'Sys.GetConfig' -Password 'test password'

        $result.ok | Should Be $true
        Assert-MockCalled Invoke-ShellyDigestJsonRequest 1 -Exactly
    }

    It 'surfaces Shelly RPC error responses' {
        Mock Invoke-ShellyRequest { [pscustomobject]@{ error = [pscustomobject]@{ code = -103; message = 'Bad arguments' } } }
        $device = [pscustomobject]@{ Host = '192.0.2.10'; Port = 80; Protected = $false }
        $threw = $false

        try { $null = Invoke-ShellyRpc -Device $device -Method 'Wifi.SetConfig' } catch {
            $threw = $_.Exception.Message -match 'code=-103.*Bad arguments'
        }

        $threw | Should Be $true
    }

    It 'uses Basic authentication for a protected Gen1 CoIoT change' {
        Mock Invoke-ShellyRequest { [pscustomobject]@{} }
        $device = [pscustomobject]@{ Host = '192.0.2.11'; Port = 80; Generation = 1; Protected = $true }

        Set-ShellyCoIoT -Device $device -Peer '192.168.178.10:5683' -Password 'test password'

        Assert-MockCalled Invoke-ShellyRequest 1 -Exactly -ParameterFilter {
            $Authentication -eq 'Basic' -and $Password -eq 'test password'
        }
    }
}

Describe 'Shelly primary WLAN configuration' {
    It 'passes the administration password on Gen2+ fallback set and read-back calls' {
        Mock Invoke-ShellyRpc {
            if ($Method -eq 'Wifi.GetConfig') {
                return [pscustomobject]@{ sta1 = [pscustomobject]@{ enable = $true; ssid = 'OldWlan' } }
            }
            [pscustomobject]@{ restart_required = $false }
        }
        $device = [pscustomobject]@{ Host = '192.0.2.12'; Port = 80; Generation = 3; Protected = $true }

        Set-ShellyFallbackWifi -Device $device -Ssid 'OldWlan' -WifiPassword 'wifi password' -Password 'admin password'

        Assert-MockCalled Invoke-ShellyRpc 2 -Exactly -ParameterFilter { $Password -eq 'admin password' }
    }

    It 'passes the administration password on the Gen2+ primary-WLAN RPC call' {
        Mock Invoke-ShellyRpc { [pscustomobject]@{ restart_required = $false } }
        $device = [pscustomobject]@{ Host = '192.0.2.12'; Port = 80; Generation = 3; Protected = $true }

        Set-ShellyPrimaryWifi -Device $device -Ssid 'NewWlan' -WifiPassword 'wifi password' -Password 'admin password'

        Assert-MockCalled Invoke-ShellyRpc 1 -Exactly -ParameterFilter {
            $Method -eq 'Wifi.SetConfig' -and
            $Password -eq 'admin password' -and
            $Parameters.ContainsKey('config') -and
            $Parameters.config.ContainsKey('sta')
        }
    }
}

Describe 'Home Assistant address update' {
    It 'submits and closes a successful reconfigure flow without invoking stray commands' {
        Mock Start-HaEntryFlow { [pscustomobject]@{ flow_id = 'flow-1' } }
        Mock Invoke-HaRequest { [pscustomobject]@{ type = 'abort'; reason = 'reconfigure_successful' } }
        Mock Stop-HaEntryFlow {}

        Set-HaShellyAddress -HomeAssistantUrl 'https://ha.example' -Token 'test-token' -EntryId 'entry-1' -Host '192.168.20.42' -Port 80

        Assert-MockCalled Invoke-HaRequest 1 -Exactly
    }
}
