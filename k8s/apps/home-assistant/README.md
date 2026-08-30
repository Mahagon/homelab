# Home Assistant

The Home Assistant workload uses host networking on `192.168.178.10`. Shelly
devices can be isolated on VLAN 20 (`192.168.20.0/24`) while Home Assistant
continues to control them directly.

## Shelly VLAN 20 migration

[`scripts/migrate-shelly-wifi.ps1`](scripts/migrate-shelly-wifi.ps1) discovers
the Shelly config entries through the Home Assistant API, preserves each
device's current WLAN as its fallback, switches its primary WLAN to VLAN 20,
and verifies the device's MAC address at a DHCP address in the target subnet.
It then:

1. makes the VLAN WLAN primary and removes the fallback;
2. sets every Gen1 CoIoT peer to `192.168.178.10:5683`;
3. disables Shelly Cloud;
4. configures PTB NTP;
5. updates the Home Assistant config-entry address through its supported API;
6. enables a shared device administration password and completes Home
   Assistant's reauthentication flow.

It does not edit Home Assistant's `.storage` files. The script supports Gen1
Basic authentication and the Gen2+ Shelly/RFC 7616 digest flow.

### Network prerequisites

Create the target WLAN as a 2.4 GHz, **WPA2-Personal-only** SSID backed by VLAN
20 and DHCP. Avoid WPA2/WPA3 transition mode and make PMF optional rather than
required; some Shelly models or firmware versions reject the enhanced modes.
Keep the existing Shelly WLAN enabled throughout the migration. The
script asks securely for its password so it can be retained as a per-device
fallback; unselected devices are not interrupted.

Place these stateful UniFi rules above the VLAN 20 deny rules:

| Direction | Action | Protocol | Source | Destination | Port |
| --- | --- | --- | --- | --- | --- |
| VLAN 20 to External | Allow | UDP | `192.168.20.0/24` | `192.53.103.103`, `192.53.103.108` | `123` |
| VLAN 20 to Internal | Allow | UDP | `192.168.20.0/24` | `192.168.178.10` | `5683` |
| Main LAN to VLAN 20 | Allow | TCP | trusted main LAN | `192.168.20.0/24` | `80`, `443` |

The first rule allows only PTB time synchronization. The second is required for
Gen1 CoIoT push updates. The third lets Home Assistant and the migration
workstation initiate local API connections. Stateful return traffic must be
allowed; VLAN 20 does not otherwise need access to the main LAN or internet.

The migration workstation must be able to reach `192.168.20.0/24`. If the main
LAN rule is narrowed to only Home Assistant, temporarily include the
workstation while running this script.

### Preparation

Use PowerShell 7 and create a Home Assistant administrator long-lived access
token under the user profile's Security page. The token, WLAN password, and
Shelly password are read with secure prompts and are not placed on the command
line or written to the checkpoint file. Home Assistant stores the Shelly
credentials in its config-entry storage after reauthentication.

Set `HOME_ASSISTANT_URL` to the externally reachable Home Assistant base URL,
or pass it with `-HomeAssistantUrl`. Reauthentication
flow discovery uses the local WebSocket endpoint
`ws://192.168.178.10:8123/api/websocket` by default. Override it with
`-HomeAssistantWebSocketUrl` if the Home Assistant address changes.

Run an audit first:

```powershell
Set-Location k8s/apps/home-assistant
$env:HOME_ASSISTANT_URL = "https://homeassistant.<your-domain>"
pwsh ./scripts/migrate-shelly-wifi.ps1 -Mode Audit
```

Wake battery-powered Shellys immediately before auditing or migrating them.
Unavailable devices are skipped, not modified.

### Migrate

Preview a batch without changing anything:

```powershell
pwsh ./scripts/migrate-shelly-wifi.ps1 -Mode Migrate -BatchSize 5 -WhatIf
```

Migrate at most five devices:

```powershell
pwsh ./scripts/migrate-shelly-wifi.ps1 -Mode Migrate -BatchSize 5
```

For every selected device, the script reads the current SSID, installs that
SSID as the fallback, changes the primary WLAN to the VLAN SSID, and scans
`192.168.20.0/24` for the same MAC address. The old SSID remains enabled and
unselected devices remain online. Completed entry IDs are recorded locally and
skipped on later runs.

Select devices by Home Assistant title (wildcards are accepted), for example:

```powershell
pwsh ./scripts/migrate-shelly-wifi.ps1 -Mode Migrate -DeviceTitle 'tempsensor' -BatchSize 1
pwsh ./scripts/migrate-shelly-wifi.ps1 -Mode Migrate -DeviceTitle 'Shelly Plug*' -BatchSize 5
```

The default non-secret checkpoint is
`$env:LOCALAPPDATA\ShellyVlanMigration\state.json`. Re-running `Migrate` uses
the VLAN address for a device whose prior run reached discovery but did not
finish.

### Password-only operation and verification

Protect devices without moving their WLAN:

```powershell
pwsh ./scripts/migrate-shelly-wifi.ps1 -Mode Protect -BatchSize 5
```

`Protect` updates Home Assistant immediately. If Home Assistant cannot accept
newly enabled credentials, the script removes only the authentication that it
enabled in that run. Authentication that already existed is never removed by
that failure path.

Verify connectivity and the shared password after migration:

```powershell
pwsh ./scripts/migrate-shelly-wifi.ps1 -Mode Verify
```

### Recovery

If a device is not discovered on VLAN 20, its old WLAN fallback is deliberately
left enabled, so it should remain reachable or reconnect to the old network.
After correcting the target WLAN, rerun `Migrate`. To explicitly restore the
old WLAN as primary and remove the fallback configuration:

```powershell
pwsh ./scripts/migrate-shelly-wifi.ps1 -Mode RollbackStaged
```

If a run failed after discovery, leave main-to-VLAN TCP `80/443` open and run
`Migrate` again with the same shared password and target WLAN. The checkpoint
lets the script resume from the device's new DHCP address without repeating the
WLAN handoff. Do not delete a checkpoint until every affected device is either
complete or recovered.

If a device reached the target WLAN before its checkpoint was updated, the
script scans VLAN 20 and recovers it by its checkpointed MAC address. It adopts
the device only after confirming both the target SSID and target subnet, then
finishes Cloud, NTP, password, and Home Assistant configuration.

### Firmware updates

Home Assistant communicates with Shellys locally and does not require Shelly
Cloud. Its update entity triggers the device's OTA process; Home Assistant does
not proxy the firmware image. A fully internet-blocked Shelly therefore cannot
download vendor firmware. Temporarily allow the device outbound internet access
for an update window, then remove that rule again. NTP-only access is not enough.

See the official [Home Assistant Shelly integration documentation](https://www.home-assistant.io/integrations/shelly/)
and [Shelly Gen2+ authentication documentation](https://shelly-api-docs.shelly.cloud/gen2/General/Authentication/).

### Credential cleanup

Rotate or delete any temporary UniFi administrator account created for this
migration. No UniFi credential is used or stored by the script.
