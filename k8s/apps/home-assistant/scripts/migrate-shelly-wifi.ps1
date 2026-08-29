#Requires -Version 7.0

<#
.SYNOPSIS
Audits, migrates, and password-protects Shelly devices managed by Home Assistant.

.DESCRIPTION
This script runs from a PowerShell 7 workstation that can reach Home Assistant,
the current Shelly network, and VLAN 20. Secrets are requested interactively and
are never written to the migration state file.

.EXAMPLE
./migrate-shelly-wifi.ps1 -Mode Audit

.EXAMPLE
./migrate-shelly-wifi.ps1 -Mode Migrate -DeviceTitle 'Weihnachtsbaum'

.EXAMPLE
./migrate-shelly-wifi.ps1 -Mode Protect -BatchSize 5
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('Audit', 'Migrate', 'Protect', 'Verify', 'RollbackStaged')]
    [string] $Mode = 'Audit',

    [ValidatePattern('^https?://')]
    [string] $HomeAssistantUrl = 'https://homeassistant.example.invalid',

    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
    [string] $HomeAssistantIp = '192.168.178.10',

    [ValidatePattern('^wss?://')]
    [string] $HomeAssistantWebSocketUrl,

    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$')]
    [string] $TargetSubnet = '192.168.20.0/24',

    [string[]] $NtpServers = @('192.53.103.103', '192.53.103.108'),

    [ValidateRange(1, 100)]
    [int] $BatchSize = 5,

    [string[]] $DeviceTitle,

    [ValidateRange(30, 1800)]
    [int] $DiscoveryTimeoutSeconds = 300,

    [string] $StatePath = (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'ShellyVlanMigration\state.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Join-ApiUri {
    param(
        [Parameter(Mandatory)] [string] $BaseUri,
        [Parameter(Mandatory)] [string] $Path
    )

    '{0}/{1}' -f $BaseUri.TrimEnd('/'), $Path.TrimStart('/')
}

function Get-ObjectProperty {
    param(
        [AllowNull()] [object] $InputObject,
        [Parameter(Mandatory)] [string] $Name,
        [AllowNull()] [object] $Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }
    if ($InputObject -is [Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) {
            return $InputObject[$Name]
        }
        return $Default
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }
    return $Default
}

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory)] [scriptblock] $Operation,
        [Parameter(Mandatory)] [string] $Description,
        [ValidateRange(1, 10)] [int] $Attempts = 3,
        [ValidateRange(0, 30)] [int] $DelaySeconds = 2
    )

    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        try {
            return & $Operation
        }
        catch {
            if ($attempt -eq $Attempts) {
                throw
            }
            $detail = $_.Exception.GetBaseException().Message
            Write-Warning "$Description failed (attempt $attempt/$Attempts): $detail. Retrying."
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

function ConvertFrom-SecureValue {
    param([Parameter(Mandatory)] [Security.SecureString] $SecureValue)

    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)
    try {
        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Read-ConfirmedSecret {
    param(
        [Parameter(Mandatory)] [string] $Prompt,
        [ValidateRange(1, 1024)] [int] $MinimumLength = 1,
        [ValidateRange(1, 1024)] [int] $MaximumLength = 1024,
        [switch] $PrintableAscii
    )

    while ($true) {
        $firstSecure = Read-Host -Prompt $Prompt -AsSecureString
        $secondSecure = Read-Host -Prompt "$Prompt (confirm)" -AsSecureString
        $first = ConvertFrom-SecureValue $firstSecure
        $second = ConvertFrom-SecureValue $secondSecure

        if ($first -cne $second) {
            Write-Warning 'The values do not match. Try again.'
            continue
        }
        if ($first.Length -lt $MinimumLength -or $first.Length -gt $MaximumLength) {
            Write-Warning "The value must contain between $MinimumLength and $MaximumLength characters."
            continue
        }
        if ($PrintableAscii -and $first -notmatch ('^[\x20-\x7e]{{{0},{1}}}$' -f $MinimumLength, $MaximumLength)) {
            Write-Warning 'Use printable ASCII characters only.'
            continue
        }

        return $first
    }
}

function Read-Secret {
    param([Parameter(Mandatory)] [string] $Prompt)

    ConvertFrom-SecureValue (Read-Host -Prompt $Prompt -AsSecureString)
}

function Invoke-HaRequest {
    param(
        [Parameter(Mandatory)] [string] $HomeAssistantUrl,
        [Parameter(Mandatory)] [string] $Token,
        [Parameter(Mandatory)] [ValidateSet('Get', 'Post', 'Delete')] [string] $Method,
        [Parameter(Mandatory)] [string] $Path,
        [AllowNull()] [object] $Body
    )

    $parameters = @{
        Uri                  = Join-ApiUri $HomeAssistantUrl $Path
        Method               = $Method
        Headers              = @{ Authorization = "Bearer $Token" }
        SkipCertificateCheck = $true
        TimeoutSec           = 30
        ErrorAction          = 'Stop'
    }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $parameters.ContentType = 'application/json'
        $parameters.Body = $Body | ConvertTo-Json -Depth 20 -Compress
    }

    Invoke-RestMethod @parameters
}

function Get-HaEntries {
    param(
        [Parameter(Mandatory)] [string] $HomeAssistantUrl,
        [Parameter(Mandatory)] [string] $Token
    )

    $response = Invoke-HaRequest -HomeAssistantUrl $HomeAssistantUrl -Token $Token -Method Get -Path '/api/config/config_entries/entry?domain=shelly'
    $wrappedEntries = Get-ObjectProperty -InputObject $response -Name 'entries'
    if ($null -ne $wrappedEntries) {
        $response = $wrappedEntries
    }

    # Invoke-RestMethod deliberately returns a JSON top-level array as one
    # pipeline object. Emit each config entry individually so callers never see
    # one Object[] whose member-access expression expands to every entry_id.
    foreach ($entry in [object[]]$response) {
        $entryId = Get-ObjectProperty -InputObject $entry -Name 'entry_id'
        if ($entryId -isnot [string] -or [string]::IsNullOrWhiteSpace($entryId)) {
            $entryType = if ($null -eq $entry) { '<null>' } else { $entry.GetType().FullName }
            throw "Home Assistant returned a Shelly config-entry item without a scalar entry_id (item type: $entryType)."
        }
        Write-Output $entry
    }
}

function Get-FlowSchemaDefault {
    param(
        [Parameter(Mandatory)] [object] $Flow,
        [Parameter(Mandatory)] [string] $Name,
        [AllowNull()] [object] $Fallback = $null
    )

    foreach ($field in @($Flow.data_schema)) {
        if ([string]$field.name -eq $Name) {
            $defaultValue = Get-ObjectProperty -InputObject $field -Name 'default'
            if ($null -ne $defaultValue) {
                return $defaultValue
            }
            return $Fallback
        }
    }
    return $Fallback
}

function Start-HaEntryFlow {
    param(
        [Parameter(Mandatory)] [string] $HomeAssistantUrl,
        [Parameter(Mandatory)] [string] $Token,
        [Parameter(Mandatory)] [string] $EntryId
    )

    Invoke-HaRequest -HomeAssistantUrl $HomeAssistantUrl -Token $Token -Method Post -Path '/api/config/config_entries/flow' -Body @{
        handler  = 'shelly'
        entry_id = $EntryId
    }
}

function Stop-HaEntryFlow {
    param(
        [Parameter(Mandatory)] [string] $HomeAssistantUrl,
        [Parameter(Mandatory)] [string] $Token,
        [Parameter(Mandatory)] [string] $FlowId
    )

    $null = Invoke-HaRequest -HomeAssistantUrl $HomeAssistantUrl -Token $Token -Method Delete -Path "/api/config/config_entries/flow/$FlowId"
}

function Get-HaShellyInventory {
    param(
        [Parameter(Mandatory)] [string] $HomeAssistantUrl,
        [Parameter(Mandatory)] [string] $Token
    )

    $inventory = foreach ($entry in Get-HaEntries -HomeAssistantUrl $HomeAssistantUrl -Token $Token) {
        $entryId = [string](Get-ObjectProperty -InputObject $entry -Name 'entry_id')
        $flow = Start-HaEntryFlow -HomeAssistantUrl $HomeAssistantUrl -Token $Token -EntryId $entryId
        try {
            if ($flow.type -ne 'form' -or $flow.step_id -ne 'reconfigure') {
                throw "Home Assistant did not return the expected Shelly reconfigure form for '$($entry.title)'."
            }
            $entryHost = Get-FlowSchemaDefault -Flow $flow -Name 'host'
            if ([string]::IsNullOrWhiteSpace([string]$entryHost)) {
                throw "The Shelly reconfigure form for '$($entry.title)' did not contain a host."
            }

            [pscustomobject]@{
                EntryId   = $entryId
                Title     = [string]$entry.title
                State     = [string]$entry.state
                Host      = [string]$entryHost
                Port      = [int](Get-FlowSchemaDefault -Flow $flow -Name 'port' -Fallback 80)
                VerifySsl = [bool](Get-FlowSchemaDefault -Flow $flow -Name 'verify_ssl' -Fallback $false)
            }
        }
        finally {
            Stop-HaEntryFlow -HomeAssistantUrl $HomeAssistantUrl -Token $Token -FlowId $flow.flow_id
        }
    }

    @($inventory)
}

function Set-HaShellyAddress {
    param(
        [Parameter(Mandatory)] [string] $HomeAssistantUrl,
        [Parameter(Mandatory)] [string] $Token,
        [Parameter(Mandatory)] [string] $EntryId,
        [Parameter(Mandatory)] [Alias('Host')] [string] $DeviceAddress,
        [Parameter(Mandatory)] [int] $Port,
        [bool] $VerifySsl = $false
    )

    $flow = Start-HaEntryFlow -HomeAssistantUrl $HomeAssistantUrl -Token $Token -EntryId $EntryId
    try {
        $result = Invoke-HaRequest -HomeAssistantUrl $HomeAssistantUrl -Token $Token -Method Post -Path "/api/config/config_entries/flow/$($flow.flow_id)" -Body @{
            host       = $DeviceAddress
            port       = $Port
            verify_ssl = $VerifySsl
        }
        $resultType = Get-ObjectProperty -InputObject $result -Name 'type'
        $reason = Get-ObjectProperty -InputObject $result -Name 'reason'
        if ($resultType -ne 'abort' -or $reason -notin @('reconfigure_successful', 'already_configured')) {
            $errors = Get-ObjectProperty -InputObject $result -Name 'errors' | ConvertTo-Json -Compress
            throw "Home Assistant rejected the Shelly address update: type=$resultType, reason=$reason, errors=$errors"
        }
    }
    finally {
        if ($flow.flow_id) {
            try {
                Stop-HaEntryFlow -HomeAssistantUrl $HomeAssistantUrl -Token $Token -FlowId $flow.flow_id
            }
            catch {
                # A successful flow removes itself.
            }
        }
    }
}

function Invoke-HaEntryReload {
    param(
        [Parameter(Mandatory)] [string] $HomeAssistantUrl,
        [Parameter(Mandatory)] [string] $Token,
        [Parameter(Mandatory)] [string] $EntryId
    )

    $null = Invoke-HaRequest -HomeAssistantUrl $HomeAssistantUrl -Token $Token -Method Post -Path "/api/config/config_entries/entry/$EntryId/reload" -Body @{}
}

function Send-WebSocketJson {
    param(
        [Parameter(Mandatory)] [Net.WebSockets.ClientWebSocket] $Socket,
        [Parameter(Mandatory)] [object] $Value
    )

    $bytes = [Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 20 -Compress))
    $segment = [ArraySegment[byte]]::new($bytes)
    $null = $Socket.SendAsync($segment, [Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
}

function Receive-WebSocketJson {
    param([Parameter(Mandatory)] [Net.WebSockets.ClientWebSocket] $Socket)

    $stream = [IO.MemoryStream]::new()
    try {
        do {
            $buffer = [byte[]]::new(16384)
            $segment = [ArraySegment[byte]]::new($buffer)
            $result = $Socket.ReceiveAsync($segment, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
            if ($result.MessageType -eq [Net.WebSockets.WebSocketMessageType]::Close) {
                throw 'Home Assistant closed the WebSocket connection.'
            }
            $stream.Write($buffer, 0, $result.Count)
        } until ($result.EndOfMessage)

        [Text.Encoding]::UTF8.GetString($stream.ToArray()) | ConvertFrom-Json
    }
    finally {
        $stream.Dispose()
    }
}

function Invoke-HaWebSocketCommand {
    param(
        [Parameter(Mandatory)] [string] $HomeAssistantWebSocketUrl,
        [Parameter(Mandatory)] [string] $Token,
        [Parameter(Mandatory)] [hashtable] $Command
    )

    $webSocketUri = [Uri]$HomeAssistantWebSocketUrl
    if ($webSocketUri.Scheme -notin @('ws', 'wss')) {
        throw "Home Assistant WebSocket URL must use ws:// or wss://: $HomeAssistantWebSocketUrl"
    }

    $socket = [Net.WebSockets.ClientWebSocket]::new()
    $socket.Options.RemoteCertificateValidationCallback = { $true }
    try {
        try {
            $null = $socket.ConnectAsync($webSocketUri, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
        }
        catch {
            $detail = $_.Exception.GetBaseException().Message
            throw "Unable to connect to the Home Assistant WebSocket at '$HomeAssistantWebSocketUrl': $detail"
        }
        $hello = Receive-WebSocketJson -Socket $socket
        if ($hello.type -ne 'auth_required') {
            throw "Unexpected Home Assistant WebSocket greeting '$($hello.type)'."
        }
        Send-WebSocketJson -Socket $socket -Value @{ type = 'auth'; access_token = $Token }
        $auth = Receive-WebSocketJson -Socket $socket
        if ($auth.type -ne 'auth_ok') {
            throw 'Home Assistant rejected the WebSocket access token.'
        }

        $payload = @{} + $Command
        $payload.id = 1
        Send-WebSocketJson -Socket $socket -Value $payload
        do {
            $response = Receive-WebSocketJson -Socket $socket
        } until ($response.id -eq 1)
        if (-not $response.success) {
            throw "Home Assistant WebSocket command '$($Command.type)' failed."
        }
        return $response.result
    }
    finally {
        if ($socket.State -eq [Net.WebSockets.WebSocketState]::Open) {
            try {
                $null = $socket.CloseAsync([Net.WebSockets.WebSocketCloseStatus]::NormalClosure, 'done', [Threading.CancellationToken]::None).GetAwaiter().GetResult()
            }
            catch {
                $socket.Abort()
            }
        }
        $socket.Dispose()
    }
}

function Wait-HaReauthFlow {
    param(
        [Parameter(Mandatory)] [string] $HomeAssistantWebSocketUrl,
        [Parameter(Mandatory)] [string] $Token,
        [Parameter(Mandatory)] [string] $EntryId,
        [ValidateRange(5, 120)] [int] $TimeoutSeconds = 45
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $flows = @(Invoke-HaWebSocketCommand -HomeAssistantWebSocketUrl $HomeAssistantWebSocketUrl -Token $Token -Command @{ type = 'config_entries/flow/progress' })
        $flow = $flows | Where-Object {
            $_.handler -eq 'shelly' -and
            $_.context.source -eq 'reauth' -and
            $_.context.entry_id -eq $EntryId
        } | Select-Object -First 1
        if ($flow) {
            return $flow
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "Home Assistant did not create a Shelly reauthentication flow within $TimeoutSeconds seconds."
}

function Complete-HaReauth {
    param(
        [Parameter(Mandatory)] [string] $HomeAssistantUrl,
        [Parameter(Mandatory)] [string] $HomeAssistantWebSocketUrl,
        [Parameter(Mandatory)] [string] $Token,
        [Parameter(Mandatory)] [string] $EntryId,
        [Parameter(Mandatory)] [int] $Generation,
        [Parameter(Mandatory)] [string] $Password
    )

    Invoke-HaEntryReload -HomeAssistantUrl $HomeAssistantUrl -Token $Token -EntryId $EntryId
    $flow = Wait-HaReauthFlow -HomeAssistantWebSocketUrl $HomeAssistantWebSocketUrl -Token $Token -EntryId $EntryId
    $body = @{ password = $Password }
    if ($Generation -eq 1) {
        $body.username = 'admin'
    }
    $result = Invoke-HaRequest -HomeAssistantUrl $HomeAssistantUrl -Token $Token -Method Post -Path "/api/config/config_entries/flow/$($flow.flow_id)" -Body $body
    $resultType = Get-ObjectProperty -InputObject $result -Name 'type'
    $reason = Get-ObjectProperty -InputObject $result -Name 'reason'
    if ($resultType -ne 'abort' -or $reason -notin @('reauth_successful', 'already_configured')) {
        throw "Home Assistant Shelly reauthentication failed: type=$resultType, reason=$reason."
    }
}

function Wait-HaEntryLoaded {
    param(
        [Parameter(Mandatory)] [string] $HomeAssistantUrl,
        [Parameter(Mandatory)] [string] $Token,
        [Parameter(Mandatory)] [string] $EntryId,
        [ValidateRange(5, 120)] [int] $TimeoutSeconds = 45
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $entry = Get-HaEntries -HomeAssistantUrl $HomeAssistantUrl -Token $Token | Where-Object entry_id -eq $EntryId
        if ($entry -and (Get-ObjectProperty -InputObject $entry -Name 'state') -eq 'loaded') {
            return $true
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    return $false
}

function Normalize-MacAddress {
    param([Parameter(Mandatory)] [string] $MacAddress)

    $normalized = ($MacAddress -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($normalized -notmatch '^[0-9A-F]{12}$') {
        throw "Invalid MAC address '$MacAddress'."
    }
    return $normalized
}

function New-ShellyBaseUri {
    param(
        [Parameter(Mandatory)] [Alias('Host')] [string] $DeviceAddress,
        [Parameter(Mandatory)] [int] $Port
    )

    $scheme = if ($Port -eq 443) { 'https' } else { 'http' }
    if (($scheme -eq 'http' -and $Port -eq 80) -or ($scheme -eq 'https' -and $Port -eq 443)) {
        return "${scheme}://$DeviceAddress"
    }
    return "${scheme}://${DeviceAddress}:$Port"
}

function New-ShellyCredential {
    param([Parameter(Mandatory)] [string] $Password)

    [Management.Automation.PSCredential]::new('admin', (ConvertTo-SecureString $Password -AsPlainText -Force))
}

function Invoke-ShellyDigestJsonRequest {
    param(
        [Parameter(Mandatory)] [uri] $Uri,
        [Parameter(Mandatory)] [ValidateSet('Get', 'Post')] [string] $Method,
        [Parameter(Mandatory)] [object] $Body,
        [Parameter(Mandatory)] [string] $Password,
        [ValidateRange(1, 30)] [int] $TimeoutSeconds = 8
    )

    # HttpClientHandler performs the RFC 7616 challenge/response exchange used
    # by Gen2+ devices. PowerShell's -Authentication parameter has no Digest mode.
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.Credentials = [Net.NetworkCredential]::new('admin', $Password)
    $handler.ServerCertificateCustomValidationCallback = { $true }
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    try {
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::$Method, $Uri)
        try {
            $json = $Body | ConvertTo-Json -Depth 20 -Compress
            $request.Content = [Net.Http.StringContent]::new($json, [Text.Encoding]::UTF8, 'application/json')
            $response = $client.Send($request)
            try {
                $content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                if (-not $response.IsSuccessStatusCode) {
                    throw "Shelly request to $Uri failed with HTTP $([int]$response.StatusCode): $content"
                }
                if ([string]::IsNullOrWhiteSpace($content)) {
                    return $null
                }
                return $content | ConvertFrom-Json
            }
            finally {
                $response.Dispose()
            }
        }
        finally {
            $request.Dispose()
        }
    }
    finally {
        $client.Dispose()
        $handler.Dispose()
    }
}

function Invoke-ShellyRequest {
    param(
        [Parameter(Mandatory)] [Alias('Host')] [string] $DeviceAddress,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [ValidateSet('Get', 'Post')] [string] $Method,
        [Parameter(Mandatory)] [string] $Path,
        [AllowNull()] [object] $Body,
        [ValidateSet('None', 'Basic', 'Digest')] [string] $Authentication = 'None',
        [AllowNull()] [string] $Password,
        [ValidateSet('Json', 'Form')] [string] $BodyType = 'Json',
        [ValidateRange(1, 30)] [int] $TimeoutSeconds = 8
    )

    if ($Authentication -eq 'Digest') {
        if ($BodyType -ne 'Json' -or -not $PSBoundParameters.ContainsKey('Body')) {
            throw 'Shelly Digest requests require a JSON body.'
        }
        if ([string]::IsNullOrEmpty($Password)) {
            throw 'A password is required for an authenticated Shelly request.'
        }
        $uri = [uri](Join-ApiUri (New-ShellyBaseUri -Host $DeviceAddress -Port $Port) $Path)
        return Invoke-ShellyDigestJsonRequest -Uri $uri -Method $Method -Body $Body -Password $Password -TimeoutSeconds $TimeoutSeconds
    }

    $parameters = @{
        Uri                  = Join-ApiUri (New-ShellyBaseUri -Host $DeviceAddress -Port $Port) $Path
        Method               = $Method
        SkipCertificateCheck = $true
        TimeoutSec           = $TimeoutSeconds
        ErrorAction          = 'Stop'
    }
    if ($Authentication -ne 'None') {
        if ([string]::IsNullOrEmpty($Password)) {
            throw 'A password is required for an authenticated Shelly request.'
        }
        $parameters.Authentication = $Authentication
        $parameters.Credential = New-ShellyCredential -Password $Password
        if ($Authentication -eq 'Basic' -and $Port -ne 443) {
            $parameters.AllowUnencryptedAuthentication = $true
        }
    }
    if ($PSBoundParameters.ContainsKey('Body')) {
        if ($BodyType -eq 'Json') {
            $parameters.ContentType = 'application/json'
            $parameters.Body = $Body | ConvertTo-Json -Depth 20 -Compress
        }
        else {
            $parameters.ContentType = 'application/x-www-form-urlencoded'
            $parameters.Body = $Body
        }
    }

    Invoke-RestMethod @parameters
}

function Get-ShellyIdentity {
    param(
        [Parameter(Mandatory)] [Alias('Host')] [string] $DeviceAddress,
        [Parameter(Mandatory)] [int] $Port
    )

    $info = Invoke-ShellyRequest -Host $DeviceAddress -Port $Port -Method Get -Path '/shelly' -TimeoutSeconds 5
    $generationValue = Get-ObjectProperty -InputObject $info -Name 'gen'
    $generation = if ($null -ne $generationValue) { [int]$generationValue } else { 1 }
    $mac = Normalize-MacAddress -MacAddress ([string](Get-ObjectProperty -InputObject $info -Name 'mac'))
    $model = Get-ObjectProperty -InputObject $info -Name 'model'
    if (-not $model) {
        $model = Get-ObjectProperty -InputObject $info -Name 'type'
    }
    [pscustomobject]@{
        Host       = $DeviceAddress
        Port       = $Port
        Mac        = $mac
        Generation = $generation
        Realm      = if ($generation -gt 1) { [string](Get-ObjectProperty -InputObject $info -Name 'id') } else { [string](Get-ObjectProperty -InputObject $info -Name 'hostname') }
        Model      = [string]$model
        Protected  = [bool]((Get-ObjectProperty -InputObject $info -Name 'auth_en' -Default $false) -or (Get-ObjectProperty -InputObject $info -Name 'auth' -Default $false))
    }
}

function Invoke-ShellyRpc {
    param(
        [Parameter(Mandatory)] [object] $Device,
        [Parameter(Mandatory)] [string] $Method,
        [hashtable] $Parameters = @{},
        [AllowNull()] [string] $Password
    )

    $authentication = if ($Device.Protected) { 'Digest' } else { 'None' }
    $response = Invoke-ShellyRequest -Host $Device.Host -Port $Device.Port -Method Post -Path '/rpc' -Body @{
        id     = 1
        method = $Method
        params = $Parameters
    } -Authentication $authentication -Password $Password -BodyType Json
    $rpcError = Get-ObjectProperty -InputObject $response -Name 'error'
    if ($rpcError) {
        $errorCode = Get-ObjectProperty -InputObject $rpcError -Name 'code'
        $errorMessage = Get-ObjectProperty -InputObject $rpcError -Name 'message' -Default 'Unknown RPC error'
        throw "Shelly RPC '$Method' failed: code=$errorCode, message=$errorMessage"
    }
    $result = Get-ObjectProperty -InputObject $response -Name 'result'
    if ($null -ne $result) {
        return $result
    }
    $responseParameters = Get-ObjectProperty -InputObject $response -Name 'params'
    if ($null -ne $responseParameters) {
        return $responseParameters
    }
    return $response
}

function Get-ShellySettings {
    param(
        [Parameter(Mandatory)] [object] $Device,
        [AllowNull()] [string] $Password
    )

    if ($Device.Generation -eq 1) {
        $auth = if ($Device.Protected) { 'Basic' } else { 'None' }
        return Invoke-ShellyRequest -Host $Device.Host -Port $Device.Port -Method Get -Path '/settings' -Authentication $auth -Password $Password
    }

    [pscustomobject]@{
        Wifi  = Invoke-ShellyRpc -Device $Device -Method 'Wifi.GetConfig' -Password $Password
        Sys   = Invoke-ShellyRpc -Device $Device -Method 'Sys.GetConfig' -Password $Password
        Cloud = Invoke-ShellyRpc -Device $Device -Method 'Cloud.GetConfig' -Password $Password
    }
}

function Get-ShellyPrimarySsid {
    param(
        [Parameter(Mandatory)] [object] $Device,
        [AllowNull()] [string] $Password
    )

    $settings = Get-ShellySettings -Device $Device -Password $Password
    if ($Device.Generation -eq 1) {
        $primary = Get-ObjectProperty -InputObject $settings -Name 'wifi_sta'
    }
    else {
        $wifi = Get-ObjectProperty -InputObject $settings -Name 'Wifi'
        $primary = Get-ObjectProperty -InputObject $wifi -Name 'sta'
    }
    $ssid = [string](Get-ObjectProperty -InputObject $primary -Name 'ssid')
    if ([string]::IsNullOrWhiteSpace($ssid)) {
        throw 'The Shelly did not report its current primary WLAN SSID.'
    }
    return $ssid
}

function Set-ShellyFallbackWifi {
    param(
        [Parameter(Mandatory)] [object] $Device,
        [Parameter(Mandatory)] [string] $Ssid,
        [Parameter(Mandatory)] [string] $WifiPassword,
        [AllowNull()] [string] $Password
    )

    if ($Device.Generation -eq 1) {
        $auth = if ($Device.Protected) { 'Basic' } else { 'None' }
        $null = Invoke-ShellyRequest -Host $Device.Host -Port $Device.Port -Method Post -Path '/settings/sta1' -BodyType Form -Body @{
            enabled     = 1
            ssid        = $Ssid
            key         = $WifiPassword
            ipv4_method = 'dhcp'
        } -Authentication $auth -Password $Password
        $config = Invoke-ShellyRequest -Host $Device.Host -Port $Device.Port -Method Get -Path '/settings/sta1' -Authentication $auth -Password $Password
        if (-not (Get-ObjectProperty -InputObject $config -Name 'enabled') -or (Get-ObjectProperty -InputObject $config -Name 'ssid') -cne $Ssid) {
            throw 'The Gen1 fallback Wi-Fi configuration did not pass read-back validation.'
        }
        return
    }

    $null = Invoke-ShellyRpc -Device $Device -Method 'Wifi.SetConfig' -Parameters @{
        config = @{
            sta1 = @{
                enable   = $true
                ssid     = $Ssid
                pass     = $WifiPassword
                ipv4mode = 'dhcp'
            }
        }
    } -Password $Password
    $config = Invoke-ShellyRpc -Device $Device -Method 'Wifi.GetConfig' -Password $Password
    $sta1 = Get-ObjectProperty -InputObject $config -Name 'sta1'
    if (-not $sta1 -or -not (Get-ObjectProperty -InputObject $sta1 -Name 'enable') -or (Get-ObjectProperty -InputObject $sta1 -Name 'ssid') -cne $Ssid) {
        throw 'The Gen2+ fallback Wi-Fi configuration did not pass read-back validation.'
    }
}

function Set-ShellyPrimaryWifi {
    param(
        [Parameter(Mandatory)] [object] $Device,
        [Parameter(Mandatory)] [string] $Ssid,
        [Parameter(Mandatory)] [string] $WifiPassword,
        [AllowNull()] [string] $Password
    )

    if ($Device.Generation -eq 1) {
        $auth = if ($Device.Protected) { 'Basic' } else { 'None' }
        $null = Invoke-ShellyRequest -Host $Device.Host -Port $Device.Port -Method Post -Path '/settings/sta' -BodyType Form -Body @{
            enabled     = 1
            ssid        = $Ssid
            key         = $WifiPassword
            ipv4_method = 'dhcp'
        } -Authentication $auth -Password $Password
        return
    }

    $null = Invoke-ShellyRpc -Device $Device -Method 'Wifi.SetConfig' -Parameters @{
        config = @{
            sta = @{
                enable   = $true
                ssid     = $Ssid
                pass     = $WifiPassword
                ipv4mode = 'dhcp'
            }
        }
    } -Password $Password
}

function Disable-ShellyFallbackWifi {
    param(
        [Parameter(Mandatory)] [object] $Device,
        [AllowNull()] [string] $Password
    )

    if ($Device.Generation -eq 1) {
        $auth = if ($Device.Protected) { 'Basic' } else { 'None' }
        $null = Invoke-ShellyRequest -Host $Device.Host -Port $Device.Port -Method Post -Path '/settings/sta1' -BodyType Form -Body @{ enabled = 0 } -Authentication $auth -Password $Password
        return
    }

    $null = Invoke-ShellyRpc -Device $Device -Method 'Wifi.SetConfig' -Parameters @{ config = @{ sta1 = @{ enable = $false } } } -Password $Password
}

function Set-ShellyCoIoT {
    param(
        [Parameter(Mandatory)] [object] $Device,
        [Parameter(Mandatory)] [string] $Peer,
        [AllowNull()] [string] $Password
    )

    if ($Device.Generation -ne 1) {
        return
    }
    $auth = if ($Device.Protected) { 'Basic' } else { 'None' }
    $null = Invoke-ShellyRequest -Host $Device.Host -Port $Device.Port -Method Post -Path '/settings' -BodyType Form -Body @{
        coiot_enable = 1
        coiot_peer   = $Peer
    } -Authentication $auth -Password $Password
}

function Disable-ShellyCloud {
    param(
        [Parameter(Mandatory)] [object] $Device,
        [AllowNull()] [string] $Password
    )

    if ($Device.Generation -eq 1) {
        $auth = if ($Device.Protected) { 'Basic' } else { 'None' }
        $null = Invoke-ShellyRequest -Host $Device.Host -Port $Device.Port -Method Post -Path '/settings/cloud' -BodyType Form -Body @{ enabled = 0 } -Authentication $auth -Password $Password
        return
    }

    $null = Invoke-ShellyRpc -Device $Device -Method 'Cloud.SetConfig' -Parameters @{ config = @{ enable = $false } } -Password $Password
}

function Test-ShellyTimeSynchronized {
    param(
        [Parameter(Mandatory)] [object] $Device,
        [AllowNull()] [string] $Password
    )

    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if ($Device.Generation -eq 1) {
        $auth = if ($Device.Protected) { 'Basic' } else { 'None' }
        $status = Invoke-ShellyRequest -Host $Device.Host -Port $Device.Port -Method Get -Path '/status' -Authentication $auth -Password $Password
        $unixTime = Get-ObjectProperty -InputObject $status -Name 'unixtime'
        return $unixTime -and ([Math]::Abs([long]$unixTime - $now) -lt 180)
    }

    $status = Invoke-ShellyRpc -Device $Device -Method 'Sys.GetStatus' -Password $Password
    $unixTime = Get-ObjectProperty -InputObject $status -Name 'unixtime'
    return $unixTime -and ([Math]::Abs([long]$unixTime - $now) -lt 180)
}

function Set-ShellyNtp {
    param(
        [Parameter(Mandatory)] [object] $Device,
        [Parameter(Mandatory)] [string[]] $Servers,
        [AllowNull()] [string] $Password
    )

    foreach ($server in $Servers) {
        $configured = $false
        foreach ($configurationAttempt in 1..3) {
            try {
                if ($Device.Generation -eq 1) {
                    $auth = if ($Device.Protected) { 'Basic' } else { 'None' }
                    $null = Invoke-ShellyRequest -Host $Device.Host -Port $Device.Port -Method Post -Path '/settings' -BodyType Form -Body @{ sntp_server = $server } -Authentication $auth -Password $Password
                }
                else {
                    $null = Invoke-ShellyRpc -Device $Device -Method 'Sys.SetConfig' -Parameters @{ config = @{ sntp = @{ server = $server } } } -Password $Password
                }
                $configured = $true
                break
            }
            catch {
                if ($configurationAttempt -lt 3) {
                    Start-Sleep -Seconds 2
                }
            }
        }
        if (-not $configured) {
            continue
        }

        foreach ($attempt in 1..5) {
            Start-Sleep -Seconds 3
            try {
                if (Test-ShellyTimeSynchronized -Device $Device -Password $Password) {
                    return $server
                }
            }
            catch { }
        }
    }

    return $null
}

function Get-Sha256Hex {
    param([Parameter(Mandatory)] [string] $Value)

    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))
        return ([Convert]::ToHexString($hash)).ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
}

function Enable-ShellyAuthentication {
    param(
        [Parameter(Mandatory)] [object] $Device,
        [Parameter(Mandatory)] [string] $Password
    )

    if ($Device.Generation -eq 1) {
        $null = Invoke-ShellyRequest -Host $Device.Host -Port $Device.Port -Method Post -Path '/settings/login' -BodyType Form -Body @{
            enabled     = 1
            unprotected = 0
            username    = 'admin'
            password    = $Password
        }
    }
    else {
        if ([string]::IsNullOrWhiteSpace($Device.Realm)) {
            throw 'The Gen2+ Shelly did not report an authentication realm.'
        }
        $ha1 = Get-Sha256Hex -Value "admin:$($Device.Realm):$Password"
        $null = Invoke-ShellyRpc -Device $Device -Method 'Shelly.SetAuth' -Parameters @{
            user  = 'admin'
            realm = $Device.Realm
            ha1   = $ha1
        }
    }

    $protected = Get-ShellyIdentity -Host $Device.Host -Port $Device.Port
    if (-not $protected.Protected) {
        throw 'The Shelly did not report authentication as enabled.'
    }
    $null = Get-ShellySettings -Device $protected -Password $Password
    return $protected
}

function Disable-ShellyAuthentication {
    param(
        [Parameter(Mandatory)] [object] $Device,
        [Parameter(Mandatory)] [string] $Password
    )

    if ($Device.Generation -eq 1) {
        $null = Invoke-ShellyRequest -Host $Device.Host -Port $Device.Port -Method Post -Path '/settings/login' -BodyType Form -Body @{ enabled = 0 } -Authentication Basic -Password $Password
        return
    }

    $null = Invoke-ShellyRpc -Device $Device -Method 'Shelly.SetAuth' -Parameters @{
        user  = 'admin'
        realm = $Device.Realm
        ha1   = $null
    } -Password $Password
}

function Protect-ShellyAndHomeAssistant {
    param(
        [Parameter(Mandatory)] [object] $Device,
        [Parameter(Mandatory)] [object] $InventoryEntry,
        [Parameter(Mandatory)] [string] $HomeAssistantUrl,
        [Parameter(Mandatory)] [string] $HomeAssistantWebSocketUrl,
        [Parameter(Mandatory)] [string] $Token,
        [Parameter(Mandatory)] [string] $Password
    )

    $enabledHere = -not $Device.Protected
    if ($Device.Protected) {
        $null = Get-ShellySettings -Device $Device -Password $Password
        if (Wait-HaEntryLoaded -HomeAssistantUrl $HomeAssistantUrl -Token $Token -EntryId $InventoryEntry.EntryId -TimeoutSeconds 5) {
            return $Device
        }
    }
    else {
        $Device = Enable-ShellyAuthentication -Device $Device -Password $Password
    }

    try {
        Complete-HaReauth -HomeAssistantUrl $HomeAssistantUrl -HomeAssistantWebSocketUrl $HomeAssistantWebSocketUrl -Token $Token -EntryId $InventoryEntry.EntryId -Generation $Device.Generation -Password $Password
        if (-not (Wait-HaEntryLoaded -HomeAssistantUrl $HomeAssistantUrl -Token $Token -EntryId $InventoryEntry.EntryId)) {
            throw 'Home Assistant did not return the Shelly entry to loaded state.'
        }
        return $Device
    }
    catch {
        if ($enabledHere) {
            Write-Warning "Home Assistant reauthentication failed for '$($InventoryEntry.Title)'; disabling the authentication enabled by this run."
            Disable-ShellyAuthentication -Device $Device -Password $Password
        }
        else {
            Write-Warning "Home Assistant reauthentication failed for '$($InventoryEntry.Title)'. Existing device authentication was left enabled."
        }
        Invoke-HaEntryReload -HomeAssistantUrl $HomeAssistantUrl -Token $Token -EntryId $InventoryEntry.EntryId
        throw
    }
}

function Get-CidrHosts {
    param([Parameter(Mandatory)] [string] $Cidr)

    $parts = $Cidr.Split('/')
    if ($parts.Count -ne 2) {
        throw "Invalid CIDR '$Cidr'."
    }
    $address = [Net.IPAddress]::Parse($parts[0])
    if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'Only IPv4 CIDRs are supported.'
    }
    $prefix = [int]$parts[1]
    if ($prefix -lt 22 -or $prefix -gt 30) {
        throw 'The target CIDR must contain between 2 and 1022 usable IPv4 hosts (/30 through /22).'
    }

    $bytes = $address.GetAddressBytes()
    [uint64]$number = ([uint64]$bytes[0] * 16777216) + ([uint64]$bytes[1] * 65536) + ([uint64]$bytes[2] * 256) + $bytes[3]
    [uint64]$size = [Math]::Pow(2, 32 - $prefix)
    [uint64]$network = [Math]::Floor($number / $size) * $size
    for ([uint64]$value = $network + 1; $value -lt ($network + $size - 1); $value++) {
        '{0}.{1}.{2}.{3}' -f (($value -shr 24) -band 255), (($value -shr 16) -band 255), (($value -shr 8) -band 255), ($value -band 255)
    }
}

function Test-Ipv4AddressInCidr {
    param(
        [Parameter(Mandatory)] [string] $Address,
        [Parameter(Mandatory)] [string] $Cidr
    )

    @(Get-CidrHosts -Cidr $Cidr) -contains $Address
}

function Test-ShellyTargetPlacement {
    param(
        [Parameter(Mandatory)] [object] $Device,
        [Parameter(Mandatory)] [string] $CurrentSsid,
        [Parameter(Mandatory)] [string] $TargetSsid,
        [Parameter(Mandatory)] [string] $TargetSubnet
    )

    $CurrentSsid -ceq $TargetSsid -and (Test-Ipv4AddressInCidr -Address $Device.Host -Cidr $TargetSubnet)
}

function Find-ShellyDevicesInSubnet {
    param([Parameter(Mandatory)] [string] $Cidr)

    $hosts = @(Get-CidrHosts -Cidr $Cidr)
    @($hosts | ForEach-Object -Parallel {
        $hostAddress = $_
        $handler = [Net.Http.HttpClientHandler]::new()
        $handler.AllowAutoRedirect = $true
        $handler.ServerCertificateCustomValidationCallback = { $true }
        $client = [Net.Http.HttpClient]::new($handler)
        $client.Timeout = [TimeSpan]::FromSeconds(2)
        try {
            $response = $client.GetAsync("http://$hostAddress/shelly").GetAwaiter().GetResult()
            if (-not $response.IsSuccessStatusCode) {
                return
            }
            $json = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
            $mac = ([string]$json.mac -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
            if ($mac -notmatch '^[0-9A-F]{12}$') {
                return
            }
            $generation = if ($null -ne $json.gen) { [int]$json.gen } else { 1 }
            [pscustomobject]@{
                Host       = $hostAddress
                Port       = [int]$response.RequestMessage.RequestUri.Port
                Mac        = $mac
                Generation = $generation
                Realm      = if ($generation -gt 1) { [string]$json.id } else { [string]$json.hostname }
                Model      = if ($json.model) { [string]$json.model } else { [string]$json.type }
                Protected  = [bool]($json.auth_en -or $json.auth)
            }
        }
        catch {
            return
        }
        finally {
            $client.Dispose()
            $handler.Dispose()
        }
    } -ThrottleLimit 32)
}

function Wait-ForTargetDevices {
    param(
        [Parameter(Mandatory)] [object[]] $Devices,
        [Parameter(Mandatory)] [string] $TargetSubnet,
        [Parameter(Mandatory)] [int] $TimeoutSeconds
    )

    $wanted = @{}
    foreach ($device in $Devices) {
        $wanted[$device.Mac] = $true
    }
    $found = @{}
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        foreach ($candidate in Find-ShellyDevicesInSubnet -Cidr $TargetSubnet) {
            if ($wanted.ContainsKey($candidate.Mac)) {
                $found[$candidate.Mac] = $candidate
            }
        }
        if ($found.Count -eq $wanted.Count) {
            break
        }
        if ([DateTimeOffset]::UtcNow -lt $deadline) {
            Start-Sleep -Seconds 5
        }
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    return $found
}

function Wait-ShellyIdentity {
    param(
        [Parameter(Mandatory)] [Alias('Host')] [string] $DeviceAddress,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [string] $ExpectedMac,
        [ValidateRange(5, 120)] [int] $TimeoutSeconds = 45
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $identity = Get-ShellyIdentity -Host $DeviceAddress -Port $Port
            if ($identity.Mac -eq $ExpectedMac) {
                return $identity
            }
        }
        catch {
            Start-Sleep -Seconds 2
        }
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "Shelly $ExpectedMac did not reconnect at ${DeviceAddress}:$Port."
}

function Read-MigrationState {
    param([Parameter(Mandatory)] [string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return [ordered]@{
            version    = 1
            targetSsid = $null
            updatedAt  = $null
            devices    = @()
        }
    }
    Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -AsHashtable
}

function Write-MigrationState {
    param(
        [Parameter(Mandatory)] [Collections.IDictionary] $State,
        [Parameter(Mandatory)] [string] $Path
    )

    $State.updatedAt = [DateTimeOffset]::UtcNow.ToString('o')
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }
    $temporaryPath = "$Path.tmp"
    $State | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $temporaryPath -Encoding utf8NoBOM
    Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
}

function Set-MigrationCheckpoint {
    param(
        [Parameter(Mandatory)] [Collections.IDictionary] $State,
        [Parameter(Mandatory)] [object] $Entry,
        [Parameter(Mandatory)] [object] $Device,
        [Parameter(Mandatory)] [string] $Phase,
        [AllowNull()] [string] $NewIp,
        [AllowNull()] [Nullable[int]] $NewPort,
        [AllowNull()] [string] $OldSsid,
        [AllowNull()] [string] $ErrorMessage
    )

    $existing = @($State.devices | Where-Object { $_.entryId -eq $Entry.EntryId }) | Select-Object -First 1
    $recordOldIp = Get-ObjectProperty -InputObject $existing -Name 'oldIp' -Default $Entry.Host
    $recordOldSsid = if ($PSBoundParameters.ContainsKey('OldSsid')) {
        $OldSsid
    }
    else {
        Get-ObjectProperty -InputObject $existing -Name 'oldSsid'
    }
    $record = [ordered]@{
        entryId    = $Entry.EntryId
        title      = $Entry.Title
        mac        = $Device.Mac
        generation = $Device.Generation
        oldIp      = $recordOldIp
        oldSsid    = $recordOldSsid
        newIp      = $NewIp
        newPort    = $NewPort
        phase      = $Phase
        error      = $ErrorMessage
    }
    $State.devices = @($State.devices | Where-Object { $_.entryId -ne $Entry.EntryId }) + @($record)
}

function Resolve-InventoryFromState {
    param(
        [Parameter(Mandatory)] [object[]] $Inventory,
        [Parameter(Mandatory)] [Collections.IDictionary] $State
    )

    foreach ($entry in $Inventory) {
        $record = @($State.devices | Where-Object { $_.entryId -eq $entry.EntryId }) | Select-Object -First 1
        $newIp = Get-ObjectProperty -InputObject $record -Name 'newIp'
        $newPort = Get-ObjectProperty -InputObject $record -Name 'newPort'
        $phase = Get-ObjectProperty -InputObject $record -Name 'phase'
        if ($record -and $newIp -and $phase -in @('discovered', 'finalize_failed')) {
            $entry.Host = [string]$newIp
            if ($newPort) {
                $entry.Port = [int]$newPort
            }
        }
    }
    return $Inventory
}

function Select-InventoryEntries {
    param(
        [Parameter(Mandatory)] [object[]] $Inventory,
        [string[]] $DeviceTitle,
        [int] $Limit = 0
    )

    $selected = @($Inventory | Sort-Object Title)
    if ($DeviceTitle) {
        $selected = @($selected | Where-Object {
            $title = $_.Title
            @($DeviceTitle | Where-Object { $title -like $_ }).Count -gt 0
        })
    }
    if ($Limit -gt 0) {
        $selected = @($selected | Select-Object -First $Limit)
    }
    return $selected
}

function Get-ReachableInventory {
    param([Parameter(Mandatory)] [object[]] $Inventory)

    $result = foreach ($entry in $Inventory) {
        try {
            $device = Get-ShellyIdentity -Host $entry.Host -Port $entry.Port
            [pscustomobject]@{ Entry = $entry; Device = $device; Error = $null }
        }
        catch {
            [pscustomobject]@{ Entry = $entry; Device = $null; Error = $_.Exception.Message }
        }
    }
    @($result)
}

function Show-Audit {
    param([Parameter(Mandatory)] [object[]] $Reachability)

    $rows = foreach ($item in $Reachability) {
        [pscustomobject]@{
            Title      = $item.Entry.Title
            Host       = "$($item.Entry.Host):$($item.Entry.Port)"
            Generation = if ($item.Device) { "Gen$($item.Device.Generation)" } else { '-' }
            Protected  = if ($item.Device) { $item.Device.Protected } else { '-' }
            HAState    = $item.Entry.State
            Reachable  = [bool]$item.Device
            Error      = $item.Error
        }
    }
    $rows | Format-Table -AutoSize
}

function Invoke-ShellyMigration {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidateSet('Audit', 'Migrate', 'Protect', 'Verify', 'RollbackStaged')]
        [string] $Mode = 'Audit',
        [string] $HomeAssistantUrl = 'https://homeassistant.example.invalid',
        [string] $HomeAssistantIp = '192.168.178.10',
        [string] $HomeAssistantWebSocketUrl,
        [string] $TargetSubnet = '192.168.20.0/24',
        [string[]] $NtpServers = @('192.53.103.103', '192.53.103.108'),
        [int] $BatchSize = 5,
        [string[]] $DeviceTitle,
        [int] $DiscoveryTimeoutSeconds = 300,
        [string] $StatePath = (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'ShellyVlanMigration\state.json')
    )

    if ([string]::IsNullOrWhiteSpace($HomeAssistantWebSocketUrl)) {
        $HomeAssistantWebSocketUrl = "ws://${HomeAssistantIp}:8123/api/websocket"
    }

    $token = Read-Secret -Prompt 'Home Assistant administrator token'
    try {
        $inventory = Get-HaShellyInventory -HomeAssistantUrl $HomeAssistantUrl -Token $token
        $inventory = Select-InventoryEntries -Inventory $inventory -DeviceTitle $DeviceTitle
        if (-not $inventory) {
            throw 'No matching Home Assistant Shelly entries were found.'
        }

        if ($Mode -eq 'Audit') {
            Show-Audit -Reachability (Get-ReachableInventory -Inventory $inventory)
            return
        }

        $devicePassword = Read-ConfirmedSecret -Prompt 'Shared Shelly administration password' -MinimumLength 16 -MaximumLength 50 -PrintableAscii

        if ($Mode -eq 'Verify') {
            $currentEntries = Get-HaEntries -HomeAssistantUrl $HomeAssistantUrl -Token $token
            $rows = foreach ($item in Get-ReachableInventory -Inventory $inventory) {
                $authenticated = $false
                $details = $null
                if ($item.Device) {
                    try {
                        $details = Get-ShellySettings -Device $item.Device -Password $devicePassword
                        $authenticated = $true
                    }
                    catch {
                        $details = $null
                    }
                }
                $currentEntry = $currentEntries | Where-Object entry_id -eq $item.Entry.EntryId
                [pscustomobject]@{
                    Title         = $item.Entry.Title
                    Host          = if ($item.Device) { $item.Device.Host } else { $item.Entry.Host }
                    Protected     = if ($item.Device) { $item.Device.Protected } else { '-' }
                    Authenticated = $authenticated
                    HAState       = if ($currentEntry) { Get-ObjectProperty -InputObject $currentEntry -Name 'state' -Default 'unknown' } else { 'missing' }
                    Reachable     = [bool]$item.Device
                }
            }
            $rows | Format-Table -AutoSize
            return
        }

        if ($Mode -eq 'Protect') {
            $reachability = @(Get-ReachableInventory -Inventory $inventory)
            foreach ($item in $reachability | Where-Object { -not $_.Device }) {
                Write-Warning "Skipping '$($item.Entry.Title)': $($item.Error)"
            }
            $selected = @($reachability | Where-Object {
                $_.Device -and (-not $_.Device.Protected -or $_.Entry.State -ne 'loaded')
            } | Select-Object -First $BatchSize)
            if (-not $selected) {
                Write-Host 'No reachable Shelly devices still require protection or Home Assistant reauthentication.' -ForegroundColor Yellow
                return
            }
            foreach ($item in $selected) {
                if ($PSCmdlet.ShouldProcess($item.Entry.Title, 'Enable Shelly authentication and update Home Assistant credentials')) {
                    try {
                        $null = Protect-ShellyAndHomeAssistant -Device $item.Device -InventoryEntry $item.Entry -HomeAssistantUrl $HomeAssistantUrl -HomeAssistantWebSocketUrl $HomeAssistantWebSocketUrl -Token $token -Password $devicePassword
                        Write-Host "Protected '$($item.Entry.Title)' and updated Home Assistant." -ForegroundColor Green
                    }
                    catch {
                        Write-Error -ErrorRecord $_ -ErrorAction Continue
                    }
                }
            }
            return
        }

        $state = Read-MigrationState -Path $StatePath
        $inventory = @(Resolve-InventoryFromState -Inventory $inventory -State $state)
        if ($Mode -eq 'RollbackStaged') {
            $records = @($state.devices | Where-Object phase -in @('staged', 'transitioning', 'transition_failed'))
            $needsOldWifiPassword = @($records | Where-Object { Get-ObjectProperty -InputObject $_ -Name 'oldSsid' }).Count -gt 0
            $oldWifiPassword = if ($needsOldWifiPassword) {
                Read-ConfirmedSecret -Prompt 'Old WLAN password for rollback' -MinimumLength 8 -MaximumLength 63 -PrintableAscii
            }
            foreach ($record in $records) {
                $entry = $inventory | Where-Object EntryId -eq $record.entryId
                if (-not $entry) {
                    continue
                }
                $device = $null
                $recordNewIp = Get-ObjectProperty -InputObject $record -Name 'newIp'
                $recordOldIp = Get-ObjectProperty -InputObject $record -Name 'oldIp'
                $recordNewPort = Get-ObjectProperty -InputObject $record -Name 'newPort'
                foreach ($candidateHost in @($recordNewIp, $recordOldIp) | Where-Object { $_ } | Select-Object -Unique) {
                    foreach ($candidatePort in @($recordNewPort, 443, 80) | Where-Object { $_ } | Select-Object -Unique) {
                        try {
                            $candidate = Get-ShellyIdentity -Host $candidateHost -Port $candidatePort
                            if ($candidate.Mac -eq $record.mac) {
                                $device = $candidate
                                break
                            }
                        }
                        catch { }
                    }
                    if ($device) { break }
                }
                if (-not $device) {
                    Write-Warning "Could not locate staged device '$($record.title)' on either subnet."
                    continue
                }
                $oldSsid = Get-ObjectProperty -InputObject $record -Name 'oldSsid'
                if ($PSCmdlet.ShouldProcess($record.title, 'Restore the old primary WLAN and remove the staged fallback')) {
                    if ($oldSsid) {
                        Set-ShellyPrimaryWifi -Device $device -Ssid $oldSsid -WifiPassword $oldWifiPassword -Password $devicePassword
                        $device = Wait-ShellyIdentity -Host $recordOldIp -Port $device.Port -ExpectedMac $device.Mac -TimeoutSeconds 60
                    }
                    Disable-ShellyFallbackWifi -Device $device -Password $devicePassword
                    Set-MigrationCheckpoint -State $state -Entry $entry -Device $device -Phase 'rolled_back' -NewIp $null -NewPort $null -OldSsid $oldSsid -ErrorMessage $null
                    Write-MigrationState -State $state -Path $StatePath
                    Write-Host "Restored the old WLAN for '$($record.title)'." -ForegroundColor Green
                }
            }
            return
        }

        $ssid = Read-Host -Prompt 'Target VLAN WLAN SSID'
        if ([string]::IsNullOrWhiteSpace($ssid) -or $ssid.Length -gt 32) {
            throw 'The target SSID must contain between 1 and 32 characters.'
        }
        $wifiPassword = Read-ConfirmedSecret -Prompt 'Target VLAN WLAN password' -MinimumLength 8 -MaximumLength 63 -PrintableAscii

        $reachability = @(Get-ReachableInventory -Inventory $inventory)
        $reachable = @($reachability | Where-Object Device)
        $unreachableWithCheckpoint = @($reachability | Where-Object {
            if ($_.Device) { return $false }
            $unreachableItem = $_
            $record = @($state.devices | Where-Object { $_.entryId -eq $unreachableItem.Entry.EntryId }) | Select-Object -First 1
            $recordMac = Get-ObjectProperty -InputObject $record -Name 'mac'
            $recordPhase = Get-ObjectProperty -InputObject $record -Name 'phase'
            $recordMac -and $recordPhase -ne 'complete'
        })
        if ($unreachableWithCheckpoint) {
            Write-Host "Scanning $TargetSubnet for checkpointed Shellys whose Home Assistant address is stale..." -ForegroundColor Cyan
            $targetScan = @(Find-ShellyDevicesInSubnet -Cidr $TargetSubnet)
            foreach ($unreachableItem in $unreachableWithCheckpoint) {
                $record = @($state.devices | Where-Object { $_.entryId -eq $unreachableItem.Entry.EntryId }) | Select-Object -First 1
                $recordMac = [string](Get-ObjectProperty -InputObject $record -Name 'mac')
                $device = $targetScan | Where-Object Mac -eq $recordMac | Select-Object -First 1
                if ($device) {
                    $unreachableItem.Entry.Host = $device.Host
                    $unreachableItem.Entry.Port = $device.Port
                    $reachable += [pscustomobject]@{ Entry = $unreachableItem.Entry; Device = $device; Error = $null }
                    Write-Host "Recovered '$($unreachableItem.Entry.Title)' by MAC at $($device.Host)." -ForegroundColor Cyan
                }
            }
        }
        $completedEntryIds = @($state.devices | Where-Object phase -eq 'complete' | ForEach-Object entryId)
        $selected = @($reachable | Where-Object { $_.Entry.EntryId -notin $completedEntryIds } | Select-Object -First $BatchSize)
        if (-not $selected) {
            Write-Host 'No reachable, incomplete Shelly devices matched this run.' -ForegroundColor Yellow
            return
        }

        if ($WhatIfPreference) {
            $selected | ForEach-Object { Write-Host "Would hand off, verify, and protect '$($_.Entry.Title)' ($($_.Entry.Host))." }
            return
        }

        $staged = @()
        $freshStaged = @()
        $resumedTargetDevices = @{}
        $currentPrimarySsids = @{}
        foreach ($candidateItem in $selected) {
            try {
                $currentPrimarySsids[$candidateItem.Entry.EntryId] = Get-ShellyPrimarySsid -Device $candidateItem.Device -Password $devicePassword
            }
            catch {
                $currentPrimarySsids[$candidateItem.Entry.EntryId] = $null
            }
        }
        $freshCandidates = @($selected | Where-Object {
            $candidateItem = $_
            $candidateRecord = @($state.devices | Where-Object { $_.entryId -eq $candidateItem.Entry.EntryId }) | Select-Object -First 1
            $candidatePhase = Get-ObjectProperty -InputObject $candidateRecord -Name 'phase'
            $candidateNewIp = Get-ObjectProperty -InputObject $candidateRecord -Name 'newIp'
            $isResume = $candidateNewIp -and $candidatePhase -in @('discovered', 'finalize_failed') -and $candidateItem.Device.Host -eq $candidateNewIp
            $candidateSsid = $currentPrimarySsids[$candidateItem.Entry.EntryId]
            $isAdoptable = $candidateSsid -and (Test-ShellyTargetPlacement -Device $candidateItem.Device -CurrentSsid $candidateSsid -TargetSsid $ssid -TargetSubnet $TargetSubnet)
            -not ($isResume -or $isAdoptable)
        })
        $oldWifiPassword = if ($freshCandidates) {
            Read-ConfirmedSecret -Prompt 'Current/old WLAN password (used only as per-device fallback)' -MinimumLength 8 -MaximumLength 63 -PrintableAscii
        }
        foreach ($item in $selected) {
            $record = @($state.devices | Where-Object { $_.entryId -eq $item.Entry.EntryId }) | Select-Object -First 1
            $recordPhase = Get-ObjectProperty -InputObject $record -Name 'phase'
            $recordNewIp = Get-ObjectProperty -InputObject $record -Name 'newIp'
            if ($recordNewIp -and $recordPhase -in @('discovered', 'finalize_failed') -and $item.Device.Host -eq $recordNewIp) {
                if (-not $PSCmdlet.ShouldProcess($item.Entry.Title, "Resume VLAN finalization at $recordNewIp and synchronize Home Assistant credentials")) {
                    continue
                }
                $staged += $item
                $resumedTargetDevices[$item.Device.Mac] = $item.Device
                Write-Host "Resuming '$($item.Entry.Title)' at $recordNewIp; WLAN handoff is already complete." -ForegroundColor Cyan
                continue
            }
            $currentPrimarySsid = $currentPrimarySsids[$item.Entry.EntryId]
            if ($currentPrimarySsid -ceq $ssid) {
                if (-not (Test-ShellyTargetPlacement -Device $item.Device -CurrentSsid $currentPrimarySsid -TargetSsid $ssid -TargetSubnet $TargetSubnet)) {
                    $message = "The Shelly reports '$ssid' as primary but is reachable at $($item.Device.Host), outside $TargetSubnet; refusing automatic adoption."
                    Set-MigrationCheckpoint -State $state -Entry $item.Entry -Device $item.Device -Phase 'stage_failed' -NewIp $null -NewPort $null -ErrorMessage $message
                    Write-MigrationState -State $state -Path $StatePath
                    Write-Warning "'$($item.Entry.Title)': $message"
                    continue
                }
                if (-not $PSCmdlet.ShouldProcess($item.Entry.Title, "Adopt existing target-WLAN address $($item.Device.Host) and finalize Home Assistant credentials")) {
                    continue
                }
                Set-MigrationCheckpoint -State $state -Entry $item.Entry -Device $item.Device -Phase 'discovered' -NewIp $item.Device.Host -NewPort $item.Device.Port -ErrorMessage $null
                Write-MigrationState -State $state -Path $StatePath
                $staged += $item
                $resumedTargetDevices[$item.Device.Mac] = $item.Device
                Write-Host "Adopting '$($item.Entry.Title)' at $($item.Device.Host); primary WLAN and target subnet are already correct." -ForegroundColor Cyan
                continue
            }
            if (-not $PSCmdlet.ShouldProcess($item.Entry.Title, "Preserve the current WLAN as fallback, switch to '$ssid', and verify VLAN placement")) {
                continue
            }
            try {
                if ($item.Device.Protected) {
                    $null = Get-ShellySettings -Device $item.Device -Password $devicePassword
                }
                $oldSsid = $currentPrimarySsid
                if ([string]::IsNullOrWhiteSpace($oldSsid)) {
                    throw 'The Shelly current primary WLAN could not be read.'
                }
                Set-ShellyCoIoT -Device $item.Device -Peer "${HomeAssistantIp}:5683" -Password $devicePassword
                Set-ShellyFallbackWifi -Device $item.Device -Ssid $oldSsid -WifiPassword $oldWifiPassword -Password $devicePassword
                Set-MigrationCheckpoint -State $state -Entry $item.Entry -Device $item.Device -Phase 'staged' -NewIp $null -NewPort $null -OldSsid $oldSsid -ErrorMessage $null
                $state.targetSsid = $ssid
                Write-MigrationState -State $state -Path $StatePath

                try {
                    Set-ShellyPrimaryWifi -Device $item.Device -Ssid $ssid -WifiPassword $wifiPassword -Password $devicePassword
                }
                catch {
                    $switchError = $_.Exception.GetBaseException().Message
                    Write-Warning "'$($item.Entry.Title)' closed or failed the primary-WLAN request ($switchError); VLAN discovery will determine whether it was applied."
                }
                Set-MigrationCheckpoint -State $state -Entry $item.Entry -Device $item.Device -Phase 'transitioning' -NewIp $null -NewPort $null -OldSsid $oldSsid -ErrorMessage $null
                Write-MigrationState -State $state -Path $StatePath
                $staged += $item
                $freshStaged += $item
                Write-Host "Switching '$($item.Entry.Title)' from '$oldSsid' to '$ssid'." -ForegroundColor Green
            }
            catch {
                Set-MigrationCheckpoint -State $state -Entry $item.Entry -Device $item.Device -Phase 'stage_failed' -NewIp $null -NewPort $null -ErrorMessage $_.Exception.Message
                Write-MigrationState -State $state -Path $StatePath
                Write-Error -ErrorRecord $_ -ErrorAction Continue
            }
        }
        if (-not $staged) {
            throw 'No devices were staged successfully.'
        }

        $targetDevices = @{} + $resumedTargetDevices
        if ($freshStaged) {
            $discoveredDevices = Wait-ForTargetDevices -Devices @($freshStaged.Device) -TargetSubnet $TargetSubnet -TimeoutSeconds $DiscoveryTimeoutSeconds
            foreach ($mac in $discoveredDevices.Keys) {
                $targetDevices[$mac] = $discoveredDevices[$mac]
            }
        }
        foreach ($item in $staged) {
            if (-not $targetDevices.ContainsKey($item.Device.Mac)) {
                $message = "Device was not discovered on $TargetSubnet. It should remain on or fall back to its old WLAN; the fallback was left enabled."
                Set-MigrationCheckpoint -State $state -Entry $item.Entry -Device $item.Device -Phase 'transition_failed' -NewIp $null -NewPort $null -ErrorMessage $message
                Write-MigrationState -State $state -Path $StatePath
                Write-Warning "'$($item.Entry.Title)': $message"
                continue
            }

            $device = $targetDevices[$item.Device.Mac]
            try {
                Set-MigrationCheckpoint -State $state -Entry $item.Entry -Device $device -Phase 'discovered' -NewIp $device.Host -NewPort $device.Port -ErrorMessage $null
                Write-MigrationState -State $state -Path $StatePath

                $device = Wait-ShellyIdentity -Host $device.Host -Port $device.Port -ExpectedMac $device.Mac
                Invoke-WithRetry -Description "Disable fallback WLAN for '$($item.Entry.Title)'" -Operation {
                    Disable-ShellyFallbackWifi -Device $device -Password $devicePassword
                }
                Invoke-WithRetry -Description "Disable Shelly Cloud for '$($item.Entry.Title)'" -Operation {
                    Disable-ShellyCloud -Device $device -Password $devicePassword
                }

                $ntpServer = Set-ShellyNtp -Device $device -Servers $NtpServers -Password $devicePassword
                if (-not $ntpServer) {
                    Write-Warning "'$($item.Entry.Title)' did not synchronize with either configured PTB server."
                }

                Set-HaShellyAddress -HomeAssistantUrl $HomeAssistantUrl -Token $token -EntryId $item.Entry.EntryId -Host $device.Host -Port $device.Port -VerifySsl $false
                if (-not (Wait-HaEntryLoaded -HomeAssistantUrl $HomeAssistantUrl -Token $token -EntryId $item.Entry.EntryId)) {
                    throw 'Home Assistant did not load the Shelly after its address was updated.'
                }

                $device = Protect-ShellyAndHomeAssistant -Device $device -InventoryEntry $item.Entry -HomeAssistantUrl $HomeAssistantUrl -HomeAssistantWebSocketUrl $HomeAssistantWebSocketUrl -Token $token -Password $devicePassword
                Set-MigrationCheckpoint -State $state -Entry $item.Entry -Device $device -Phase 'complete' -NewIp $device.Host -NewPort $device.Port -ErrorMessage $null
                Write-MigrationState -State $state -Path $StatePath
                Write-Host "Completed '$($item.Entry.Title)' at $($device.Host)." -ForegroundColor Green
            }
            catch {
                Set-MigrationCheckpoint -State $state -Entry $item.Entry -Device $device -Phase 'finalize_failed' -NewIp $device.Host -NewPort $device.Port -ErrorMessage $_.Exception.Message
                Write-MigrationState -State $state -Path $StatePath
                Write-Error -ErrorRecord $_ -ErrorAction Continue
            }
        }

        Write-Host ''
        Write-Host 'Batch processing finished. The old SSID remained enabled throughout.' -ForegroundColor Cyan
        Write-Host "Non-secret migration state: $StatePath"
    }
    finally {
        $token = $null
        $devicePassword = $null
        $wifiPassword = $null
        $oldWifiPassword = $null
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-ShellyMigration @PSBoundParameters
}
