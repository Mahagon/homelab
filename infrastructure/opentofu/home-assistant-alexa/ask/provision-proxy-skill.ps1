[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^https://[^/]+/api/alexa/smart_home$')]
    [string]$EndpointUrl,
    [Parameter(Mandatory)]
    [ValidatePattern('^https://')]
    [string]$SmallIconUri,
    [Parameter(Mandatory)]
    [ValidatePattern('^https://')]
    [string]$LargeIconUri,
    [string]$VendorId,
    [string]$SkillId
)

$ErrorActionPreference = "Stop"
$templatePath = Join-Path $PSScriptRoot "proxy-skill-template.json"
$renderedPath = Join-Path $PSScriptRoot "rendered-proxy-skill.json"
$manifest = (Get-Content -Raw -LiteralPath $templatePath).
    Replace('${ENDPOINT_URL}', $EndpointUrl).
    Replace('${SMALL_ICON_URI}', $SmallIconUri).
    Replace('${LARGE_ICON_URI}', $LargeIconUri)
[System.IO.File]::WriteAllText($renderedPath, $manifest, [System.Text.UTF8Encoding]::new($false))

try {
    if ($SkillId) {
        ask smapi update-skill-manifest -s $SkillId -f $renderedPath
        Write-Host "Updated Alexa skill $SkillId."
    }
    else {
        if (-not $VendorId) {
            throw "VendorId is required when creating a new skill. Run 'ask api list-vendors' first."
        }
        $result = ask smapi create-skill-for-vendor -v $VendorId -f $renderedPath | ConvertFrom-Json
        Write-Host "Created Alexa skill. Record the returned skill ID for the Alexa developer console."
        $result | ConvertTo-Json -Depth 10
    }
    Write-Host "Configure account linking interactively in the Alexa developer console using the values in docs/home-assistant-alexa-proxy.md."
}
finally {
    Remove-Item -LiteralPath $renderedPath -Force -ErrorAction SilentlyContinue
}
