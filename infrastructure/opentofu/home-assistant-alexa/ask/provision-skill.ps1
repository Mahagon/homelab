[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^arn:aws:lambda:eu-west-1:[0-9]{12}:function:home-assistant-alexa$')]
    [string]$LambdaArn,

    [Parameter(Mandatory)]
    [ValidatePattern('^https://')]
    [string]$SmallIconUri,

    [Parameter(Mandatory)]
    [ValidatePattern('^https://')]
    [string]$LargeIconUri,

    [ValidatePattern('^$|^amzn1\.ask\.skill\.[0-9a-fA-F-]{36}$')]
    [string]$SkillId = "",

    [string]$AskProfile = "default",

    [switch]$SkipAccountLinking
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command ask -ErrorAction SilentlyContinue)) {
    throw "ASK CLI v2 is not installed. Run 'npm install --global ask-cli@2' and then 'ask configure'."
}

$templatePath = Join-Path $PSScriptRoot "skill-template.json"
$renderedPath = Join-Path $PSScriptRoot "rendered-skill.json"
$manifest = Get-Content -Raw -LiteralPath $templatePath
$manifest = $manifest.Replace('${LAMBDA_ARN}', $LambdaArn)
$manifest = $manifest.Replace('${SMALL_ICON_URI}', $SmallIconUri)
$manifest = $manifest.Replace('${LARGE_ICON_URI}', $LargeIconUri)
$null = $manifest | ConvertFrom-Json
[System.IO.File]::WriteAllText($renderedPath, $manifest, [System.Text.UTF8Encoding]::new($false))

if ($SkillId) {
    & ask smapi update-skill-manifest --skill-id $SkillId --file $renderedPath --profile $AskProfile
    if ($LASTEXITCODE -ne 0) {
        throw "ASK CLI failed to update skill $SkillId."
    }
}
else {
    $result = & ask smapi create-skill-for-vendor --manifest $manifest --profile $AskProfile
    if ($LASTEXITCODE -ne 0) {
        throw "ASK CLI failed to create the skill."
    }
    $result | Write-Output
    try {
        $parsedResult = $result | ConvertFrom-Json
        $SkillId = $parsedResult.skillId
    }
    catch {
        Write-Warning "Could not parse the Skill ID automatically. Copy it from the ASK output or Developer Console."
    }
}

if (-not $SkillId) {
    Write-Warning "Re-run this script with -SkillId after copying the generated Skill ID."
    return
}

Write-Host "Skill ID: $SkillId"
Write-Host "Set GitHub variable ALEXA_SKILL_ID to this value and re-run the OpenTofu apply."

if (-not $SkipAccountLinking) {
    Write-Host "ASK will now prompt for account linking. Use the values documented in docs/home-assistant-alexa.md."
    & ask api create-account-linking --skill-id $SkillId --stage development --profile $AskProfile
    if ($LASTEXITCODE -ne 0) {
        throw "ASK CLI account-linking configuration failed."
    }
}

