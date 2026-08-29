[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$TofuDirectory = (Join-Path $PSScriptRoot "..\main"),
    [string]$KubeContext
)

$ErrorActionPreference = "Stop"
$resolvedTofuDirectory = (Resolve-Path -LiteralPath $TofuDirectory).Path
$kubectlContextArgs = @()
if ($KubeContext) {
    $kubectlContextArgs = @("--context", $KubeContext)
}

& kubectl @kubectlContextArgs get namespace cloudflared *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Namespace 'cloudflared' does not exist. Sync the Argo CD cloudflared application first."
}

$token = & tofu "-chdir=$resolvedTofuDirectory" output -raw cloudflared_tunnel_token
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($token)) {
    throw "Unable to read cloudflared_tunnel_token from OpenTofu state."
}

try {
    $tokenBytes = [System.Text.Encoding]::UTF8.GetBytes($token.Trim())
    $secret = @{
        apiVersion = "v1"
        kind = "Secret"
        metadata = @{
            name = "cloudflared-tunnel-token"
            namespace = "cloudflared"
        }
        type = "Opaque"
        data = @{
            token = [Convert]::ToBase64String($tokenBytes)
        }
    } | ConvertTo-Json -Depth 5 -Compress

    if ($PSCmdlet.ShouldProcess("cloudflared/cloudflared-tunnel-token", "Create or update Kubernetes secret")) {
        $secret | & kubectl @kubectlContextArgs apply -f -
        if ($LASTEXITCODE -ne 0) {
            throw "kubectl failed to apply the tunnel token Secret."
        }

        & kubectl @kubectlContextArgs rollout restart deployment/cloudflared --namespace cloudflared
        if ($LASTEXITCODE -ne 0) {
            throw "Secret was updated, but the cloudflared rollout could not be restarted."
        }
    }
}
finally {
    if ($tokenBytes) {
        [Array]::Clear($tokenBytes, 0, $tokenBytes.Length)
    }
    $secret = $null
    $token = $null
}

