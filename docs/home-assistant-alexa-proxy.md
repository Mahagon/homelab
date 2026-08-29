# Home Assistant Alexa integration without AWS

This is the zero-AWS path. Alexa Smart Home directives are sent through the
existing Cloudflare Tunnel to a small, hardened proxy running in K3s. The proxy
forwards authenticated directives to Home Assistant; no AWS account, Lambda,
S3 state bucket, or CloudWatch Logs are required.

## 1. Deploy the proxy

Push the repository changes and wait for Argo CD to sync `alexa-proxy` and
`cloudflared`:

```powershell
kubectl rollout status deployment/alexa-proxy --namespace alexa-proxy
kubectl rollout status deployment/cloudflared --namespace cloudflared
kubectl get networkpolicy --namespace alexa-proxy
```

The proxy accepts only `POST /api/alexa/smart_home`, requires a Bearer token,
and can reach only Home Assistant TCP 8123. Cloudflared can reach the proxy on
TCP 8080 and Home Assistant for all other paths.

## 2. Manage the tunnel with Cloudflare-only OpenTofu

Create a dedicated Cloudflare API token with Tunnel read/write, zone read, and
DNS read/write for `danieljacobs.de`. Keep the state directory on an encrypted
workstation because it contains the tunnel token.

```powershell
Set-Location infrastructure/opentofu/home-assistant-alexa/cloudflare
Copy-Item terraform.tfvars.example terraform.tfvars
$env:CLOUDFLARE_API_TOKEN = Read-Host "Cloudflare API token"

tofu init
tofu validate
tofu test
tofu plan -var="cloudflare_account_id=<ACCOUNT_ID>" `
  -var="cloudflare_zone_id=<ZONE_ID>" `
  -var="publish_dns=false" -out tunnel.tfplan
tofu apply tunnel.tfplan

Remove-Item Env:CLOUDFLARE_API_TOKEN
```

Transfer the token to Kubernetes without saving it to a file:

```powershell
infrastructure/opentofu/home-assistant-alexa/scripts/set-cloudflared-secret.ps1 `
  -TofuDirectory infrastructure/opentofu/home-assistant-alexa/cloudflare
```

Wait until both connectors are Ready and the tunnel is Healthy in Cloudflare.

## 3. Publish DNS

Set `publish_dns=true` and apply after confirming the tunnel health. If an old
DNS record exists, import it first:

```powershell
tofu import 'cloudflare_dns_record.home_assistant[0]' '<ZONE_ID>/<RECORD_ID>'
tofu plan -var="publish_dns=true" -out dns.tfplan
tofu apply dns.tfplan
```

The public record must be a proxied CNAME to the tunnel hostname, never your
home WAN address. Keep a UniFi local DNS override to
`192.168.178.10` for fast LAN access.

## 4. Create the Alexa skill

Use an Amazon Developer account associated with your Alexa devices. Configure
ASK and create/update the skill with the proxy endpoint:

```powershell
ask configure
infrastructure/opentofu/home-assistant-alexa/ask/provision-proxy-skill.ps1 `
  -VendorId <VENDOR_ID> `
  -EndpointUrl "https://homeassistant.danieljacobs.de/api/alexa/smart_home" `
  -SmallIconUri "https://<host>/home-assistant-108.png" `
  -LargeIconUri "https://<host>/home-assistant-512.png"
```

Configure account linking with:

```text
Authorization URL: https://homeassistant.danieljacobs.de/auth/authorize
Token URL:         https://homeassistant.danieljacobs.de/auth/token
Client ID:         https://layla.amazon.com/
Grant type:        Authorization Code
Authentication:    Request body credentials
Scope:             smart_home
```

Enable the development skill in the Alexa app, link the dedicated Home
Assistant user, and run device discovery. The Home Assistant package exposes
only the four lights, nine shutters, and the shutter group.

## 5. Verify and troubleshoot

```powershell
curl.exe --include https://homeassistant.danieljacobs.de/api/alexa/smart_home
kubectl logs deployment/alexa-proxy --namespace alexa-proxy --tail=100
```

Unauthenticated proxy requests should return `401`. Do not add a port forward or
DMZ rule. If the Home Assistant node IP changes, update both NetworkPolicies
and the proxy `HOME_ASSISTANT_URL` value.

The previous AWS implementation remains under `infrastructure/opentofu/home-assistant-alexa/main`
for reference only; do not apply it for the zero-cost deployment.
