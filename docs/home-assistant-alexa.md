# Legacy AWS variant: Home Assistant remote access and Alexa

> For the zero-AWS deployment, use [home-assistant-alexa-proxy.md](home-assistant-alexa-proxy.md).
> This document remains as reference for the optional AWS Lambda architecture.

This runbook publishes `homeassistant.danieljacobs.de` through an outbound-only
Cloudflare Tunnel and connects a private German Alexa Smart Home skill through
an AWS Lambda function. No inbound Home Assistant port is required on the UniFi
gateway.

The infrastructure is intentionally split into three trust domains:

- OpenTofu manages AWS, Cloudflare Tunnel configuration, and public DNS.
- Argo CD manages the two `cloudflared` connectors and Home Assistant YAML.
- A local helper transfers the tunnel token from encrypted OpenTofu state to a
  Kubernetes Secret. The token is never committed.

## Expected cost

The expected Alexa traffic fits comfortably within the permanent Lambda free
allowance. S3 state, CloudWatch Logs, and DNS usage are very small but AWS and
Cloudflare do not provide a contractual zero-cost guarantee. The AWS budget
alerts at USD 0.01 of actual monthly cost; it does not stop resources.

Paid Security Hub, AWS Config, GuardDuty, customer-managed KMS keys, X-Ray, and
Cloudflare Access are not enabled. See [security-compliance.md](security-compliance.md)
for the resulting CIS gaps.

## 1. Workstation tools

Run these from an elevated PowerShell prompt. Verify the IDs shown by
`winget search` before installing if the package source has changed.

```powershell
winget install --exact --id OpenTofu.Tofu
winget install --exact --id Amazon.AWSCLI
winget install --exact --id OpenJS.NodeJS.LTS
winget install --exact --id AquaSecurity.Trivy
winget install --exact --id TerraformLinters.tflint

npm install --global ask-cli@2
python -m pip install --user pipx
python -m pipx ensurepath
pipx install checkov==3.3.15
```

Open a new terminal and verify:

```powershell
tofu version
aws --version
ask --version
trivy --version
tflint --version
checkov --version
kubectl version --client
```

## 2. Secure the new AWS account

1. Register the AWS account and choose the paid account plan if AWS requires it
   after the introductory free-plan period. The resources remain usage billed.
2. Register a phishing-resistant passkey or hardware MFA device for the root
   user and do not create root access keys.
3. Add current security, operations, and billing alternate contacts.
4. Enable IAM Identity Center for human administration. Do not create an IAM
   user with permanent access keys for this project.
5. Configure AWS CLI SSO and authenticate:

   ```powershell
   aws configure sso
   aws sso login --profile homelab-admin
   $env:AWS_PROFILE = "homelab-admin"
   aws sts get-caller-identity
   ```

The German Alexa Smart Home endpoint must run in `eu-west-1`, even though
Frankfurt is geographically closer. Home Assistant and Amazon both document
Ireland for the `de-DE` Alexa endpoint. Deploying it in Frankfurt can complete
successfully but fail during account linking or device discovery.

## 3. Bootstrap OpenTofu state and GitHub OIDC

The bootstrap root deliberately uses local state because it creates the remote
state bucket itself. Protect its state with an encrypted workstation backup.

```powershell
Set-Location infrastructure/opentofu/home-assistant-alexa/bootstrap
Copy-Item terraform.tfvars.example terraform.tfvars

tofu init
tofu fmt -check
tofu validate
tofu test
tofu plan -out bootstrap.tfplan
tofu apply bootstrap.tfplan

tofu output state_bucket_name
tofu output github_deployment_role_arn
```

After applying, copy `terraform.tfstate` into an encrypted password manager
attachment or encrypted offline backup. Never commit it. Bucket deletion is
protected by `prevent_destroy`; changing that control requires a reviewed code
change and a separate apply.

## 4. Configure GitHub

Create an environment named `aws-production` and restrict deployment branches
to `main`. Add required reviewers if the repository plan supports them.

Add these repository or environment variables:

| Name | Value |
|---|---|
| `AWS_DEPLOY_ROLE_ARN` | Bootstrap output `github_deployment_role_arn` |
| `TOFU_STATE_BUCKET` | Bootstrap output `state_bucket_name` |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account ID |
| `CLOUDFLARE_ZONE_ID` | Zone ID for `danieljacobs.de` |
| `AWS_BUDGET_EMAIL` | Address for budget notifications |
| `ALEXA_SKILL_ID` | Empty until the ASK deployment creates the skill |

Add the environment secret `CLOUDFLARE_OPENTOFU_API_TOKEN`. Create a dedicated
Cloudflare token; do not reuse the cert-manager or ExternalDNS token. Restrict
it to this account and zone with only:

- Cloudflare Tunnel / cloudflared Connector: Read and Write.
- Zone: Read.
- DNS: Read and Write for `danieljacobs.de`.

The GitHub role uses OIDC and accepts only the exact subject
`repo:Mahagon/homelab:environment:aws-production`. It cannot be assumed by a
different repository or a normal branch workflow.

## 5. Create the tunnel without publishing DNS

For the first deployment, dispatch **Apply Home Assistant Alexa infrastructure**
from `main` with `publish_dns` disabled. This creates the tunnel, Lambda, IAM,
logging, and budget but leaves the current DNS record untouched.

For a local first apply instead:

```powershell
Set-Location infrastructure/opentofu/home-assistant-alexa/main
$env:AWS_PROFILE = "homelab-admin"
$env:CLOUDFLARE_API_TOKEN = Read-Host "Cloudflare OpenTofu token"

tofu init -backend-config="bucket=<TOFU_STATE_BUCKET>"
tofu plan -var="cloudflare_account_id=<ACCOUNT_ID>" `
  -var="cloudflare_zone_id=<ZONE_ID>" `
  -var="budget_email=<EMAIL>" `
  -var="publish_dns=false" -out first.tfplan
tofu apply first.tfplan
```

Do not put the Cloudflare token in a `.tfvars` file or PowerShell history.
Remove the environment variable after the apply:

```powershell
Remove-Item Env:CLOUDFLARE_API_TOKEN
```

## 6. Enable K3s network policy and deploy the connectors

`butane/config.bu` enables the controller for future provisioning. On the
existing node, make the equivalent one-time change and restart K3s:

```bash
ssh core@192.168.178.10
sudo cp /etc/rancher/k3s/config.yaml /etc/rancher/k3s/config.yaml.before-netpol
sudo vi /etc/rancher/k3s/config.yaml
# Set disable-network-policy: false, or remove the old true setting.
sudo systemctl restart k3s
sudo systemctl is-active k3s
```

After Argo CD has created the `cloudflared` namespace, transfer the connector
token without writing it to disk:

```powershell
$env:AWS_PROFILE = "homelab-admin"
infrastructure/opentofu/home-assistant-alexa/scripts/set-cloudflared-secret.ps1 `
  -TofuDirectory infrastructure/opentofu/home-assistant-alexa/main
kubectl rollout status deployment/cloudflared --namespace cloudflared
kubectl get pods --namespace cloudflared
```

Both replicas must be Ready. In Cloudflare, the `homeassistant-k3s` tunnel must
show Healthy before changing DNS.

The NetworkPolicy allows only DNS, Cloudflare TCP/UDP 7844, and Home Assistant
TCP 8123. If the Home Assistant node address changes, update the `/32` rule in
the manifest before moving the node.

## 7. Move the existing DNS record under OpenTofu

First let Argo CD sync the ExternalDNS exclusion and confirm ExternalDNS is no
longer reconciling `homeassistant.danieljacobs.de`.

Find the existing Home Assistant DNS record ID in the Cloudflare dashboard or
API. With `TF_VAR_publish_dns=true`, import it into the counted resource:

```powershell
Set-Location infrastructure/opentofu/home-assistant-alexa/main
$env:TF_VAR_cloudflare_account_id = "<ACCOUNT_ID>"
$env:TF_VAR_cloudflare_zone_id = "<ZONE_ID>"
$env:TF_VAR_budget_email = "<EMAIL>"
$env:TF_VAR_publish_dns = "true"
$env:CLOUDFLARE_API_TOKEN = Read-Host "Cloudflare OpenTofu token"

tofu import 'cloudflare_dns_record.home_assistant[0]' '<ZONE_ID>/<DNS_RECORD_ID>'
tofu plan -out dns-cutover.tfplan
tofu apply dns-cutover.tfplan
```

The plan should replace the old A/AAAA record with a proxied CNAME targeting
`<tunnel-id>.cfargotunnel.com`. Remove only the obsolete ExternalDNS ownership
TXT record for this hostname after confirming that no other record uses it.

For later deployments, dispatch the GitHub workflow with `publish_dns` enabled.

Verify from a network outside the home:

```powershell
Resolve-DnsName homeassistant.danieljacobs.de
curl.exe --fail-with-body https://homeassistant.danieljacobs.de/auth/authorize
curl.exe --include https://homeassistant.danieljacobs.de/api/
```

The API request without a token must return `401 Unauthorized`. Public DNS must
not contain the home WAN address.

## 8. Preserve fast and resilient LAN access

In the UniFi Network application, add a local DNS record/host override:

```text
homeassistant.danieljacobs.de -> 192.168.178.10
```

UniFi changes menu names between releases; look under Settings, DNS, or Local
DNS Records. Confirm a LAN client resolves the node address while a mobile
client with Wi-Fi disabled resolves Cloudflare.

Verify that the UniFi Gateway has no WAN port-forward, destination NAT, or DMZ
rule for ports 8123 or 443 to Home Assistant. Do not disable unrelated gateway
rules as part of this change.

## 9. Prepare Home Assistant

Argo CD mounts the Alexa package as
`/config/integrations/alexa.yaml`. Validate it before restarting if Home
Assistant has not rolled automatically:

```powershell
kubectl exec --namespace home-assistant deployment/home-assistant -- `
  python -m homeassistant --script check_config --config /config
kubectl rollout restart --namespace home-assistant deployment/home-assistant
kubectl rollout status --namespace home-assistant deployment/home-assistant
```

In Home Assistant:

1. Correct the existing helper name from `Alle Rolläden` to `Alle Rollläden`.
   Keep entity ID `cover.shutters` and its nine current members.
2. Create a dedicated non-administrator Home Assistant user for Alexa.
3. Enable MFA for administrative and remote-access users.
4. Confirm the four lights, nine shutters, and helper show the German names.

The YAML allowlist exposes exactly 14 entities. Do not add domain or glob
includes; they would make newly created entities visible to Alexa implicitly.

## 10. Create and link the Alexa skill

The Amazon Developer account must use the same Amazon account as the Alexa app
and Echo devices. Configure ASK once:

```powershell
ask configure
```

Provide public HTTPS URLs for a 108x108 PNG and a 512x512 PNG. These are Alexa
catalog metadata, even for a development skill. Then run:

```powershell
$lambdaArn = tofu `
  -chdir=infrastructure/opentofu/home-assistant-alexa/main `
  output -raw lambda_function_arn

infrastructure/opentofu/home-assistant-alexa/ask/provision-skill.ps1 `
  -LambdaArn $lambdaArn `
  -SmallIconUri "https://<host>/home-assistant-108.png" `
  -LargeIconUri "https://<host>/home-assistant-512.png"
```

ASK account linking is interactive because the CLI intentionally does not save
the client secret. Enter:

| Prompt | Value |
|---|---|
| Grant type | Authorization Code |
| Authorization URL | `https://homeassistant.danieljacobs.de/auth/authorize` |
| Access-token URL | `https://homeassistant.danieljacobs.de/auth/token` |
| Client ID | `https://layla.amazon.com/` including trailing slash |
| Client secret | A generated nonempty value; Home Assistant does not inspect it |
| Authentication scheme | Request body credentials |
| Scope | `smart_home` |
| Link from own app/site | Disabled |
| Allow enablement without linking | No |

Set GitHub variable `ALEXA_SKILL_ID` to the returned ID and re-run the OpenTofu
apply. Confirm the plan adds exactly one `aws_lambda_permission` whose
`event_source_token` is that Skill ID.

In Alexa mobile app, open **More → Skills & Games → Your Skills → Dev**, enable
`Mein Zuhause`, and sign in using the dedicated Home Assistant user. Run device
discovery.

Expected examples:

- “Alexa, Wohnzimmer Licht einschalten.”
- “Alexa, Alle Rollläden öffnen.”
- “Alexa, Alle Rollläden schließen.”

## Rotation, troubleshooting, and rollback

- Rotate the Cloudflare tunnel token by regenerating it, applying OpenTofu, and
  immediately rerunning `set-cloudflared-secret.ps1`.
- A `403` or account-linking loop usually means the client ID lacks the trailing
  slash, HTTP Basic was selected, or Cloudflare Access was enabled.
- “No new devices found” commonly indicates the Lambda is outside `eu-west-1`,
  the Skill ID permission is missing, or Home Assistant rejected its YAML.
- Inspect Lambda logs without dumping events:
  `aws logs tail /aws/lambda/home-assistant-alexa --region eu-west-1`.
- To roll back to LAN-only access, disable the Alexa development skill and set
  `publish_dns=false`. Do not restore an inbound port forward.
- Versioned S3 state permits recovery of a prior state object. Restore only
  after copying the current version and reviewing an OpenTofu plan.
