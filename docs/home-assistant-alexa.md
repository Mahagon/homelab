# AWS Lambda architecture: Home Assistant remote access and Alexa

This is the active architecture. Alexa Smart Home requires the Lambda endpoint;
the Lambda forwards directives through the protected outbound-only Cloudflare
Tunnel. `infrastructure/opentofu/home-assistant-alexa/main` is the single
OpenTofu root for this stack.

This runbook publishes `homeassistant.<your-domain>` through an outbound-only
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

Add these environment variables:

| Name | Value |
|---|---|
| `AWS_DEPLOY_ROLE_ARN` | Bootstrap output `github_deployment_role_arn` |
| `TOFU_STATE_BUCKET` | Bootstrap output `state_bucket_name` |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account ID |
| `CLOUDFLARE_ZONE_ID` | Zone ID for `<your-domain>` |
| `ALEXA_SKILL_ID` | Empty until the ASK deployment creates the skill |
| `PUBLISH_DNS` | `true` after the tunnel connectors are healthy |

Add these environment secrets. Enter them interactively so their values do not
appear in shell history:

| Secret | Purpose |
|---|---|
| `HOME_ASSISTANT_DOMAIN` | Root domain only, without `homeassistant.`, a scheme, or a path |
| `CLOUDFLARE_API_TOKEN` | Dedicated token used only by this OpenTofu stack |
| `AWS_BUDGET_EMAIL` | Address for budget notifications |

Create a dedicated Cloudflare token; do not reuse the cert-manager or
ExternalDNS token. Restrict
Cloudflare token; do not reuse the cert-manager or ExternalDNS token. Restrict
it to this account and zone with only:

- Cloudflare Tunnel / cloudflared Connector: Read and Write.
- Zone: Read.
- DNS: Read and Write for `<your-domain>`.
- Zone WAF: Read and Write for `<your-domain>`.
- Cache Settings: Read and Write for `<your-domain>`.
- Zone Transform Rules: Read and Write for `<your-domain>`.
- Zone Settings: Read and Write for `<your-domain>`.
- Account Rulesets: Read and Write.
- Account Filter Lists: Read and Write.

The GitHub role uses OIDC and accepts only the exact subject
`repo:Mahagon/homelab:environment:aws-production`. It cannot be assumed by a
different repository or a normal branch workflow.

Configure the environment from PowerShell with `gh`:

```powershell
$repoName = "Mahagon/homelab"
$environmentName = "aws-production"

gh api --method PUT "repos/$repoName/environments/$environmentName"

gh secret set HOME_ASSISTANT_DOMAIN --repo $repoName --env $environmentName
gh secret set CLOUDFLARE_API_TOKEN --repo $repoName --env $environmentName
gh secret set AWS_BUDGET_EMAIL --repo $repoName --env $environmentName

$bootstrapDir = "infrastructure/opentofu/home-assistant-alexa/bootstrap"
gh variable set AWS_DEPLOY_ROLE_ARN --repo $repoName --env $environmentName --body (tofu -chdir=$bootstrapDir output -raw github_deployment_role_arn)
gh variable set TOFU_STATE_BUCKET --repo $repoName --env $environmentName --body (tofu -chdir=$bootstrapDir output -raw state_bucket_name)

gh variable set CLOUDFLARE_ACCOUNT_ID --repo $repoName --env $environmentName --body "<ACCOUNT_ID>"
gh variable set CLOUDFLARE_ZONE_ID --repo $repoName --env $environmentName --body "<ZONE_ID>"
gh variable set ALEXA_SKILL_ID --repo $repoName --env $environmentName --body "<SKILL_ID>"
gh variable set PUBLISH_DNS --repo $repoName --env $environmentName --body "true"

gh secret list --repo $repoName --env $environmentName
gh variable list --repo $repoName --env $environmentName
```

## 5. Import the existing tunnel and deploy AWS resources

For the first deployment, dispatch **Apply Home Assistant Alexa infrastructure**
from `main` with `publish_dns` disabled. This creates the tunnel, Lambda, IAM,
logging, and budget but leaves the current DNS record untouched.

The live tunnel and DNS record were created by the temporary `cloudflare` root.
Import them into the remote-backed `main` state before applying so OpenTofu
does not create a duplicate tunnel.

For a local apply:

```powershell
Set-Location infrastructure/opentofu/home-assistant-alexa/main
$env:AWS_PROFILE = "homelab-admin"
$env:CLOUDFLARE_API_TOKEN = Read-Host "Cloudflare OpenTofu token"
$env:TF_VAR_home_assistant_domain = Read-Host "Home Assistant root domain"

tofu init -backend-config="bucket=<TOFU_STATE_BUCKET>"
tofu import cloudflare_zero_trust_tunnel_cloudflared.home_assistant `
  "<ACCOUNT_ID>/<TUNNEL_ID>"
tofu import cloudflare_zero_trust_tunnel_cloudflared_config.home_assistant `
  "<ACCOUNT_ID>/<TUNNEL_ID>"
tofu import 'cloudflare_dns_record.home_assistant[0]' `
  "<ZONE_ID>/<DNS_RECORD_ID>"
tofu plan -var="cloudflare_account_id=<ACCOUNT_ID>" `
  -var="cloudflare_zone_id=<ZONE_ID>" `
  -var="budget_email=<EMAIL>" `
  -var="publish_dns=true" -var="alexa_skill_id=" -out first.tfplan
tofu apply first.tfplan
```

Do not put the Cloudflare token in a `.tfvars` file or PowerShell history.
Remove the environment variable after the apply:

```powershell
Remove-Item Env:CLOUDFLARE_API_TOKEN
```

Once the consolidated `main` state has been applied successfully, retire the
old standalone state without deleting any live Cloudflare resources:

```powershell
tofu -chdir=infrastructure/opentofu/home-assistant-alexa/main state list
tofu -chdir=infrastructure/opentofu/home-assistant-alexa/cloudflare state list
tofu -chdir=infrastructure/opentofu/home-assistant-alexa/cloudflare state rm `
  'cloudflare_dns_record.home_assistant[0]' `
  cloudflare_zero_trust_tunnel_cloudflared.home_assistant `
  cloudflare_zero_trust_tunnel_cloudflared_config.home_assistant `
  data.cloudflare_zero_trust_tunnel_cloudflared_token.home_assistant
```

The `state rm` operation only forgets the old state objects; it does not call
the Cloudflare API to destroy the tunnel or DNS record. Verify a no-change plan
from `main` before removing any ignored local `.terraform` or state artifacts.

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

Verify the running node no longer has the disabling flag before relying on the
policies:

```powershell
kubectl get node homelab -o jsonpath="{.metadata.annotations.k3s\.io/node-args}{'\n'}"
kubectl get networkpolicy -n cloudflared
```

The node arguments must not contain `--disable-network-policy true`. Existing
clusters created before this setting was changed may continue reporting that
flag until K3s is restarted with the corrected configuration.

After Argo CD has created the `cloudflared` namespace, transfer the connector
token without writing it to disk:

```powershell
$env:AWS_PROFILE = "homelab-admin"
infrastructure/opentofu/home-assistant-alexa/scripts/set-cloudflared-secret.ps1 `
  -TofuDirectory infrastructure/opentofu/home-assistant-alexa/main
kubectl rollout status deployment/cloudflared --namespace cloudflared
kubectl get pods --namespace cloudflared
```

Both replicas must be Ready. In Cloudflare, the `home-assistant-k3s` tunnel must
show Healthy before changing DNS.

The NetworkPolicies allow only DNS, Cloudflare TCP/UDP 7844, and Home Assistant
TCP 8123. If the Home Assistant node address changes, update the `/32` rule in
`k8s/apps/cloudflared/manifests/networkpolicy.yaml` before moving the node.

The UniFi gateway must not have a WAN port-forward or DMZ rule for Home
Assistant. The connector is outbound-only; no inbound firewall exception is
required. If UniFi egress rules are restricted, allow the K3s node to reach
Cloudflare on TCP/UDP 7844. Cloudflare edge IPs are intentionally not pinned
because they change over time.

## 7. Move the existing DNS record under OpenTofu

First let Argo CD sync the ExternalDNS exclusion and confirm ExternalDNS is no
longer reconciling `homeassistant.<your-domain>`.

Find the existing Home Assistant DNS record ID in the Cloudflare dashboard or
API. With `TF_VAR_publish_dns=true`, import it into the counted resource:

```powershell
Set-Location infrastructure/opentofu/home-assistant-alexa/main
$env:TF_VAR_cloudflare_account_id = "<ACCOUNT_ID>"
$env:TF_VAR_cloudflare_zone_id = "<ZONE_ID>"
$env:TF_VAR_home_assistant_domain = "<YOUR_DOMAIN>"
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

For later deployments, set the `PUBLISH_DNS` environment variable to `true`.
Changes to the main OpenTofu root or Lambda are applied automatically after
both security jobs pass. To request an explicit main-branch deployment:

```powershell
gh workflow run security-iac.yml --repo Mahagon/homelab --ref main -f apply=true -f allow_destroy=false
gh run watch --repo Mahagon/homelab
```

Verify from a network outside the home:

```powershell
Resolve-DnsName homeassistant.<your-domain>
curl.exe --fail-with-body https://homeassistant.<your-domain>/auth/authorize
curl.exe --include https://homeassistant.<your-domain>/api/
```

The API request without a token must return `401 Unauthorized`. Public DNS must
not contain the home WAN address.

### Cloudflare edge hardening

Cloudflare automatically deploys the Free Managed Ruleset on Free-plan zones.
The `main` OpenTofu root additionally owns the zone entry-point rulesets for the
custom-firewall, rate-limit, cache-settings, and response-header phases. It
configures:

- hostname-scoped blocking of non-HTTPS edge ports;
- blocking of `CONNECT`, `TRACE`, and `TRACK`, which Home Assistant does not
  require;
- blocking of common source-control, secret-file, WordPress, and phpMyAdmin
  reconnaissance paths; and
- the Free plan's single rate-limit rule: more than 10 requests to Home
  Assistant's `/auth/login_flow` path from one IP in 10 seconds causes a
  10-second block;
- an explicit cache bypass for every response from the Home Assistant hostname;
  and
- a 30-day hostname-scoped HSTS header without `includeSubDomains` or preload,
  plus `X-Content-Type-Options: nosniff`.

The Free plan does not make `Host` available in rate-limit expressions. The
rate-limit rule therefore uses Home Assistant's distinctive login-flow path and
applies to that path across the `<your-domain>` zone. It intentionally excludes
`/auth/token`, `/api`, WebSocket traffic, and `/api/alexa/smart_home` so normal
companion-app, OAuth, and Alexa operation is unaffected.

Each zone can have only one entry-point ruleset per phase, and OpenTofu treats
each `cloudflare_ruleset` as the complete configuration for that phase. Before
the first apply, review **Security > Security rules**, **Rules > Cache Rules**,
and **Rules > Transform Rules** in Cloudflare. If rules already exist in any of
these four phases, merge them into `cloudflare-security.tf` without exceeding
the Free-plan limits, then import the existing phase ruleset:

```powershell
tofu import cloudflare_ruleset.home_assistant_custom_waf `
  'zones/<ZONE_ID>/<CUSTOM_PHASE_RULESET_ID>'
tofu import cloudflare_ruleset.home_assistant_rate_limit `
  'zones/<ZONE_ID>/<RATE_LIMIT_PHASE_RULESET_ID>'
tofu import cloudflare_ruleset.home_assistant_cache `
  'zones/<ZONE_ID>/<CACHE_PHASE_RULESET_ID>'
tofu import cloudflare_ruleset.home_assistant_response_headers `
  'zones/<ZONE_ID>/<RESPONSE_HEADERS_PHASE_RULESET_ID>'
```

Do not apply a plan that removes an unrelated existing rule. After applying,
verify the protected paths and inspect sampled matches under **Security > Events**:

```powershell
curl.exe --include http://homeassistant.<your-domain>/
curl.exe --include https://homeassistant.<your-domain>/.git/config
curl.exe --include --request TRACE https://homeassistant.<your-domain>/
curl.exe --include https://homeassistant.<your-domain>/api/
```

The first three requests must be blocked by Cloudflare. The unauthenticated API
request must still reach Home Assistant and return `401 Unauthorized`.

Check the successful API response headers as well:

```powershell
curl.exe --silent --dump-header - --output NUL `
  https://homeassistant.<your-domain>/
```

The response must contain `Strict-Transport-Security: max-age=2592000`,
`X-Content-Type-Options: nosniff`, and a `CF-Cache-Status` value other than
`HIT`. Do not add `includeSubDomains` or preload until every hostname in the
zone has been reviewed and a long-lived HTTPS commitment is intended.

### Zone-wide DNS and TLS controls

The same root enables Cloudflare DNSSEC signing, requires TLS 1.2 or newer, and
offers TLS 1.3. Unlike the hostname-scoped WAF, cache, and header rules, the TLS
settings affect every proxied hostname under `<your-domain>`. Review all such
services before applying a change from TLS 1.0 or 1.1.

Enabling DNSSEC in Cloudflare is only the first half of deployment. After the
apply, retrieve the generated public DS record:

```powershell
tofu output -raw cloudflare_dnssec_ds_record
tofu output -json cloudflare_dnssec_registrar_fields
```

Use either the full DS record or its separate key-tag, algorithm, digest-type,
and digest fields at the registrar for `<your-domain>`. Wait for the
delegation to propagate, then verify it through an external validating resolver:

```powershell
Resolve-DnsName -Type DS <your-domain> -Server 1.1.1.1
Resolve-DnsName homeassistant.<your-domain> -DnssecOk -Server 1.1.1.1
```

If DNSSEC was already enabled manually, import it before applying:

```powershell
tofu import cloudflare_zone_dnssec.zone '<ZONE_ID>'
```

Never disable Cloudflare DNSSEC while the registrar still publishes the DS
record; that would make the entire domain fail validation. Remove the registrar
DS record first and wait for its TTL before disabling DNSSEC during a rollback.

Certificate Transparency Monitoring has no suitable resource in the pinned
Cloudflare provider. Enable it once under **SSL/TLS > Edge Certificates >
Certificate Transparency Monitoring** and add the operational email address.

## 8. Preserve fast and resilient LAN access

In the UniFi Network application, add a local DNS record/host override:

```text
homeassistant.<your-domain> -> 192.168.178.10
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
| Authorization URL | `https://homeassistant.<your-domain>/auth/authorize` |
| Access-token URL | `https://homeassistant.<your-domain>/auth/token` |
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
