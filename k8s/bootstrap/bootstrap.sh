#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Bootstrap ArgoCD on K3s
# Run from your workstation with kubectl configured
#
# Environment variables (will prompt if not set):
#   REPO_URL      - git repo URL, e.g. git@github.com:You/homelab.git
#   DOMAIN        - your domain, e.g. example.com
#   EMAIL         - ACME/Let's Encrypt email, e.g. you@example.com
#   SSH_KEY_FILE  - path to SSH private key for repo access (default: ~/.ssh/id_ed25519_argocd)
#
# DOMAIN and EMAIL are stored in a cluster Secret and injected
# into manifests at ArgoCD sync time via the envsubst CMP -
# they are never written to git.
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- Gather configuration ----

if [[ -z "${REPO_URL:-}" ]]; then
  read -rp "Git repo URL (e.g. git@github.com:You/homelab.git): " REPO_URL
fi

if [[ -z "${KUBE_CONTEXT:-}" ]]; then
  KUBE_CONTEXT="default"
fi

kubectl config get-contexts "$KUBE_CONTEXT" &>/dev/null || {
  echo "Error: kube context '$KUBE_CONTEXT' not found. Available contexts:"
  kubectl config get-contexts -o name
  exit 1
}

# Pin every call to the selected context without changing the user's current one.
kubectl() { command kubectl --context "$KUBE_CONTEXT" "$@"; }
helm() { command helm --kube-context "$KUBE_CONTEXT" "$@"; }

# Print a JSON document built from environment variables, so secret values are
# escaped correctly and never appear in a process's argument list.
json_from_env() { python3 -c "$1"; }

# Try to read DOMAIN/EMAIL from an existing cluster secret before prompting
if [[ -z "${DOMAIN:-}" ]] || [[ -z "${EMAIL:-}" ]]; then
  if kubectl get secret homelab-config --namespace argocd &>/dev/null; then
    DOMAIN="${DOMAIN:-$(kubectl get secret homelab-config --namespace argocd -o jsonpath='{.data.domain}' | base64 -d)}"
    EMAIL="${EMAIL:-$(kubectl get secret homelab-config --namespace argocd -o jsonpath='{.data.email}' | base64 -d)}"
  fi
fi
if [[ -z "${DOMAIN:-}" ]]; then
  read -rp "Domain (e.g. example.com): " DOMAIN
fi
if [[ -z "${EMAIL:-}" ]]; then
  read -rp "ACME email (e.g. you@example.com): " EMAIL
fi

if [[ ! "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
  echo "Error: DOMAIN must be a plain hostname, got '$DOMAIN'" >&2
  exit 1
fi
if [[ ! "$EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]]; then
  echo "Error: EMAIL must be a plain address, got '$EMAIL'" >&2
  exit 1
fi

SSH_KEY_FILE="${SSH_KEY_FILE:-${HOME}/.ssh/id_ed25519_argocd}"

# Install the same chart version Argo CD later manages itself, avoiding an
# upgrade or downgrade on its first self-sync.
ARGOCD_CHART_VERSION="$(awk '/chart: argo-cd/ { found = 1 } found && /targetRevision:/ { print $2; exit }' \
  "$SCRIPT_DIR/../apps/argocd/application.yaml")"
if [[ -z "$ARGOCD_CHART_VERSION" ]]; then
  echo "Error: could not read the argo-cd chart version from k8s/apps/argocd/application.yaml" >&2
  exit 1
fi

# ---- Bootstrap ----

echo "==> Creating namespaces..."
kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace cert-manager --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace external-dns --dry-run=client -o yaml | kubectl apply -f -

if kubectl get secret homelab-config --namespace argocd &>/dev/null; then
  echo "==> homelab-config secret already exists, skipping."
else
  echo "==> Storing domain config in cluster (never written to git)..."
  kubectl create secret generic homelab-config \
    --namespace argocd \
    --from-literal=domain="$DOMAIN" \
    --from-literal=email="$EMAIL" \
    --dry-run=client -o yaml | kubectl apply -f -
fi

echo "==> Applying ArgoCD CMP plugin config..."
kubectl apply -f "$SCRIPT_DIR/argocd-cmp.yaml"

echo "==> Installing ArgoCD via Helm..."
helm repo add argo https://argoproj.github.io/argo-helm
helm repo update

ARGOCD_VALUES=$(sed "s|\${DOMAIN}|${DOMAIN}|g; s|\${EMAIL}|${EMAIL}|g" "$SCRIPT_DIR/argocd-values.yaml")

helm upgrade --install argocd argo/argo-cd \
  --version "$ARGOCD_CHART_VERSION" \
  --namespace argocd \
  --values <(echo "$ARGOCD_VALUES") \
  --set "global.domain=argocd.${DOMAIN}" \
  --wait

echo "==> Creating repo credential secret (managed outside Helm)..."
kubectl create secret generic argocd-repo-homelab \
  --namespace argocd \
  --from-literal=type=git \
  --from-literal=url="$REPO_URL" \
  --from-file=sshPrivateKey="$SSH_KEY_FILE" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl label secret argocd-repo-homelab \
  --namespace argocd \
  argocd.argoproj.io/secret-type=repository \
  --overwrite

_cf_external_dns_exists=false
_cf_cert_manager_exists=false
kubectl get secret cloudflare-api-token --namespace external-dns &>/dev/null && _cf_external_dns_exists=true
kubectl get secret cloudflare-api-token --namespace cert-manager &>/dev/null && _cf_cert_manager_exists=true

if [[ "$_cf_external_dns_exists" == "true" && "$_cf_cert_manager_exists" == "true" ]]; then
  echo "==> cloudflare-api-token secrets already exist, skipping."
else
  echo "==> Creating Cloudflare API token secret for external-dns and cert-manager..."
  echo ""
  echo "Please provide your Cloudflare API token"
  echo "(needs Zone:DNS:Edit + Zone:Zone:Read permissions):"
  read -rsp "  Cloudflare API Token: " CF_TOKEN
  echo ""

  if [[ "$_cf_external_dns_exists" == "false" ]]; then
    kubectl create secret generic cloudflare-api-token \
      --namespace external-dns \
      --from-file=api-token=<(printf '%s' "$CF_TOKEN") \
      --dry-run=client -o yaml | kubectl apply -f -
  fi

  if [[ "$_cf_cert_manager_exists" == "false" ]]; then
    kubectl create secret generic cloudflare-api-token \
      --namespace cert-manager \
      --from-file=api-token=<(printf '%s' "$CF_TOKEN") \
      --dry-run=client -o yaml | kubectl apply -f -
  fi
fi

_argocd_oauth_exists=false
if kubectl get secret argocd-secret --namespace argocd &>/dev/null; then
  _existing_client_id="$(kubectl get secret argocd-secret --namespace argocd -o jsonpath='{.data.dex\.github\.clientID}' 2>/dev/null)"
  [[ -n "$_existing_client_id" ]] && _argocd_oauth_exists=true
fi

if [[ "$_argocd_oauth_exists" == "true" ]]; then
  echo "==> ArgoCD GitHub OAuth already configured in argocd-secret, skipping."
else
  echo "==> Configuring GitHub OAuth for ArgoCD..."
  echo ""
  echo "Create a GitHub OAuth App at https://github.com/settings/developers"
  echo "  Homepage URL:  https://argocd.${DOMAIN}"
  echo "  Callback URL:  https://argocd.${DOMAIN}/api/dex/callback"
  echo ""
  read -rp "  GitHub OAuth Client ID: " ARGOCD_GH_CLIENT_ID
  read -rsp "  GitHub OAuth Client Secret: " ARGOCD_GH_CLIENT_SECRET
  echo ""

  export ARGOCD_GH_CLIENT_ID ARGOCD_GH_CLIENT_SECRET
  json_from_env 'import json, os; print(json.dumps({"stringData": {
      "dex.github.clientID": os.environ["ARGOCD_GH_CLIENT_ID"],
      "dex.github.clientSecret": os.environ["ARGOCD_GH_CLIENT_SECRET"]}}))' |
    kubectl patch secret argocd-secret \
      --namespace argocd \
      --type merge \
      --patch-file /dev/stdin
  unset ARGOCD_GH_CLIENT_SECRET
fi

kubectl create namespace paperless --dry-run=client -o yaml | kubectl apply -f -

if kubectl get secret paperless-github-oauth --namespace paperless &>/dev/null; then
  echo "==> paperless-github-oauth secret already exists, skipping."
else
  echo "==> Configuring GitHub OAuth for Paperless-ngx..."
  echo ""
  echo "Create a GitHub OAuth App at https://github.com/settings/developers"
  echo "  Homepage URL:  https://paperless.${DOMAIN}"
  echo "  Callback URL:  https://paperless.${DOMAIN}/accounts/github/login/callback/"
  echo ""
  read -rp "  GitHub OAuth Client ID: " PAPERLESS_GH_CLIENT_ID
  read -rsp "  GitHub OAuth Client Secret: " PAPERLESS_GH_CLIENT_SECRET
  echo ""

  export PAPERLESS_GH_CLIENT_ID PAPERLESS_GH_CLIENT_SECRET
  kubectl create secret generic paperless-github-oauth \
    --namespace paperless \
    --from-file=providers-json=<(json_from_env 'import json, os; print(json.dumps({"github": {"APP": {
      "client_id": os.environ["PAPERLESS_GH_CLIENT_ID"],
      "secret": os.environ["PAPERLESS_GH_CLIENT_SECRET"], "key": ""}}}))') \
    --dry-run=client -o yaml | kubectl apply -f -
  unset PAPERLESS_GH_CLIENT_SECRET
fi

kubectl create namespace grafana-alloy --dry-run=client -o yaml | kubectl apply -f -

if kubectl get secret grafana-cloud-credentials --namespace grafana-alloy &>/dev/null; then
  _gc_otlp_url="$(kubectl get secret grafana-cloud-credentials --namespace grafana-alloy -o jsonpath='{.data.OTLP_URL}' 2>/dev/null)"
  _gc_otlp_username="$(kubectl get secret grafana-cloud-credentials --namespace grafana-alloy -o jsonpath='{.data.OTLP_USERNAME}' 2>/dev/null)"

  if [[ -n "$_gc_otlp_url" && -n "$_gc_otlp_username" ]]; then
    echo "==> grafana-cloud-credentials secret already includes OTLP credentials, skipping."
  else
    echo "==> Adding Grafana Cloud OTLP credentials to the existing secret..."
    echo ""
    echo "Find these at https://grafana.com -> your stack -> OpenTelemetry -> Configure"
    echo "The existing API token must include the traces:write scope."
    echo ""
    read -rp "  OTLP/gRPC endpoint (host:port): " GC_OTLP_URL
    read -rp "  OTLP username (instance ID): " GC_OTLP_USERNAME

    _gc_otlp_url_b64="$(printf '%s' "$GC_OTLP_URL" | base64 | tr -d '\n')"
    _gc_otlp_username_b64="$(printf '%s' "$GC_OTLP_USERNAME" | base64 | tr -d '\n')"
    kubectl patch secret grafana-cloud-credentials \
      --namespace grafana-alloy \
      --type merge \
      --patch-file <(printf '{"data":{"OTLP_URL":"%s","OTLP_USERNAME":"%s"}}' "$_gc_otlp_url_b64" "$_gc_otlp_username_b64")
  fi
else
  echo "==> Configuring Grafana Cloud credentials..."
  echo ""
  echo "Find these at https://grafana.com -> your stack -> Details"
  echo "The API token must include metrics:write, logs:write, and traces:write scopes."
  echo ""
  read -rsp "  Grafana Cloud API token (glc_...): " GC_API_KEY
  echo ""
  read -rp "  Prometheus remote write URL: " GC_METRICS_URL
  read -rp "  Prometheus username (instance ID): " GC_METRICS_USERNAME
  read -rp "  Loki push URL: " GC_LOGS_URL
  read -rp "  Loki username (instance ID): " GC_LOGS_USERNAME
  read -rp "  OTLP/gRPC endpoint (host:port): " GC_OTLP_URL
  read -rp "  OTLP username (instance ID): " GC_OTLP_USERNAME

  kubectl create secret generic grafana-cloud-credentials \
    --namespace grafana-alloy \
    --from-file=API_KEY=<(printf '%s' "$GC_API_KEY") \
    --from-literal=METRICS_URL="$GC_METRICS_URL" \
    --from-literal=METRICS_USERNAME="$GC_METRICS_USERNAME" \
    --from-literal=LOGS_URL="$GC_LOGS_URL" \
    --from-literal=LOGS_USERNAME="$GC_LOGS_USERNAME" \
    --from-literal=OTLP_URL="$GC_OTLP_URL" \
    --from-literal=OTLP_USERNAME="$GC_OTLP_USERNAME" \
    --dry-run=client -o yaml | kubectl apply -f -
fi

echo "==> Retrieving ArgoCD initial admin password..."
echo "    Password: $(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d)"
echo ""

echo "==> Bootstrap complete!"
echo "    Next: kubectl apply -f k8s/apps/app-of-apps.yaml"
echo ""
echo "    ArgoCD will deploy all apps. The envsubst CMP will inject"
echo "    \${DOMAIN} and \${EMAIL} into manifests at sync time."
