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
# into manifests at ArgoCD sync time via the envsubst CMP —
# they are never written to git.
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ---- Gather configuration ----

if [[ -z "${REPO_URL:-}" ]]; then
  read -rp "Git repo URL (e.g. git@github.com:You/homelab.git): " REPO_URL
fi
if [[ -z "${DOMAIN:-}" ]]; then
  read -rp "Domain (e.g. example.com): " DOMAIN
fi
if [[ -z "${EMAIL:-}" ]]; then
  read -rp "ACME email (e.g. you@example.com): " EMAIL
fi

SSH_KEY_FILE="${SSH_KEY_FILE:-${HOME}/.ssh/id_ed25519_argocd}"

# ---- Bootstrap ----

echo "==> Creating namespaces..."
kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace cert-manager --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace external-dns --dry-run=client -o yaml | kubectl apply -f -

echo "==> Storing domain config in cluster (never written to git)..."
kubectl create secret generic homelab-config \
  --namespace argocd \
  --from-literal=domain="$DOMAIN" \
  --from-literal=email="$EMAIL" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> Applying ArgoCD CMP plugin config..."
kubectl apply -f "$SCRIPT_DIR/argocd-cmp.yaml"

echo "==> Installing ArgoCD via Helm..."
helm repo add argo https://argoproj.github.io/argo-helm
helm repo update

helm upgrade --install argocd argo/argo-cd \
  --namespace argocd \
  --values "$SCRIPT_DIR/argocd-values.yaml" \
  --set "global.domain=argocd.${DOMAIN}" \
  --set "configs.repositories.homelab.url=$REPO_URL" \
  --set-file "configs.repositories.homelab.sshPrivateKey=$SSH_KEY_FILE" \
  --wait

echo "==> Creating Cloudflare API token secret for external-dns and cert-manager..."
echo ""
echo "Please provide your Cloudflare API token"
echo "(needs Zone:DNS:Edit + Zone:Zone:Read permissions):"
read -rsp "  Cloudflare API Token: " CF_TOKEN
echo ""

kubectl create secret generic cloudflare-api-token \
  --namespace external-dns \
  --from-literal=api-token="$CF_TOKEN" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic cloudflare-api-token \
  --namespace cert-manager \
  --from-literal=api-token="$CF_TOKEN" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> Retrieving ArgoCD initial admin password..."
echo "    Password: $(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d)"
echo ""

echo "==> Bootstrap complete!"
echo "    Next: kubectl apply -f k8s/apps/app-of-apps.yaml"
echo ""
echo "    ArgoCD will deploy all apps. The envsubst CMP will inject"
echo "    \${DOMAIN} and \${EMAIL} into manifests at sync time."
