#!/usr/bin/env bash
# Copies the Cloudflare tunnel token from OpenTofu state into the cloudflared
# Kubernetes Secret without writing it to disk, then restarts the connector.
set -euo pipefail

usage() {
  echo "Usage: set-cloudflared-secret.sh [--tofu-directory DIR] [--kube-context CONTEXT] [--dry-run]"
}

die() { echo "error: $*" >&2; exit 1; }

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tofu_directory="$script_dir/../main"
kube_context="" dry_run=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tofu-directory) tofu_directory="${2:?}"; shift 2 ;;
    --kube-context) kube_context="${2:?}"; shift 2 ;;
    --dry-run) dry_run=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

tofu_directory="$(cd "$tofu_directory" && pwd)"
kubectl_args=()
[[ -z "$kube_context" ]] || kubectl_args+=(--context "$kube_context")

kubectl "${kubectl_args[@]}" get namespace cloudflared >/dev/null 2>&1 \
  || die "Namespace 'cloudflared' does not exist. Sync the Argo CD cloudflared application first."

token="$(tofu "-chdir=$tofu_directory" output -raw cloudflared_tunnel_token)" || token=""
[[ -n "${token//[[:space:]]/}" ]] || die "Unable to read cloudflared_tunnel_token from OpenTofu state."
trap 'token=""' EXIT

if [[ "$dry_run" == true ]]; then
  echo "Would create or update secret cloudflared/cloudflared-tunnel-token and restart deployment/cloudflared."
  exit 0
fi

# printf is a shell builtin, so the token never appears in a process argument list.
printf '%s' "${token//[[:space:]]/}" | jq -nRc '{
  apiVersion: "v1", kind: "Secret",
  metadata: {name: "cloudflared-tunnel-token", namespace: "cloudflared"},
  type: "Opaque",
  data: {token: (input | @base64)}
}' | kubectl "${kubectl_args[@]}" apply -f - \
  || die "kubectl failed to apply the tunnel token Secret."

kubectl "${kubectl_args[@]}" rollout restart deployment/cloudflared --namespace cloudflared \
  || die "Secret was updated, but the cloudflared rollout could not be restarted."
