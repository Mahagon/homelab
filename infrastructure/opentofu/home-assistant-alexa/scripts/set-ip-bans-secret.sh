#!/usr/bin/env bash
# Creates the ip-bans Kubernetes Secret from OpenTofu outputs and interactive
# prompts. Nothing is written to disk, echoed, or passed as a process argument.
set -euo pipefail

usage() {
  echo "Usage: set-ip-bans-secret.sh [--tofu-directory DIR] [--kube-context CONTEXT] [--dry-run]"
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

kubectl "${kubectl_args[@]}" get namespace ip-bans >/dev/null 2>&1 \
  || die "Namespace 'ip-bans' does not exist. Sync the Argo CD ip-bans application first."

ids="$(tofu "-chdir=$tofu_directory" output -json ip_bans_sync | jq -c .)" || ids=""
[[ "$ids" == \{* ]] || die "Unable to read ip_bans_sync from OpenTofu state. Apply the main root first."

cloudflare_token="" abuseipdb_key="" allowlist=""
trap 'cloudflare_token="" abuseipdb_key="" allowlist=""' EXIT

read -rsp "Cloudflare API token (Filter Lists Edit, Zone Analytics Read, Zone WAF Read): " cloudflare_token
echo
cloudflare_token="${cloudflare_token//[[:space:]]/}"
[[ -n "$cloudflare_token" ]] || die "A Cloudflare API token is required."

read -rsp "AbuseIPDB API key (empty disables import and reporting): " abuseipdb_key
echo
abuseipdb_key="${abuseipdb_key//[[:space:]]/}"

echo "Addresses that must never be banned, e.g. your home IPv6 prefix. The public"
echo "IPv4 of the cluster's connection is detected automatically."
read -rp "Allowlist (comma-separated IPs/CIDRs, empty for none): " allowlist

if [[ "$dry_run" == true ]]; then
  echo "Would create or update secret ip-bans/ip-bans."
  exit 0
fi

# printf is a shell builtin, so the values never appear in a process argument list.
printf '%s\n%s\n%s\n%s\n' "$ids" "$cloudflare_token" "$abuseipdb_key" "$allowlist" | jq -nRc '
  (input | fromjson) as $ids | input as $token | input as $key | input as $allow
  | {
      CLOUDFLARE_API_TOKEN: $token,
      CLOUDFLARE_ACCOUNT_ID: $ids.account_id,
      CLOUDFLARE_ZONE_ID: $ids.zone_id,
      CLOUDFLARE_LIST_ID: $ids.list_id,
      ABUSEIPDB_API_KEY: $key,
      IP_BAN_ALLOWLIST: $allow
    }
  | with_entries(select(.value != ""))
  | {
      apiVersion: "v1", kind: "Secret",
      metadata: {name: "ip-bans", namespace: "ip-bans"},
      type: "Opaque",
      data: map_values(@base64)
    }' | kubectl "${kubectl_args[@]}" apply -f - \
  || die "kubectl failed to apply the ip-bans Secret."

echo "Secret ip-bans/ip-bans updated; the next CronJob run uses it."
