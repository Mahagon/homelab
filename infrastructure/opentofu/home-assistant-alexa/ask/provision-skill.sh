#!/usr/bin/env bash
# Renders skill-template.json and creates or updates the Alexa skill via ASK CLI v2.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: provision-skill.sh --lambda-arn ARN --small-icon-uri URL --large-icon-uri URL
                          [--skill-id ID] [--ask-profile NAME] [--skip-account-linking]
USAGE
}

die() { echo "error: $*" >&2; exit 1; }

lambda_arn="" small_icon_uri="" large_icon_uri="" skill_id="" ask_profile="default" skip_linking=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --lambda-arn) lambda_arn="${2:?}"; shift 2 ;;
    --small-icon-uri) small_icon_uri="${2:?}"; shift 2 ;;
    --large-icon-uri) large_icon_uri="${2:?}"; shift 2 ;;
    --skill-id) skill_id="${2:?}"; shift 2 ;;
    --ask-profile) ask_profile="${2:?}"; shift 2 ;;
    --skip-account-linking) skip_linking=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

[[ "$lambda_arn" =~ ^arn:aws:lambda:eu-west-1:[0-9]{12}:function:home-assistant-alexa$ ]] \
  || die "--lambda-arn must be the home-assistant-alexa function ARN in eu-west-1."
[[ "$small_icon_uri" =~ ^https:// ]] || die "--small-icon-uri must start with https://"
[[ "$large_icon_uri" =~ ^https:// ]] || die "--large-icon-uri must start with https://"
[[ -z "$skill_id" || "$skill_id" =~ ^amzn1\.ask\.skill\.[0-9a-fA-F-]{36}$ ]] \
  || die "--skill-id is not a valid Alexa skill ID."

command -v ask >/dev/null \
  || die "ASK CLI v2 is not installed. Run 'npm install --global ask-cli@2' and then 'ask configure'."
command -v jq >/dev/null || die "jq is required."

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
template_path="$script_dir/skill-template.json"
rendered_path="$script_dir/rendered-skill.json"

# jq's gsub replacement is literal, so URLs containing '&' are safe.
manifest="$(jq -c \
  --arg lambda "$lambda_arn" --arg small "$small_icon_uri" --arg large "$large_icon_uri" '
  walk(if type == "string" then
    gsub("\\$\\{LAMBDA_ARN\\}"; $lambda) | gsub("\\$\\{SMALL_ICON_URI\\}"; $small) | gsub("\\$\\{LARGE_ICON_URI\\}"; $large)
  else . end)' "$template_path")"
printf '%s\n' "$manifest" > "$rendered_path"

if [[ -n "$skill_id" ]]; then
  ask smapi update-skill-manifest --skill-id "$skill_id" --file "$rendered_path" --profile "$ask_profile" \
    || die "ASK CLI failed to update skill $skill_id."
else
  result="$(ask smapi create-skill-for-vendor --manifest "$manifest" --profile "$ask_profile")" \
    || die "ASK CLI failed to create the skill."
  printf '%s\n' "$result"
  skill_id="$(jq -r '.skillId // empty' <<<"$result" 2>/dev/null || true)"
  [[ -n "$skill_id" ]] \
    || echo "warning: Could not parse the Skill ID automatically. Copy it from the ASK output or Developer Console." >&2
fi

if [[ -z "$skill_id" ]]; then
  echo "warning: Re-run this script with --skill-id after copying the generated Skill ID." >&2
  exit 0
fi

echo "Skill ID: $skill_id"
echo "Set GitHub variable ALEXA_SKILL_ID to this value and re-run the OpenTofu apply."

if [[ "$skip_linking" != true ]]; then
  echo "ASK will now prompt for account linking. Use the values documented in docs/home-assistant-alexa.md."
  ask api create-account-linking --skill-id "$skill_id" --stage development --profile "$ask_profile" \
    || die "ASK CLI account-linking configuration failed."
fi
