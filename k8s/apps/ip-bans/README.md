# IP bans

Two CronJobs keep the Cloudflare IP list `homelab_ip_bans` up to date. The
`home_assistant_unsafe_methods` custom WAF rule blocks every address on it for
all tunnel hostnames. Amazon's Alexa traffic on `/api/alexa/smart_home` and
`/auth/token` is exempt, because shared AWS addresses are reported often.

| CronJob             | Schedule (UTC) | What it does                                                                                                                                                              |
| ------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ip-bans-recon`     | every 5 min    | Bans each source of a `home_assistant_reconnaissance_paths` block for 24 h (IPv6 as its /64), reports new bans to AbuseIPDB as _Web App Attack_, and removes expired bans |
| `ip-bans-abuseipdb` | `17 */6 * * *` | Mirrors AbuseIPDB blacklist entries from Germany reported in the last 7 days, capped at 8,000 items                                                                       |

The geo rules already block every country except Germany, so importing other
countries would only use up list slots. The Free plan allows 10,000 items
across all lists. Recon bans and manually added items take precedence over
imported entries.

## Addresses stay out of git and logs

- OpenTofu owns only the empty list. Its `items` are left unset, so the provider
  never reads them into state or CI plans. Never add items there or
  `tofu import` the list.
- Each job writes only items whose comment carries its own tag
  (`ip-bans:recon:<time>` or `ip-bans:abuseipdb:<time>`). Items you add by
  hand in the dashboard are left alone.
- Logs contain counts only, and API error text is redacted. Pod logs are
  shipped off the cluster.
- Tests use documentation addresses only. `test_no_public_addresses_are_committed`
  fails if a public IP literal is committed under this directory.

## Never banning yourself

Each run looks up the connection's public IPv4 (and IPv6, when the pod has
one) through `ipv4.icanhazip.com` and `ipv6.icanhazip.com`. It exempts those
addresses for that run only, and removes them from the list if an AbuseIPDB
import added them. If the IPv4 lookup fails, the run changes nothing and fails;
the 60-minute lookback catches up on the next run.

The cluster is IPv4 single-stack, so the pod cannot see your IPv6 prefix. Add
the prefix your router delegates (for example a /56) to the allowlist. Mobile
and other networks are not covered: an address you used on them can still be
banned after a probe.

## Setup

1. Create a Cloudflare API token for this account and zone with only:
   - Account Filter Lists: Edit;
   - Zone Analytics: Read;
   - Zone WAF: Read.
2. Create an AbuseIPDB account and API key. This is optional: without a key the
   import job fails and reporting is skipped.
3. Apply the `main` OpenTofu root, then let ArgoCD sync this application.
4. Create the Secret. The script reads the list, account, and zone IDs from
   state and prompts for the token, the key, and the allowlist:

   ```bash
   infrastructure/opentofu/home-assistant-alexa/scripts/set-ip-bans-secret.sh
   ```

5. Run the import once instead of waiting for the schedule:

   ```bash
   kubectl -n ip-bans create job --from=cronjob/ip-bans-abuseipdb ip-bans-abuseipdb-manual
   kubectl -n ip-bans logs job/ip-bans-abuseipdb-manual
   ```

   Free AbuseIPDB keys allow five blacklist downloads a day; the schedule
   uses four.

## Operations

- **Unban an address:** delete its item from `homelab_ip_bans` on the
  account's Lists page in the Cloudflare dashboard. A recon ban comes back only
  if the address probes again.
- **Pause:** `kubectl -n ip-bans patch cronjob ip-bans-recon -p '{"spec":{"suspend":true}}'`.
  This keeps the current bans; delete the items to lift them.
- **Change the allowlist:** rerun the Secret script. The next runs remove
  matching items.
- **Edit the script:** change `scripts/sync_ip_bans.py`, then run
  `python k8s/apps/ip-bans/scripts/render_configmap.py`. ArgoCD applies the
  embedded copy in `manifests/script-configmap.yaml`.
- **Test:** `python -m unittest discover -s k8s/apps/ip-bans/scripts/tests -p "test_*.py" -v`.

Firewall events are sampled, so a single probe can occasionally be missed.
