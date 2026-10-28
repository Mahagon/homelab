# Grist trusts the Cf-Access-Authenticated-User-Email header for identity, so
# the whole zaehlerstaende hostname sits behind Access. Neighbours sign in with
# a one-time PIN sent to an allowlisted address. The Zero Trust organization and
# its One-time PIN login method are a one-time dashboard setup.
resource "cloudflare_zero_trust_access_policy" "zaehlerstaende" {
  account_id       = var.cloudflare_account_id
  name             = "Zaehlerstaende neighbours"
  decision         = "allow"
  session_duration = "168h"
  include          = [for email in var.zaehlerstaende_allowed_emails : { email = { email = email } }]
}

resource "cloudflare_zero_trust_access_application" "zaehlerstaende" {
  account_id                 = var.cloudflare_account_id
  name                       = "Zaehlerstaende"
  type                       = "self_hosted"
  domain                     = local.zaehlerstaende_hostname
  session_duration           = "168h"
  app_launcher_visible       = false
  http_only_cookie_attribute = true
  same_site_cookie_attribute = "lax"

  policies = [
    {
      id         = cloudflare_zero_trust_access_policy.zaehlerstaende.id
      precedence = 1
    }
  ]
}
