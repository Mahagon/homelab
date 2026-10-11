# These settings apply to every proxied hostname in the zone, not only
# Home Assistant. TLS 1.2 remains compatible with current browsers, Alexa, and
# Home Assistant clients while disabling obsolete TLS 1.0 and 1.1 handshakes.
resource "cloudflare_zone_setting" "minimum_tls_version" {
  zone_id    = var.cloudflare_zone_id
  setting_id = "min_tls_version"
  value      = "1.2"
}

resource "cloudflare_zone_setting" "tls_1_3" {
  zone_id    = var.cloudflare_zone_id
  setting_id = "tls_1_3"
  value      = "on"
}

# Cloudflare signs the zone and returns the DS record. DNSSEC is not fully
# chained until that DS value is published through the domain registrar.
resource "cloudflare_zone_dnssec" "zone" {
  zone_id = var.cloudflare_zone_id
  status  = "active"
}

# Bot Fight Mode stays off: it cannot be skipped by WAF rules on the Free plan
# and managed-challenged the Alexa Lambda (AWS, Apache-HttpClient) calling
# /auth/token, which broke account linking and token refresh. AI Labyrinth
# (crawler_protection) still serves AI crawlers a link maze.
resource "cloudflare_bot_management" "zone" {
  zone_id            = var.cloudflare_zone_id
  enable_js          = true
  fight_mode         = false
  crawler_protection = "enabled"
}
