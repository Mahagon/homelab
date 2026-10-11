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

# Bot Fight Mode challenges likely-automated traffic zone-wide, and AI Labyrinth
# serves AI crawlers a link maze instead of real content. Bot Fight Mode cannot
# be skipped by WAF rules on the Free plan, so watch Security > Events after
# applying: if Alexa Lambda (AWS) or companion-app requests get challenged, set
# fight_mode back to false.
resource "cloudflare_bot_management" "zone" {
  zone_id            = var.cloudflare_zone_id
  enable_js          = true
  fight_mode         = true
  crawler_protection = "enabled"
}
