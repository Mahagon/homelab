# Free-plan Cloudflare notifications, sent to the same address as the Grafana
# backup alerts. The tunnel alert matters most: Home Assistant, Alexa,
# Vaultwarden, and Jellyfin all go dark when the connector is down. Leaving
# new_status unset also reports the recovery to healthy.
resource "cloudflare_notification_policy" "tunnel_health" {
  account_id  = var.cloudflare_account_id
  name        = "Homelab tunnel health"
  description = "Tunnel connector degraded, down, or recovered."
  alert_type  = "tunnel_health_event"
  enabled     = true

  filters = {
    tunnel_id = [cloudflare_zero_trust_tunnel_cloudflared.home_assistant.id]
  }

  mechanisms = {
    email = [{ id = var.budget_email }]
  }
}

resource "cloudflare_notification_policy" "http_ddos" {
  account_id  = var.cloudflare_account_id
  name        = "Homelab HTTP DDoS attack"
  description = "Cloudflare mitigated an HTTP DDoS attack on the zone."
  alert_type  = "dos_attack_l7"
  enabled     = true

  filters = {
    zones = [var.cloudflare_zone_id]
  }

  mechanisms = {
    email = [{ id = var.budget_email }]
  }
}

resource "cloudflare_notification_policy" "universal_ssl" {
  account_id  = var.cloudflare_account_id
  name        = "Homelab Universal SSL"
  description = "Universal SSL certificate validation, issuance, renewal, or expiry problems."
  alert_type  = "universal_ssl_event_type"
  enabled     = true

  filters = {
    zones = [var.cloudflare_zone_id]
  }

  mechanisms = {
    email = [{ id = var.budget_email }]
  }
}
