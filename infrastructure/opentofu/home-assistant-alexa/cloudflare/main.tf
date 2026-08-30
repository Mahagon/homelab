locals {
  tunnel_name = "home-assistant-k3s"
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "home_assistant" {
  account_id = var.cloudflare_account_id
  name       = local.tunnel_name
  config_src = "cloudflare"
}

data "cloudflare_zero_trust_tunnel_cloudflared_token" "home_assistant" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.home_assistant.id
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "home_assistant" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.home_assistant.id
  source     = "cloudflare"

  config = {
    ingress = [
      {
        hostname = var.hostname
        service  = "http://home-assistant.home-assistant.svc.cluster.local:8123"
        origin_request = {
          http_host_header = var.hostname
        }
      },
      {
        service = "http_status:404"
      }
    ]
  }
}

resource "cloudflare_dns_record" "home_assistant" {
  count   = var.publish_dns ? 1 : 0
  zone_id = var.cloudflare_zone_id
  name    = "homeassistant"
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.home_assistant.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
}

check "alexa_proxy_route" {
  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.home_assistant.config.ingress[0].service == "http://home-assistant.home-assistant.svc.cluster.local:8123"
    error_message = "All tunnel traffic must route to the internal Home Assistant service."
  }
}

check "home_assistant_route" {
  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.home_assistant.config.ingress[1].service == "http://home-assistant.home-assistant.svc.cluster.local:8123"
    error_message = "General hostname traffic must route to Home Assistant."
  }
}
