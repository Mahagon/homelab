mock_provider "cloudflare" {
  mock_resource "cloudflare_zero_trust_tunnel_cloudflared" {
    defaults = {
      id = "11111111111111111111111111111111"
    }
  }

  mock_data "cloudflare_zero_trust_tunnel_cloudflared_token" {
    defaults = {
      token = "test-token"
    }
  }
}

run "routes_are_private" {
  command = plan

  variables {
    cloudflare_account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    cloudflare_zone_id    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }

  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.home_assistant.config.ingress[0].service == "http://alexa-proxy.alexa-proxy.svc.cluster.local:8080"
    error_message = "Alexa must use the in-cluster proxy."
  }
}
