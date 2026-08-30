locals {
  home_assistant_waf_scope = "(http.host eq \"${local.home_assistant_hostname}\")"
}

# Cloudflare automatically deploys its Free Managed Ruleset on Free zones. This
# entry-point ruleset adds custom controls that are safe for Home Assistant's
# browser, companion-app, WebSocket, OAuth, and Alexa traffic.
resource "cloudflare_ruleset" "home_assistant_custom_waf" {
  zone_id     = var.cloudflare_zone_id
  name        = "Home Assistant custom WAF controls"
  description = "Free-plan custom WAF controls scoped to the Home Assistant tunnel hostname."
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules = [
    {
      ref         = "home_assistant_https_only"
      description = "Block Home Assistant traffic on ports other than HTTPS 443"
      expression  = "${local.home_assistant_waf_scope} and (cf.edge.server_port ne 443)"
      action      = "block"
      enabled     = true
    },
    {
      ref         = "home_assistant_unsafe_methods"
      description = "Block HTTP methods that Home Assistant never requires"
      expression  = "${local.home_assistant_waf_scope} and (http.request.method in {\"CONNECT\" \"TRACE\" \"TRACK\"})"
      action      = "block"
      enabled     = true
    },
    {
      ref         = "home_assistant_reconnaissance_paths"
      description = "Block common source-control, secret-file, and unrelated CMS probes"
      expression  = "${local.home_assistant_waf_scope} and (starts_with(lower(http.request.uri.path), \"/.git\") or starts_with(lower(http.request.uri.path), \"/.svn\") or starts_with(lower(http.request.uri.path), \"/.hg\") or lower(http.request.uri.path) in {\"/.env\" \"/.ds_store\" \"/xmlrpc.php\" \"/wp-login.php\"} or starts_with(lower(http.request.uri.path), \"/wp-admin\") or starts_with(lower(http.request.uri.path), \"/phpmyadmin\"))"
      action      = "block"
      enabled     = true
    }
  ]
}

# The Free plan permits one rate-limiting rule, a ten-second counting period,
# and IP-based counting. Host is not an available Free-plan rate expression
# field, so this uses Home Assistant's distinctive login-flow path. It does not
# include /auth/token, /api, WebSocket, or Alexa directive traffic.
resource "cloudflare_ruleset" "home_assistant_rate_limit" {
  zone_id     = var.cloudflare_zone_id
  name        = "Home Assistant authentication rate limit"
  description = "Free-plan per-IP protection for Home Assistant login-flow requests."
  kind        = "zone"
  phase       = "http_ratelimit"

  rules = [
    {
      ref         = "rate_limit_home_assistant_login_flow"
      description = "Block an IP after more than 10 Home Assistant login-flow requests in 10 seconds"
      expression  = "(http.request.uri.path eq \"/auth/login_flow\" or starts_with(http.request.uri.path, \"/auth/login_flow/\"))"
      action      = "block"
      enabled     = true
      ratelimit = {
        characteristics     = ["cf.colo.id", "ip.src"]
        period              = 10
        requests_per_period = 10
        mitigation_timeout  = 10
      }
    }
  ]
}

# Home Assistant is authenticated and stateful. Explicitly bypassing the edge
# cache prevents a future origin-header change from making any response cache
# eligible, including API and authentication responses.
resource "cloudflare_ruleset" "home_assistant_cache" {
  zone_id     = var.cloudflare_zone_id
  name        = "Home Assistant cache policy"
  description = "Never cache Home Assistant responses at the Cloudflare edge."
  kind        = "zone"
  phase       = "http_request_cache_settings"

  rules = [
    {
      ref         = "bypass_home_assistant_cache"
      description = "Bypass Cloudflare cache for every Home Assistant response"
      expression  = local.home_assistant_waf_scope
      action      = "set_cache_settings"
      enabled     = true
      action_parameters = {
        cache = false
      }
    }
  ]
}

# Start HSTS with a reversible 30-day lifetime and deliberately omit
# includeSubDomains and preload because this module owns only one zone hostname.
resource "cloudflare_ruleset" "home_assistant_response_headers" {
  zone_id     = var.cloudflare_zone_id
  name        = "Home Assistant security response headers"
  description = "Set conservative browser security headers on Home Assistant responses."
  kind        = "zone"
  phase       = "http_response_headers_transform"

  rules = [
    {
      ref         = "home_assistant_security_headers"
      description = "Set HSTS and disable MIME content sniffing for Home Assistant"
      expression  = local.home_assistant_waf_scope
      action      = "rewrite"
      enabled     = true
      action_parameters = {
        headers = {
          "strict-transport-security" = {
            operation = "set"
            value     = "max-age=2592000"
          }
          "x-content-type-options" = {
            operation = "set"
            value     = "nosniff"
          }
        }
      }
    }
  ]
}
