locals {
  home_assistant_waf_scope = "(http.host eq \"${local.home_assistant_hostname}\")"
  vaultwarden_waf_scope    = "(http.host eq \"${local.vaultwarden_hostname}\")"
  tunnel_waf_scope         = "(http.host in {\"${local.home_assistant_hostname}\" \"${local.vaultwarden_hostname}\"})"

  home_assistant_allowed_countries = ["DE"]
  # Alexa directives come from the eu-west-1 Lambda (IE) and account linking
  # from Amazon's token service, so Amazon ASNs bypass the geo block.
  # ponytail: whole AWS ASNs, narrow to /api/alexa + /auth/token if abused
  home_assistant_amazon_asns = [16509, 14618]

  vaultwarden_allowed_countries = ["DE"]
}

# Cloudflare automatically deploys its Free Managed Ruleset on Free zones. This
# entry-point ruleset adds custom controls that are safe for Home Assistant's
# browser, companion-app, WebSocket, OAuth, and Alexa traffic, and for the
# Vaultwarden web vault and Bitwarden clients. The Free plan permits five custom
# rules, so the Vaultwarden geo and admin-panel blocks share one rule.
resource "cloudflare_ruleset" "home_assistant_custom_waf" {
  zone_id     = var.cloudflare_zone_id
  name        = "Home Assistant custom WAF controls"
  description = "Free-plan custom WAF controls scoped to the tunnel hostnames."
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules = [
    {
      ref         = "home_assistant_https_only"
      description = "Block tunnel traffic on ports other than HTTPS 443"
      expression  = "${local.tunnel_waf_scope} and (cf.edge.server_port ne 443)"
      action      = "block"
      enabled     = true
    },
    {
      ref         = "home_assistant_unsafe_methods"
      description = "Block HTTP methods that the tunnel services never require"
      expression  = "${local.tunnel_waf_scope} and (http.request.method in {\"CONNECT\" \"TRACE\" \"TRACK\"})"
      action      = "block"
      enabled     = true
    },
    {
      ref         = "home_assistant_reconnaissance_paths"
      description = "Block common source-control, secret-file, and unrelated CMS probes"
      expression  = "${local.tunnel_waf_scope} and (starts_with(lower(http.request.uri.path), \"/.git\") or starts_with(lower(http.request.uri.path), \"/.svn\") or starts_with(lower(http.request.uri.path), \"/.hg\") or lower(http.request.uri.path) in {\"/.env\" \"/.ds_store\" \"/xmlrpc.php\" \"/wp-login.php\"} or starts_with(lower(http.request.uri.path), \"/wp-admin\") or starts_with(lower(http.request.uri.path), \"/phpmyadmin\"))"
      action      = "block"
      enabled     = true
    },
    {
      ref         = "home_assistant_geo_allowlist"
      description = "Block Home Assistant traffic from outside allowed countries, except Amazon (Alexa)"
      expression  = "${local.home_assistant_waf_scope} and not (ip.src.country in {${join(" ", [for c in local.home_assistant_allowed_countries : "\"${c}\""])}}) and not (ip.src.asnum in {${join(" ", local.home_assistant_amazon_asns)}})"
      action      = "block"
      enabled     = true
    },
    {
      ref         = "vaultwarden_geo_allowlist_and_admin"
      description = "Block Vaultwarden traffic from outside allowed countries and all public admin-panel requests"
      expression  = "${local.vaultwarden_waf_scope} and (not (ip.src.country in {${join(" ", [for c in local.vaultwarden_allowed_countries : "\"${c}\""])}}) or lower(http.request.uri.path) eq \"/admin\" or starts_with(lower(http.request.uri.path), \"/admin/\"))"
      action      = "block"
      enabled     = true
    }
  ]
}

# The Free plan permits one rate-limiting rule, a ten-second counting period,
# and IP-based counting. Host is not an available Free-plan rate expression
# field, so this uses Home Assistant's distinctive login-flow path and
# Vaultwarden's login path. It does not include /auth/token, /api, WebSocket,
# or Alexa directive traffic.
resource "cloudflare_ruleset" "home_assistant_rate_limit" {
  zone_id     = var.cloudflare_zone_id
  name        = "Home Assistant authentication rate limit"
  description = "Free-plan per-IP protection for Home Assistant and Vaultwarden login requests."
  kind        = "zone"
  phase       = "http_ratelimit"

  rules = [
    {
      ref         = "rate_limit_home_assistant_login_flow"
      description = "Block an IP after more than 10 Home Assistant or Vaultwarden login requests in 10 seconds"
      expression  = "(http.request.uri.path eq \"/auth/login_flow\" or starts_with(http.request.uri.path, \"/auth/login_flow/\") or http.request.uri.path eq \"/identity/connect/token\")"
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

# Home Assistant and Vaultwarden are authenticated and stateful. Explicitly bypassing the edge
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
    },
    {
      ref         = "bypass_vaultwarden_cache"
      description = "Bypass Cloudflare cache for every Vaultwarden response"
      expression  = local.vaultwarden_waf_scope
      action      = "set_cache_settings"
      enabled     = true
      action_parameters = {
        cache = false
      }
    }
  ]
}

# Start HSTS with a reversible 30-day lifetime and deliberately omit
# includeSubDomains and preload because this module owns only two zone hostnames.
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
    },
    {
      ref         = "vaultwarden_security_headers"
      description = "Set HSTS and disable MIME content sniffing for Vaultwarden"
      expression  = local.vaultwarden_waf_scope
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
