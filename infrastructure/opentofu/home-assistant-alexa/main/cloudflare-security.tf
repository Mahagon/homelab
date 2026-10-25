locals {
  home_assistant_waf_scope = "(http.host eq \"${local.home_assistant_hostname}\")"
  vaultwarden_waf_scope    = "(http.host eq \"${local.vaultwarden_hostname}\")"
  jellyfin_waf_scope       = "(http.host eq \"${local.jellyfin_hostname}\")"
  tunnel_waf_scope         = "(http.host in {\"${local.home_assistant_hostname}\" \"${local.vaultwarden_hostname}\" \"${local.jellyfin_hostname}\"})"
  # Vaultwarden and Jellyfin share one geo rule, so they share one allowlist.
  geo_allowlist_scope = "(http.host in {\"${local.vaultwarden_hostname}\" \"${local.jellyfin_hostname}\"})"

  home_assistant_allowed_countries = ["DE"]
  # Alexa directives come from the eu-west-1 Lambda (IE) and account linking
  # from Amazon's token service, so Amazon ASNs bypass the geo block, but only
  # on those two endpoints: anyone can rent an AWS instance in any country.
  home_assistant_amazon_asns  = [16509, 14618]
  home_assistant_amazon_paths = ["/api/alexa/smart_home", "/auth/token"]
  amazon_alexa_traffic        = "(ip.src.asnum in {${join(" ", local.home_assistant_amazon_asns)}} and http.request.uri.path in {${join(" ", [for p in local.home_assistant_amazon_paths : "\"${p}\""])}})"

  # Rule expressions reference lists as $<name>.
  ip_bans_list = format("$%s", cloudflare_list.ip_bans.name)

  geo_allowed_countries = ["DE"]

  # Secret-file, source-control, and CMS probes seen in the zone's security
  # events. None of the tunnel services serve dotfiles, PHP, WordPress, or Spring
  # Actuator paths. The suffixes catch nested variants (/backend/.env,
  # /old/phpinfo.php) that Germany-hosted scanners get past the geo rules with.
  recon_path_prefixes = ["/.git", "/.svn", "/.hg", "/.env", "/.aws", "/.docker", "/.kube", "/actuator", "/wp-", "/phpmyadmin"]
  recon_path_suffixes = ["/.env", ".php"]
  recon_paths = join(" or ", concat(
    [for p in local.recon_path_prefixes : "starts_with(${local.lower_path}, \"${p}\")"],
    [for s in local.recon_path_suffixes : "ends_with(${local.lower_path}, \"${s}\")"],
    ["${local.lower_path} eq \"/.ds_store\""],
  ))

  # Jellyfin's dashboard is a client-side route (/web/#/dashboard) that never
  # reaches the edge, so the admin API it calls is blocked instead. Derived from
  # the RequiresElevation/FirstTimeSetupOrElevated operations in the 12.2
  # OpenAPI spec (including installed plugins); recheck after major upgrades.
  # Not covered: POST /Items/{id} (metadata edit) and Live TV timers, which
  # cannot be matched by path without regex.
  lower_path = "lower(http.request.uri.path)"
  jellyfin_admin_path_prefixes = [
    "/anidb", "/auth/", "/backup", "/devices", "/environment", "/episode/",
    "/filetransformation", "/intros/", "/introskipper", "/items/remotesearch/apply",
    "/items/remotesearch/person", "/library/mediafolders", "/library/physicalpaths",
    "/library/refresh", "/library/virtualfolders", "/livetv/channelmapping",
    "/livetv/listingproviders", "/livetv/tuner", "/mediasegmentsapi", "/packages",
    "/plugins", "/repositories", "/scheduledtasks", "/skipbuttoncss", "/startup/",
    "/system/activitylog", "/system/configuration/metadataoptions", "/system/info/storage",
    "/system/logs", "/system/restart", "/system/shutdown", "/users/new",
    "/videos/mergeversions", "/web/configurationpages",
  ]
  jellyfin_admin_item_subpaths = ["/contenttype", "/externalidinfos", "/metadataeditor", "/refresh", "/remoteimages/download"]
  jellyfin_admin_paths = join(" or ", concat(
    [for p in local.jellyfin_admin_path_prefixes : "starts_with(${local.lower_path}, \"${p}\")"],
    [
      "(starts_with(${local.lower_path}, \"/items/\") and (${join(" or ", [for s in local.jellyfin_admin_item_subpaths : "${local.lower_path} contains \"${s}\""])} or (${local.lower_path} contains \"/images/\" and http.request.method in {\"POST\" \"DELETE\"})))",
      "(starts_with(${local.lower_path}, \"/system/configuration\") and http.request.method ne \"GET\")",
      "(starts_with(${local.lower_path}, \"/users/\") and (${local.lower_path} contains \"/policy\" or http.request.method eq \"DELETE\"))",
      "(starts_with(${local.lower_path}, \"/videos/\") and (${local.lower_path} contains \"/alternatesources\" or (${local.lower_path} contains \"/subtitles/\" and http.request.method eq \"DELETE\")))",
      "(starts_with(${local.lower_path}, \"/branding/splashscreen\") and http.request.method ne \"GET\")",
    ],
  ))
}

# Cloudflare deploys its Free Managed Ruleset on Free zones by default; owning
# the managed-phase entry point keeps that deployment under drift detection so
# it cannot be disabled in the dashboard unnoticed. Cloudflare updates the
# ruleset's rules (for example the php2shell CVE-2026-109618 rules) itself.
resource "cloudflare_ruleset" "cloudflare_managed_waf" {
  zone_id     = var.cloudflare_zone_id
  name        = "Cloudflare managed WAF"
  description = "Deploy the Cloudflare Free Managed Ruleset on every zone request."
  kind        = "zone"
  phase       = "http_request_firewall_managed"

  rules = [
    {
      ref         = "execute_cloudflare_free_managed_ruleset"
      description = "Execute the Cloudflare Free Managed Ruleset"
      expression  = "true"
      action      = "execute"
      enabled     = true
      action_parameters = {
        id = "77454fe2d30c4220b5701f6fdfb893ba"
      }
    }
  ]
}

# This entry-point ruleset adds custom controls that are safe for Home Assistant's
# browser, companion-app, WebSocket, OAuth, and Alexa traffic, for the
# Vaultwarden web vault and Bitwarden clients, and for the Jellyfin web and
# native clients. The Free plan permits five custom rules, so the Vaultwarden
# and Jellyfin geo blocks and both admin-surface blocks share one rule.
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
      # The ban list shares this rule because all five Free-plan slots are used.
      # Amazon's Alexa traffic is exempt: shared AWS addresses are reported often.
      ref         = "home_assistant_unsafe_methods"
      description = "Block HTTP methods that the tunnel services never require, and temporarily banned IPs"
      expression  = "${local.tunnel_waf_scope} and ((http.request.method in {\"CONNECT\" \"TRACE\" \"TRACK\"}) or (ip.src in ${local.ip_bans_list} and not ${local.amazon_alexa_traffic}))"
      action      = "block"
      enabled     = true
    },
    {
      ref         = "home_assistant_reconnaissance_paths"
      description = "Block common source-control, secret-file, and unrelated CMS probes"
      expression  = "${local.tunnel_waf_scope} and (${local.recon_paths})"
      action      = "block"
      enabled     = true
    },
    {
      ref         = "home_assistant_geo_allowlist"
      description = "Block Home Assistant traffic from outside allowed countries, except Amazon (Alexa) on the Alexa endpoints"
      expression  = "${local.home_assistant_waf_scope} and not (ip.src.country in {${join(" ", [for c in local.home_assistant_allowed_countries : "\"${c}\""])}}) and not ${local.amazon_alexa_traffic}"
      action      = "block"
      enabled     = true
    },
    {
      ref         = "geo_allowlist_and_admin_surfaces"
      description = "Block Vaultwarden and Jellyfin traffic from outside allowed countries and all public Vaultwarden admin-panel and Jellyfin admin-API requests"
      expression  = "(${local.geo_allowlist_scope} and not (ip.src.country in {${join(" ", [for c in local.geo_allowed_countries : "\"${c}\""])}})) or (${local.vaultwarden_waf_scope} and (lower(http.request.uri.path) eq \"/admin\" or starts_with(lower(http.request.uri.path), \"/admin/\"))) or (${local.jellyfin_waf_scope} and (${local.jellyfin_admin_paths}))"
      action      = "block"
      enabled     = true
    }
  ]
}

# Temporary bans for reconnaissance probes and recent German AbuseIPDB entries,
# written only by the ip-bans CronJobs (k8s/apps/ip-bans). Leaving `items` unset
# keeps the addresses out of state and plans: the provider then never reads
# them. Never add items here or `tofu import` this list, which reads them all.
resource "cloudflare_list" "ip_bans" {
  account_id  = var.cloudflare_account_id
  name        = "homelab_ip_bans"
  description = "Temporary bans managed by the ip-bans CronJobs; items are not tracked by OpenTofu."
  kind        = "ip"
}

# The Free plan permits one rate-limiting rule, a ten-second counting period,
# and IP-based counting. Host is not an available Free-plan rate expression
# field, so this uses Home Assistant's distinctive login-flow path,
# Vaultwarden's login path, and Jellyfin's password login path (listed in both
# casings because Jellyfin routes are case-insensitive). It does not include
# /auth/token, /api, WebSocket, or Alexa directive traffic.
resource "cloudflare_ruleset" "home_assistant_rate_limit" {
  zone_id     = var.cloudflare_zone_id
  name        = "Home Assistant authentication rate limit"
  description = "Free-plan per-IP protection for Home Assistant, Vaultwarden, and Jellyfin login requests."
  kind        = "zone"
  phase       = "http_ratelimit"

  rules = [
    {
      ref         = "rate_limit_home_assistant_login_flow"
      description = "Block an IP after more than 10 Home Assistant, Vaultwarden, or Jellyfin login requests in 10 seconds"
      expression  = "(http.request.uri.path eq \"/auth/login_flow\" or starts_with(http.request.uri.path, \"/auth/login_flow/\") or http.request.uri.path eq \"/identity/connect/token\" or http.request.uri.path in {\"/Users/AuthenticateByName\" \"/users/authenticatebyname\"})"
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

# Home Assistant, Vaultwarden, and Jellyfin are authenticated and stateful. Explicitly bypassing the edge
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
    },
    {
      ref         = "bypass_jellyfin_cache"
      description = "Bypass Cloudflare cache for every Jellyfin response"
      expression  = local.jellyfin_waf_scope
      action      = "set_cache_settings"
      enabled     = true
      action_parameters = {
        cache = false
      }
    }
  ]
}

# Start HSTS with a reversible 30-day lifetime and deliberately omit
# includeSubDomains and preload because this module owns only three zone hostnames.
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
    },
    {
      ref         = "jellyfin_security_headers"
      description = "Set HSTS and disable MIME content sniffing for Jellyfin"
      expression  = local.jellyfin_waf_scope
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
