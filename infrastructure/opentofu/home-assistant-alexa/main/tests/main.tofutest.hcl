mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/home-assistant-alexa-lambda"
      id  = "home-assistant-alexa-lambda"
    }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:eu-west-1:123456789012:log-group:/aws/lambda/home-assistant-alexa"
    }
  }

  mock_resource "aws_lambda_function" {
    defaults = {
      arn = "arn:aws:lambda:eu-west-1:123456789012:function:home-assistant-alexa"
    }
  }
}

mock_provider "archive" {
  mock_data "archive_file" {
    defaults = {
      output_base64sha256 = "dGVzdA=="
    }
  }
}

mock_provider "cloudflare" {
  mock_resource "cloudflare_zero_trust_tunnel_cloudflared" {
    defaults = {
      id = "11111111-2222-3333-4444-555555555555"
    }
  }

  mock_data "cloudflare_zero_trust_tunnel_cloudflared_token" {
    defaults = {
      token = "test-sensitive-tunnel-token"
    }
  }
}

variables {
  cloudflare_account_id = "0123456789abcdef0123456789abcdef"
  cloudflare_zone_id    = "fedcba9876543210fedcba9876543210"
  home_assistant_domain = "example.invalid"
  budget_email          = "alerts@example.com"
}

run "secure_stack_without_skill" {
  command = plan

  assert {
    condition     = aws_lambda_function.alexa.runtime == "python3.14" && aws_lambda_function.alexa.architectures == tolist(["arm64"])
    error_message = "Lambda must use the approved Python runtime and ARM64 architecture."
  }

  assert {
    condition     = aws_lambda_function.alexa.memory_size == 256 && aws_lambda_function.alexa.timeout == 8
    error_message = "Lambda resource and cost limits changed unexpectedly."
  }

  assert {
    condition     = aws_lambda_function.alexa.environment[0].variables == tomap({ BASE_URL = "https://homeassistant.example.invalid", LOG_LEVEL = "INFO" })
    error_message = "Lambda must contain only non-secret approved environment variables."
  }

  assert {
    condition     = aws_cloudwatch_log_group.lambda.retention_in_days == 14
    error_message = "Lambda logs must expire after 14 days."
  }

  assert {
    condition     = length(aws_lambda_permission.alexa) == 0
    error_message = "Alexa permission must not exist before a Skill ID is supplied."
  }

  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared.home_assistant.config_src == "cloudflare"
    error_message = "The tunnel must be remotely managed through OpenTofu."
  }

  assert {
    condition     = length(cloudflare_dns_record.home_assistant) == 0
    error_message = "DNS must remain unpublished during the initial connector deployment."
  }

  assert {
    condition     = cloudflare_ruleset.home_assistant_custom_waf.kind == "zone" && cloudflare_ruleset.home_assistant_custom_waf.phase == "http_request_firewall_custom"
    error_message = "Custom WAF controls must use the zone custom-firewall phase."
  }

  assert {
    condition     = length(cloudflare_ruleset.home_assistant_custom_waf.rules) == 3 && alltrue([for rule in cloudflare_ruleset.home_assistant_custom_waf.rules : rule.action == "block" && rule.enabled && strcontains(rule.expression, "homeassistant.example.invalid")])
    error_message = "All custom WAF rules must block and remain scoped to the Home Assistant hostname."
  }

  assert {
    condition     = cloudflare_ruleset.home_assistant_rate_limit.kind == "zone" && cloudflare_ruleset.home_assistant_rate_limit.phase == "http_ratelimit" && length(cloudflare_ruleset.home_assistant_rate_limit.rules) == 1
    error_message = "The Free plan permits one zone-level rate-limiting rule."
  }

  assert {
    condition     = cloudflare_ruleset.home_assistant_rate_limit.rules[0].ratelimit.period == 10 && cloudflare_ruleset.home_assistant_rate_limit.rules[0].ratelimit.requests_per_period == 10 && cloudflare_ruleset.home_assistant_rate_limit.rules[0].ratelimit.mitigation_timeout == 10
    error_message = "Authentication rate limiting must stay within the Cloudflare Free-plan limits."
  }

  assert {
    condition     = strcontains(cloudflare_ruleset.home_assistant_rate_limit.rules[0].expression, "/auth/login_flow") && !strcontains(cloudflare_ruleset.home_assistant_rate_limit.rules[0].expression, "/auth/token") && !strcontains(cloudflare_ruleset.home_assistant_rate_limit.rules[0].expression, "/api")
    error_message = "Rate limiting must protect login creation without affecting OAuth token, Home Assistant API, or Alexa traffic."
  }

  assert {
    condition     = cloudflare_ruleset.home_assistant_cache.phase == "http_request_cache_settings" && cloudflare_ruleset.home_assistant_cache.rules[0].action == "set_cache_settings" && !cloudflare_ruleset.home_assistant_cache.rules[0].action_parameters.cache
    error_message = "Every Home Assistant response must bypass the Cloudflare cache."
  }

  assert {
    condition     = cloudflare_ruleset.home_assistant_cache.rules[0].expression == "(http.host eq \"homeassistant.example.invalid\")"
    error_message = "The cache bypass must remain scoped to the Home Assistant hostname."
  }

  assert {
    condition     = cloudflare_ruleset.home_assistant_response_headers.phase == "http_response_headers_transform" && cloudflare_ruleset.home_assistant_response_headers.rules[0].action_parameters.headers["strict-transport-security"].value == "max-age=2592000"
    error_message = "Home Assistant responses must receive the conservative 30-day HSTS policy."
  }

  assert {
    condition     = cloudflare_ruleset.home_assistant_response_headers.rules[0].action_parameters.headers["x-content-type-options"].value == "nosniff" && !strcontains(cloudflare_ruleset.home_assistant_response_headers.rules[0].action_parameters.headers["strict-transport-security"].value, "includeSubDomains") && !strcontains(cloudflare_ruleset.home_assistant_response_headers.rules[0].action_parameters.headers["strict-transport-security"].value, "preload")
    error_message = "Security headers must disable MIME sniffing without imposing HSTS on unrelated subdomains."
  }

  assert {
    condition     = cloudflare_zone_setting.minimum_tls_version.value == "1.2" && cloudflare_zone_setting.tls_1_3.value == "on"
    error_message = "The Cloudflare zone must require TLS 1.2 or newer and offer TLS 1.3."
  }

  assert {
    condition     = cloudflare_zone_dnssec.zone.status == "active"
    error_message = "Cloudflare must sign the configured zone with DNSSEC."
  }
}

run "skill_and_dns_are_restricted" {
  command = plan

  variables {
    alexa_skill_id = "amzn1.ask.skill.12345678-1234-1234-1234-123456789abc"
    publish_dns    = true
  }

  assert {
    condition     = aws_lambda_permission.alexa[0].event_source_token == "amzn1.ask.skill.12345678-1234-1234-1234-123456789abc"
    error_message = "Alexa invocation permission must be restricted to the configured Skill ID."
  }

  assert {
    condition     = aws_lambda_permission.alexa[0].principal == "alexa-connectedhome.amazon.com"
    error_message = "Only the Alexa Smart Home principal may invoke the Lambda."
  }

  assert {
    condition     = cloudflare_dns_record.home_assistant[0].proxied && cloudflare_dns_record.home_assistant[0].type == "CNAME" && cloudflare_dns_record.home_assistant[0].name == "homeassistant"
    error_message = "Home Assistant DNS must be a proxied CNAME."
  }
}

run "reject_wrong_region" {
  command = plan

  variables {
    aws_region = "eu-central-1"
  }

  expect_failures = [var.aws_region]
}

run "reject_malformed_domain" {
  command = plan

  variables {
    home_assistant_domain = "https://example.invalid"
  }

  expect_failures = [var.home_assistant_domain]
}

run "reject_malformed_skill_id" {
  command = plan

  variables {
    alexa_skill_id = "not-a-skill-id"
  }

  expect_failures = [var.alexa_skill_id]
}

run "reject_malformed_cloudflare_id" {
  command = plan

  variables {
    cloudflare_account_id = "not-an-id"
  }

  expect_failures = [var.cloudflare_account_id]
}
