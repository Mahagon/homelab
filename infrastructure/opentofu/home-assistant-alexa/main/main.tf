locals {
  function_name = "home-assistant-alexa"
  tunnel_name   = "home-assistant-k3s"
  common_tags = merge({
    ManagedBy   = "OpenTofu"
    Project     = "home-assistant-alexa"
    Environment = "homelab"
  }, var.tags)
}

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/.terraform/home-assistant-alexa.zip"
  excludes    = ["__pycache__", "*.pyc"]
}

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name                 = "home-assistant-alexa-lambda"
  description          = "Minimal execution role for the Home Assistant Alexa Lambda bridge."
  assume_role_policy   = data.aws_iam_policy_document.lambda_assume_role.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "lambda_logs" {
  statement {
    sid    = "WriteOwnLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }
}

resource "aws_iam_role_policy" "lambda_logs" {
  name   = "write-own-cloudwatch-logs"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_logs.json
}

resource "aws_cloudwatch_log_group" "lambda" {
  #checkov:skip=CKV_AWS_158:A customer-managed KMS key has a recurring charge; CloudWatch service encryption is the selected cost-aware control. Review 2027-08-01.
  #checkov:skip=CKV_AWS_338:Fourteen-day retention limits cost for a low-volume homelab function; extend to one year if audit retention is required. Review 2027-08-01.
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 14
}

resource "aws_lambda_function" "alexa" {
  #checkov:skip=CKV_AWS_50:X-Ray adds cost and is not needed for this low-volume synchronous proxy. Review 2027-08-01.
  #checkov:skip=CKV_AWS_116:DLQs apply to asynchronous invocation; Alexa invokes this function synchronously. Review 2027-08-01.
  #checkov:skip=CKV_AWS_117:A VPC would add complexity and can impair public Home Assistant connectivity; the function has no private AWS dependencies. Review 2027-08-01.
  #checkov:skip=CKV_AWS_173:The environment contains no secret; BASE_URL and LOG_LEVEL are public configuration. Review 2027-08-01.
  #checkov:skip=CKV_AWS_272:AWS Signer has additional cost and is outside the cost-aware homelab baseline. Review 2027-08-01.
  function_name = local.function_name
  description   = "Forwards authenticated Alexa Smart Home v3 directives to Home Assistant."
  role          = aws_iam_role.lambda.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.14"
  architectures = ["arm64"]

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  memory_size                    = 256
  timeout                        = 8
  reserved_concurrent_executions = 2

  environment {
    variables = {
      BASE_URL  = var.home_assistant_url
      LOG_LEVEL = "INFO"
    }
  }

  logging_config {
    log_format            = "JSON"
    application_log_level = "INFO"
    system_log_level      = "WARN"
    log_group             = aws_cloudwatch_log_group.lambda.name
  }

  tracing_config {
    mode = "PassThrough"
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy.lambda_logs
  ]

  lifecycle {
    precondition {
      condition     = var.aws_region == "eu-west-1" && startswith(var.home_assistant_url, "https://")
      error_message = "Alexa must run in eu-west-1 and communicate with Home Assistant over HTTPS."
    }
  }
}

resource "aws_lambda_permission" "alexa" {
  count = var.alexa_skill_id == "" ? 0 : 1

  statement_id       = "AllowAlexaSmartHome"
  action             = "lambda:InvokeFunction"
  function_name      = aws_lambda_function.alexa.function_name
  principal          = "alexa-connectedhome.amazon.com"
  event_source_token = var.alexa_skill_id
}

resource "aws_budgets_budget" "monthly" {
  name         = "home-assistant-alexa-cost-guard"
  budget_type  = "COST"
  limit_amount = "1.00"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 1
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_email]
  }
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
        hostname = var.home_assistant_hostname
        service  = "http://home-assistant.home-assistant.svc.cluster.local:8123"
        origin_request = {
          connect_timeout  = 10
          tcp_keep_alive   = 30
          http_host_header = var.home_assistant_hostname
          no_tls_verify    = false
        }
      },
      {
        service = "http_status:404"
      }
    ]
  }
}

resource "cloudflare_dns_record" "home_assistant" {
  count = var.publish_dns ? 1 : 0

  zone_id = var.cloudflare_zone_id
  name    = "homeassistant"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.home_assistant.id}.cfargotunnel.com"
  type    = "CNAME"
  proxied = true
  ttl     = 1
  comment = "Home Assistant via the home-assistant-k3s Cloudflare Tunnel; managed by OpenTofu."
}

check "tunnel_origin_contract" {
  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.home_assistant.config.ingress[0].service == "http://home-assistant.home-assistant.svc.cluster.local:8123"
    error_message = "The tunnel may only target the internal Home Assistant service."
  }
}

check "dns_targets_tunnel" {
  assert {
    condition     = !var.publish_dns || cloudflare_dns_record.home_assistant[0].content == "${cloudflare_zero_trust_tunnel_cloudflared.home_assistant.id}.cfargotunnel.com"
    error_message = "The public DNS record must target the managed tunnel."
  }
}
