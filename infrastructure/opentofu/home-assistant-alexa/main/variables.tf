variable "aws_region" {
  description = "German Alexa Smart Home Lambda region."
  type        = string
  default     = "eu-west-1"

  validation {
    condition     = var.aws_region == "eu-west-1"
    error_message = "German Alexa Smart Home Lambda integrations must use eu-west-1."
  }
}

variable "home_assistant_hostname" {
  description = "Public Home Assistant hostname used for both Alexa and remote access."
  type        = string
  default     = "homeassistant.example.invalid"

  validation {
    condition     = var.home_assistant_hostname == "homeassistant.example.invalid"
    error_message = "This stack is intentionally restricted to homeassistant.example.invalid."
  }
}

variable "home_assistant_url" {
  description = "HTTPS Home Assistant base URL without a trailing slash."
  type        = string
  default     = "https://homeassistant.example.invalid"

  validation {
    condition     = var.home_assistant_url == "https://${var.home_assistant_hostname}" && !endswith(var.home_assistant_url, "/")
    error_message = "home_assistant_url must be the exact HTTPS hostname without a trailing slash."
  }
}

variable "cloudflare_account_id" {
  description = "Cloudflare account identifier."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_account_id))
    error_message = "cloudflare_account_id must be a 32-character lowercase hexadecimal ID."
  }
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone identifier for example.invalid."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_zone_id))
    error_message = "cloudflare_zone_id must be a 32-character lowercase hexadecimal ID."
  }
}

variable "alexa_skill_id" {
  description = "Alexa Skill ID. Leave empty during the first deployment."
  type        = string
  default     = ""

  validation {
    condition     = var.alexa_skill_id == "" || can(regex("^amzn1\\.ask\\.skill\\.[0-9a-fA-F-]{36}$", var.alexa_skill_id))
    error_message = "alexa_skill_id must be empty or use the amzn1.ask.skill.<UUID> form."
  }
}

variable "budget_email" {
  description = "Email address receiving AWS cost-budget notifications."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.budget_email))
    error_message = "budget_email must be a valid email address."
  }
}

variable "publish_dns" {
  description = "Create the public tunnel CNAME after both connectors are healthy."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Additional AWS resource tags."
  type        = map(string)
  default     = {}
}

