variable "cloudflare_api_token" {
  description = "Cloudflare API token; supply via TF_VAR_cloudflare_api_token or CLOUDFLARE_API_TOKEN."
  type        = string
  sensitive   = true
  default     = null
}

variable "cloudflare_account_id" {
  description = "Cloudflare account ID."
  type        = string
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_account_id))
    error_message = "cloudflare_account_id must be a 32-character lowercase hexadecimal ID."
  }
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID for danieljacobs.de."
  type        = string
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_zone_id))
    error_message = "cloudflare_zone_id must be a 32-character lowercase hexadecimal ID."
  }
}

variable "hostname" {
  description = "Public Home Assistant hostname."
  type        = string
  default     = "homeassistant.danieljacobs.de"
  validation {
    condition     = var.hostname == "homeassistant.danieljacobs.de"
    error_message = "hostname is fixed to the configured Home Assistant hostname."
  }
}

variable "publish_dns" {
  description = "Create the proxied CNAME record after the tunnel is healthy."
  type        = bool
  default     = false
}
