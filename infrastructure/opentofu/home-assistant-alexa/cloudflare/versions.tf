terraform {
  required_version = ">= 1.10.0, < 2.0.0"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.24"
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}
