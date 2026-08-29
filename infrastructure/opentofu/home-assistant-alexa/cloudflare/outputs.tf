output "tunnel_id" {
  description = "Cloudflare tunnel ID."
  value       = cloudflare_zero_trust_tunnel_cloudflared.home_assistant.id
}

output "cloudflared_tunnel_token" {
  description = "Token for the Kubernetes Secret; handle as sensitive data."
  value       = data.cloudflare_zero_trust_tunnel_cloudflared_token.home_assistant.token
  sensitive   = true
}

output "hostname" {
  value = var.hostname
}
