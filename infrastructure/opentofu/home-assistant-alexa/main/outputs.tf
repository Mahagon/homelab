output "lambda_function_arn" {
  description = "Lambda ARN used as the German Alexa Smart Home endpoint."
  value       = aws_lambda_function.alexa.arn
}

output "cloudflare_tunnel_id" {
  description = "Cloudflare tunnel identifier."
  value       = cloudflare_zero_trust_tunnel_cloudflared.home_assistant.id
}

output "cloudflared_tunnel_token" {
  description = "Sensitive connector token consumed by the Kubernetes bootstrap helper."
  value       = data.cloudflare_zero_trust_tunnel_cloudflared_token.home_assistant.token
  sensitive   = true
}

output "public_hostname" {
  description = "Home Assistant hostname used for Alexa and remote access."
  value       = var.home_assistant_hostname
}

output "alexa_permission_configured" {
  description = "Whether the Lambda invocation permission is restricted to an Alexa Skill ID."
  value       = var.alexa_skill_id != ""
}

