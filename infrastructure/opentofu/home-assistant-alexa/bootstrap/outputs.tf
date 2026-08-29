output "state_bucket_name" {
  description = "S3 bucket used by the main OpenTofu root."
  value       = aws_s3_bucket.state.bucket
}

output "github_deployment_role_arn" {
  description = "Role ARN stored as the AWS_DEPLOY_ROLE_ARN GitHub variable."
  value       = aws_iam_role.github_deployment.arn
}

output "github_oidc_subject" {
  description = "Exact OIDC subject allowed to deploy."
  value       = local.github_subject
}

