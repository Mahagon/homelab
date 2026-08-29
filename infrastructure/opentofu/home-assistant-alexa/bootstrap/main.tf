data "aws_caller_identity" "current" {}

resource "random_id" "state_bucket" {
  byte_length = 4
}

locals {
  state_bucket_name = "${var.state_bucket_prefix}-${random_id.state_bucket.hex}"
  common_tags = merge({
    ManagedBy   = "OpenTofu"
    Project     = "home-assistant-alexa"
    Environment = "homelab"
  }, var.tags)
  github_subject = "repo:${var.github_repository}:environment:${var.github_environment}"
}

resource "aws_s3_bucket" "state" {
  #checkov:skip=CKV_AWS_18:Access logging would require another paid S3 log bucket; versioning and CloudTrail event history provide the cost-aware baseline. Review 2027-08-01.
  #checkov:skip=CKV2_AWS_62:State objects have no event-driven consumer; notifications would add unnecessary infrastructure and cost. Review 2027-08-01.
  #checkov:skip=CKV_AWS_144:Cross-region replication is intentionally excluded for a recoverable homelab state bucket. Review 2027-08-01.
  #checkov:skip=CKV_AWS_145:A customer-managed KMS key has a recurring charge; SSE-S3 is the selected cost-aware control. Review 2027-08-01.
  bucket        = local.state_bucket_name
  force_destroy = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = false
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket = aws_s3_bucket.state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_account_public_access_block" "account" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket     = aws_s3_bucket.state.id
  depends_on = [aws_s3_bucket_versioning.state]

  rule {
    id     = "state-history-retention"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "state_bucket" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.state.arn,
      "${aws_s3_bucket.state.arn}/*"
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = data.aws_iam_policy_document.state_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.state]
}

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "github_assume_role" {
  statement {
    sid     = "GitHubActionsOidc"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [local.github_subject]
    }
  }
}

resource "aws_iam_role" "github_deployment" {
  name                 = "github-homelab-opentofu"
  description          = "Deploys only the Home Assistant Alexa stack from the protected GitHub environment."
  assume_role_policy   = data.aws_iam_policy_document.github_assume_role.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "github_deployment" {
  #checkov:skip=CKV_AWS_111:The AWS Budgets API does not support a resource ARN; this statement is limited to the four budget read/write actions. Review 2027-08-01.
  #checkov:skip=CKV_AWS_356:The AWS Budgets API does not support a resource ARN; this statement is limited to the four budget read/write actions. Review 2027-08-01.
  statement {
    sid       = "StateBucketMetadata"
    effect    = "Allow"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
    resources = [aws_s3_bucket.state.arn]
  }

  statement {
    sid    = "StateObjects"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject"
    ]
    resources = ["${aws_s3_bucket.state.arn}/home-assistant-alexa/*"]
  }

  statement {
    sid    = "AlexaLambda"
    effect = "Allow"
    actions = [
      "lambda:AddPermission",
      "lambda:CreateFunction",
      "lambda:DeleteFunction",
      "lambda:GetFunction",
      "lambda:GetFunctionCodeSigningConfig",
      "lambda:GetPolicy",
      "lambda:ListVersionsByFunction",
      "lambda:RemovePermission",
      "lambda:TagResource",
      "lambda:UntagResource",
      "lambda:UpdateFunctionCode",
      "lambda:UpdateFunctionConfiguration"
    ]
    resources = ["arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:home-assistant-alexa"]
  }

  statement {
    sid    = "AlexaLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:DeleteLogGroup",
      "logs:DescribeLogGroups",
      "logs:ListTagsForResource",
      "logs:PutRetentionPolicy",
      "logs:TagResource",
      "logs:UntagResource"
    ]
    resources = [
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/home-assistant-alexa",
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/home-assistant-alexa:*"
    ]
  }

  statement {
    sid    = "AlexaExecutionRole"
    effect = "Allow"
    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListInstanceProfilesForRole",
      "iam:ListRolePolicies",
      "iam:PutRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:UpdateAssumeRolePolicy"
    ]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/home-assistant-alexa-lambda"]
  }

  statement {
    sid       = "PassAlexaExecutionRole"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/home-assistant-alexa-lambda"]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com"]
    }
  }

  statement {
    sid    = "CostBudget"
    effect = "Allow"
    actions = [
      "budgets:CreateBudget",
      "budgets:DeleteBudget",
      "budgets:DescribeBudget",
      "budgets:ModifyBudget"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "github_deployment" {
  name        = "home-assistant-alexa-deployment"
  description = "Least-privilege deployment policy for the Home Assistant Alexa stack."
  policy      = data.aws_iam_policy_document.github_deployment.json
}

resource "aws_iam_role_policy_attachment" "github_deployment" {
  role       = aws_iam_role.github_deployment.name
  policy_arn = aws_iam_policy.github_deployment.arn
}

check "github_trust_is_exact" {
  assert {
    condition     = !strcontains(local.github_subject, "*") && startswith(local.github_subject, "repo:${var.github_repository}:environment:")
    error_message = "GitHub OIDC trust must identify one exact repository and protected environment."
  }
}
