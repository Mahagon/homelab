mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
      arn        = "arn:aws:iam::123456789012:user/test"
      user_id    = "AIDATEST"
    }
  }

  mock_resource "aws_s3_bucket" {
    defaults = {
      id  = "mahagon-homelab-opentofu-a1b2c3d4"
      arn = "arn:aws:s3:::mahagon-homelab-opentofu-a1b2c3d4"
    }
  }

  mock_resource "aws_iam_openid_connect_provider" {
    defaults = {
      arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/github-homelab-opentofu"
    }
  }

  mock_resource "aws_iam_policy" {
    defaults = {
      arn = "arn:aws:iam::123456789012:policy/home-assistant-alexa-deployment"
    }
  }
}

mock_provider "random" {
  mock_resource "random_id" {
    defaults = {
      hex = "a1b2c3d4"
    }
  }
}

run "secure_bootstrap_contract" {
  command = plan

  assert {
    condition     = aws_s3_bucket_versioning.state.versioning_configuration[0].status == "Enabled"
    error_message = "State versioning must be enabled."
  }

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.state.rule).apply_server_side_encryption_by_default).sse_algorithm == "AES256"
    error_message = "State must use server-side encryption."
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.state.block_public_acls && aws_s3_bucket_public_access_block.state.block_public_policy && aws_s3_bucket_public_access_block.state.ignore_public_acls && aws_s3_bucket_public_access_block.state.restrict_public_buckets
    error_message = "Every S3 public-access control must be enabled."
  }

  assert {
    condition     = aws_iam_openid_connect_provider.github.client_id_list == toset(["sts.amazonaws.com"])
    error_message = "GitHub OIDC must only trust the AWS STS audience."
  }

  assert {
    condition     = local.github_subject == "repo:Mahagon/homelab:environment:aws-production"
    error_message = "The deployment role must trust only the protected repository environment."
  }
}

run "reject_wrong_region" {
  command = plan

  variables {
    aws_region = "eu-central-1"
  }

  expect_failures = [var.aws_region]
}

run "reject_wildcard_repository" {
  command = plan

  variables {
    github_repository = "Mahagon/*"
  }

  expect_failures = [var.github_repository]
}
