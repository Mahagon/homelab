variable "aws_region" {
  description = "AWS region used by the German Alexa Smart Home integration."
  type        = string
  default     = "eu-west-1"

  validation {
    condition     = var.aws_region == "eu-west-1"
    error_message = "German Alexa Smart Home Lambda integrations must use eu-west-1."
  }
}

variable "github_repository" {
  description = "GitHub owner/repository allowed to deploy."
  type        = string
  default     = "Mahagon/homelab"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository)) && !strcontains(var.github_repository, "*")
    error_message = "github_repository must be one exact owner/repository without wildcards."
  }
}

variable "github_environment" {
  description = "Protected GitHub environment allowed to assume the deployment role."
  type        = string
  default     = "aws-production"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+$", var.github_environment)) && !strcontains(var.github_environment, "*")
    error_message = "github_environment must be one exact environment without wildcards."
  }
}

variable "state_bucket_prefix" {
  description = "Globally unique state bucket prefix; a random suffix is added."
  type        = string
  default     = "mahagon-homelab-opentofu"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,40}$", var.state_bucket_prefix))
    error_message = "state_bucket_prefix must be a lower-case S3-compatible prefix between 3 and 41 characters."
  }
}

variable "tags" {
  description = "Additional resource tags."
  type        = map(string)
  default     = {}
}

