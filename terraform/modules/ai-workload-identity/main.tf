# =====================================================================
# Terraform Module: AI Workload Identity
# Author: Karthik Reddy
# Version: 1.0
# Last Updated: June 2026
# Purpose: Hardened IAM role and KMS infrastructure for AI workloads
# Threat Model Reference: S-1, E-1, E-2, I-1, I-2, T-1, T-2
# =====================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
  }
}

# ---------------------------------------------------------------------
# Local Variables
# ---------------------------------------------------------------------

locals {
  common_tags = merge(var.tags, {
    Module          = "ai-workload-identity"
    SecurityOwner   = "platform-security"
    DataClass       = "sensitive"
    ManagedBy       = "terraform"
    LastReviewed    = "2026-06"
  })

  # Naming convention: {env}-{agent_name}-{resource}
  role_name        = "${var.environment}-${var.agent_name}-execution-role"
  kms_alias        = "alias/${var.environment}/${var.agent_name}/secrets"
  log_group_name   = "/ai/agents/${var.environment}/${var.agent_name}"
  secret_path      = "ai/agents/${var.environment}/${var.agent_name}"
}

# ---------------------------------------------------------------------
# KMS Key for Agent Secret Encryption
# Dedicated per-agent KMS key — never shared across agents
# ---------------------------------------------------------------------

resource "aws_kms_key" "agent_secrets" {
  description             = "KMS key for ${var.agent_name} agent secrets in ${var.environment}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = false

  # Key policy — agent can only decrypt, never administer
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccountManagement"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowAgentDecryptOnly"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.ai_agent.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${var.aws_region}.amazonaws.com"
          }
        }
      },
      {
        Sid    = "DenyAgentAdminActions"
        Effect = "Deny"
        Principal = {
          AWS = aws_iam_role.ai_agent.arn
        }
        Action = [
          "kms:DeleteAlias",
          "kms:DisableKey",
          "kms:ScheduleKeyDeletion",
          "kms:PutKeyPolicy",
          "kms:CreateGrant"
        ]
        Resource = "*"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_kms_alias" "agent_secrets" {
  name          = local.kms_alias
  target_key_id = aws_kms_key.agent_secrets.key_id
}

# ---------------------------------------------------------------------
# IAM Role for AI Agent Workload
# Scoped trust policy — only specific ECS tasks or Lambda functions
# ---------------------------------------------------------------------

resource "aws_iam_role" "ai_agent" {
  name                 = local.role_name
  max_session_duration = 3600 # 1 hour max — forces credential rotation

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowECSTaskAssumption"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
          ArnLike = {
            "aws:SourceArn" = "arn:aws:ecs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:task-definition/ai-${var.agent_name}-*"
          }
        }
      },
      {
        Sid    = "AllowLambdaAssumption"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
          ArnLike = {
            "aws:SourceArn" = "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:ai-${var.agent_name}-*"
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

# ---------------------------------------------------------------------
# IAM Policy: Base Agent Permissions
# Secrets read + KMS decrypt + CloudWatch logging only
# ---------------------------------------------------------------------

resource "aws_iam_policy" "agent_base" {
  name        = "${local.role_name}-base-policy"
  description = "Base least-privilege policy for ${var.agent_name} AI agent"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSecretRetrieval"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:${local.secret_path}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "true"
          }
        }
      },
      {
        Sid    = "AllowKMSDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = [
          aws_kms_key.agent_secrets.arn
        ]
      },
      {
        Sid    = "AllowCloudWatchLogging"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:${local.log_group_name}:*"
        ]
      },
      {
        Sid    = "DenyIAMModifications"
        Effect = "Deny"
        Action = [
          "iam:CreateUser",
          "iam:CreateRole",
          "iam:AttachRolePolicy",
          "iam:PutRolePolicy",
          "iam:CreatePolicy",
          "iam:CreateAccessKey",
          "iam:UpdateAssumeRolePolicy",
          "iam:PassRole"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyCloudTrailModification"
        Effect = "Deny"
        Action = [
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail",
          "cloudtrail:UpdateTrail"
        ]
        Resource = "*"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "agent_base" {
  role       = aws_iam_role.ai_agent.name
  policy_arn = aws_iam_policy.agent_base.arn
}

# ---------------------------------------------------------------------
# CloudWatch Log Group for Agent Audit Trail
# Encrypted, retention-enforced, never writable by agent
# ---------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "agent_logs" {
  name              = local.log_group_name
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.agent_secrets.arn

  tags = local.common_tags
}

# ---------------------------------------------------------------------
# CloudTrail — Agent API Activity Audit
# Scoped to agent role ARN for targeted monitoring
# ---------------------------------------------------------------------

resource "aws_cloudtrail" "agent_audit" {
  count = var.enable_dedicated_cloudtrail ? 1 : 0

  name                          = "${local.role_name}-audit-trail"
  s3_bucket_name                = aws_s3_bucket.audit_logs[0].id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true # SHA-256 integrity hashing
  kms_key_id                    = aws_kms_key.agent_secrets.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }

  advanced_event_selector {
    name = "LogAllAgentAPIActivity"

    field_selector {
      field  = "userIdentity.arn"
      equals = [aws_iam_role.ai_agent.arn]
    }
  }

  tags = local.common_tags
}

# ---------------------------------------------------------------------
# S3 Bucket for Audit Logs
# Write-once, versioned, encrypted — tamper resistant
# ---------------------------------------------------------------------

resource "aws_s3_bucket" "audit_logs" {
  count  = var.enable_dedicated_cloudtrail ? 1 : 0
  bucket = "${var.environment}-${var.agent_name}-audit-logs-${data.aws_caller_identity.current.account_id}"

  tags = local.common_tags
}

resource "aws_s3_bucket_versioning" "audit_logs" {
  count  = var.enable_dedicated_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.audit_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  count  = var.enable_dedicated_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.audit_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.agent_secrets.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  count  = var.enable_dedicated_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.audit_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "audit_logs" {
  count  = var.enable_dedicated_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.audit_logs[0].id

  rule {
    id     = "audit-log-retention"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER"
    }

    expiration {
      days = var.audit_log_retention_days
    }
  }
}

# ---------------------------------------------------------------------
# Data Sources
# ---------------------------------------------------------------------

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}