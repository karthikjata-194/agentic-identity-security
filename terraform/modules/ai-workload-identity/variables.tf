# =====================================================================
# Variables: AI Workload Identity Module
# =====================================================================

variable "agent_name" {
  description = "Name of the AI agent — used in resource naming and tagging"
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,28}[a-z0-9]$", var.agent_name))
    error_message = "agent_name must be lowercase alphanumeric with hyphens, 4-30 chars."
  }
}

variable "environment" {
  description = "Deployment environment"
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging, or prod."
  }
}

variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 90

  validation {
    condition     = contains([30, 60, 90, 180, 365, 731], var.log_retention_days)
    error_message = "log_retention_days must be 30, 60, 90, 180, 365, or 731."
  }
}

variable "audit_log_retention_days" {
  description = "S3 audit log retention in days"
  type        = number
  default     = 365
}

variable "enable_dedicated_cloudtrail" {
  description = "Create a dedicated CloudTrail for this agent. Set false if using org-level trail."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}