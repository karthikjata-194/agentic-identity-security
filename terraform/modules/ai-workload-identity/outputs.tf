# =====================================================================
# Outputs: AI Workload Identity Module
# =====================================================================

output "agent_role_arn" {
  description = "ARN of the AI agent IAM role"
  value       = aws_iam_role.ai_agent.arn
}

output "agent_role_name" {
  description = "Name of the AI agent IAM role"
  value       = aws_iam_role.ai_agent.name
}

output "kms_key_arn" {
  description = "ARN of the KMS key for agent secret encryption"
  value       = aws_kms_key.agent_secrets.arn
}

output "kms_key_alias" {
  description = "Alias of the KMS key"
  value       = aws_kms_alias.agent_secrets.name
}

output "log_group_name" {
  description = "CloudWatch log group name for agent audit logs"
  value       = aws_cloudwatch_log_group.agent_logs.name
}

output "secret_path_prefix" {
  description = "Secrets Manager path prefix for this agent"
  value       = local.secret_path
}