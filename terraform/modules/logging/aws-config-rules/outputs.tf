output "recorder_id" {
  description = "ID of the AWS Config configuration recorder"
  value       = aws_config_configuration_recorder.main.id
}

output "delivery_channel_id" {
  description = "ID of the AWS Config delivery channel"
  value       = aws_config_delivery_channel.main.id
}

output "config_role_arn" {
  description = "ARN of the IAM role assumed by AWS Config"
  value       = aws_iam_role.config.arn
}

output "config_rule_arns" {
  description = "Map of Config rule name to ARN for all CIS managed rules created by this module"
  value = {
    root_mfa_enabled                   = aws_config_config_rule.root_mfa_enabled.arn
    iam_password_policy                = aws_config_config_rule.iam_password_policy.arn
    access_keys_rotated                = aws_config_config_rule.access_keys_rotated.arn
    s3_bucket_public_read_prohibited   = aws_config_config_rule.s3_bucket_public_read_prohibited.arn
    s3_bucket_public_write_prohibited  = aws_config_config_rule.s3_bucket_public_write_prohibited.arn
    s3_bucket_server_side_encryption   = aws_config_config_rule.s3_bucket_server_side_encryption_enabled.arn
    cloudtrail_enabled                 = aws_config_config_rule.cloudtrail_enabled.arn
    cloudtrail_log_file_validation     = aws_config_config_rule.cloudtrail_log_file_validation.arn
    encrypted_volumes                  = aws_config_config_rule.encrypted_volumes.arn
    rds_storage_encrypted              = aws_config_config_rule.rds_storage_encrypted.arn
    kms_cmk_not_scheduled_for_deletion = aws_config_config_rule.kms_cmk_not_scheduled_for_deletion.arn
    restricted_ssh                     = aws_config_config_rule.restricted_ssh.arn
    restricted_rdp                     = aws_config_config_rule.restricted_rdp.arn
    vpc_flow_logs_enabled              = aws_config_config_rule.vpc_flow_logs_enabled.arn
    guardduty_enabled_centralized      = aws_config_config_rule.guardduty_enabled_centralized.arn
  }
}
