variable "name_prefix" {
  description = "Prefix applied to all Config rule names and the IAM role"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "config_s3_bucket_name" {
  description = "Name of the S3 bucket that receives Config snapshots and history"
  type        = string

  validation {
    condition     = length(var.config_s3_bucket_name) > 0
    error_message = "config_s3_bucket_name must not be empty."
  }
}

variable "config_s3_key_prefix" {
  description = "Optional S3 key prefix for Config delivery objects"
  type        = string
  default     = null
}

variable "config_sns_topic_arn" {
  description = "Optional SNS topic ARN that receives Config change notifications"
  type        = string
  default     = null
}

variable "delivery_frequency" {
  description = "How often Config delivers configuration snapshots: One_Hour, Three_Hours, Six_Hours, Twelve_Hours, TwentyFour_Hours"
  type        = string
  default     = "TwentyFour_Hours"

  validation {
    condition     = contains(["One_Hour", "Three_Hours", "Six_Hours", "Twelve_Hours", "TwentyFour_Hours"], var.delivery_frequency)
    error_message = "delivery_frequency must be one of: One_Hour, Three_Hours, Six_Hours, Twelve_Hours, TwentyFour_Hours."
  }
}

variable "tags" {
  description = "Map of tags applied to all resources in this module"
  type        = map(string)
  default     = {}
}
