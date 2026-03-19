variable "project_id" {
  type = string
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "log_retention_days" {
  type    = number
  default = 365
}

variable "labels" {
  type    = map(string)
  default = {}
}
