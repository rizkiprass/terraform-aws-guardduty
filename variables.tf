variable "name" {
  description = "Name to be used on creating Guardduty"
  type        = string
  default     = ""
}

variable "tags" {
  description = "A mapping of tags to assign to the resource"
  type        = map(string)
  default     = {}
}

variable "enable_guardduty" {
  description = "Enabling/disabling Guardduty"
  type        = bool
  default     = "true"
}

variable "enable_s3_protection" {
  description = "Enabling/disabling S3 protection"
  type        = bool
  default     = "false"
}

variable "enable_eks_protection" {
  description = "Enabling/disabling malware protection"
  type        = bool
  default     = "false"
}

variable "enable_malware_protection" {
  description = "Enabling/disabling Guardduty"
  type        = bool
  default     = "true"
}

variable "enable_s3_logs" {
  description = "Enabling/disabling Guardduty"
  type        = bool
  default     = "false"
}

variable "create_guardduty_finding_notif" {
  description = "Determines whether an guardduty finding notification is created or no"
  type        = bool
  default     = false
}

variable "subscription" {
  description = "Enter the email for publishing notification"
  type        = string
  default     = ""
}

