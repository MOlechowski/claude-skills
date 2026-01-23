# Input variables

variable "name" {
  type        = string
  description = "Name prefix for all resources"
}

variable "environment" {
  type        = string
  description = "Environment name (e.g., dev, staging, prod)"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "tags" {
  type        = map(string)
  description = "Additional tags to apply to all resources"
  default     = {}
}
