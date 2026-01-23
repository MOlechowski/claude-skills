# Local values
#
# Compute derived values used throughout the module.

locals {
  name_prefix = "${var.name}-${var.environment}"

  common_tags = merge(var.tags, {
    Module      = "{{ name }}"
    Environment = var.environment
    ManagedBy   = "terraform"
  })
}
