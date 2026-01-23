# Module: {{ name }}
#
# This module manages {{ description }}.
#
# Usage:
#   module "{{ name }}" {
#     source  = "git::https://github.com/org/modules.git//{{ name }}?ref=v1.0.0"
#
#     name        = "my-resource"
#     environment = "prod"
#
#     tags = {
#       Owner = "platform-team"
#     }
#   }

# TODO: Add resources here

resource "null_resource" "placeholder" {
  # Remove this placeholder once you add real resources
}
