# Module: {{ name }}
#
# This module manages {{ description }}.
#
# Usage:
#   module "{{ name }}" {
#     source = "./modules/{{ name }}"
#
#     name        = "my-resource"
#     environment = "prod"
#   }

terraform {
  required_version = ">= 1.5.0"
}

# TODO: Add resources here
