# {{ project_name }}
#
# Infrastructure configuration

terraform {
  required_version = ">= 1.5.0"

  # Uncomment and configure backend
  # backend "s3" {
  #   bucket         = "{{ project_name }}-terraform-state"
  #   key            = "terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-locks"
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = var.environment
      Project     = "{{ project_name }}"
      ManagedBy   = "terraform"
    }
  }
}

# Add resources here
