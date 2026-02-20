.PHONY: init plan apply destroy fmt validate docs

# Default environment
ENV ?= dev

# Terraform directory
TF_DIR = environments/$(ENV)

init:
	@echo "Initializing $(ENV) environment..."
	cd $(TF_DIR) && terraform init

plan:
	@echo "Planning $(ENV) environment..."
	cd $(TF_DIR) && terraform plan

apply:
	@echo "Applying $(ENV) environment..."
	cd $(TF_DIR) && terraform apply

destroy:
	@echo "Destroying $(ENV) environment..."
	cd $(TF_DIR) && terraform destroy

fmt:
	@echo "Formatting all Terraform files..."
	terraform fmt -recursive

validate:
	@echo "Validating all configurations..."
	@for dir in environments/*/; do \
		echo "Validating $$dir"; \
		cd $$dir && terraform init -backend=false && terraform validate && cd ../..; \
	done

docs:
	@echo "Generating documentation..."
	@for dir in modules/*/; do \
		echo "Generating docs for $$dir"; \
		terraform-docs markdown table --output-file README.md $$dir; \
	done

lint:
	@echo "Running linters..."
	tflint --recursive

security:
	@echo "Running security scan..."
	checkov -d .

cost:
	@echo "Estimating costs for $(ENV)..."
	cd $(TF_DIR) && infracost breakdown --path .
