# yq Examples

## Kubernetes Management

### Deployment Operations
```bash
# Update image version
yq -i '.spec.template.spec.containers[0].image = "myapp:v2.0.0"' deployment.yml

# Scale deployment
yq -i '.spec.replicas = 5' deployment.yml

# Add resource limits
yq -i '.spec.template.spec.containers[0].resources = {
  "requests": {"cpu": "100m", "memory": "128Mi"},
  "limits": {"cpu": "500m", "memory": "512Mi"}
}' deployment.yml

# Update all deployment images
yq -i '(.spec.template.spec.containers[].image | select(test("myapp"))) |= sub(":.*", ":v2.0")' *.yml

# Add init container
yq -i '.spec.template.spec.initContainers += [{
  "name": "init-db",
  "image": "busybox:latest",
  "command": ["sh", "-c", "until nc -z db 5432; do sleep 1; done"]
}]' deployment.yml
```

### ConfigMap and Secret Management
```bash
# Update ConfigMap data
yq -i '.data.API_URL = "https://api.production.com"' configmap.yml
yq -i '.data.LOG_LEVEL = "info"' configmap.yml

# Add new config entry
yq -i '.data.NEW_FEATURE = "enabled"' configmap.yml

# Extract ConfigMap to env file
yq '.data | to_entries | .[] | .key + "=" + .value' configmap.yml > .env

# Create Secret from env file
while IFS='=' read -r key value; do
  yq -i ".data.\"$key\" = \"$(echo -n "$value" | base64)\"" secret.yml
done < .env

# Decode Secret values
yq '.data | to_entries | .[] | .key + "=" + (.value | @base64d)' secret.yml
```

### Service and Ingress
```bash
# Update service port
yq -i '.spec.ports[0].port = 8080' service.yml

# Add ingress rule
yq -i '.spec.rules += [{
  "host": "app.example.com",
  "http": {
    "paths": [{
      "path": "/",
      "pathType": "Prefix",
      "backend": {
        "service": {
          "name": "app",
          "port": {"number": 80}
        }
      }
    }]
  }
}]' ingress.yml

# Get all service endpoints
yq '.spec.ports[] | .port + ":" + (.targetPort | tostring)' service.yml
```

### Multi-Resource Files
```bash
# Split multi-doc YAML into separate files
yq -s '.kind + "-" + .metadata.name' all-resources.yml

# Extract specific resource kind
yq 'select(.kind == "Deployment")' all-resources.yml > deployments.yml

# Filter resources by namespace
yq 'select(.metadata.namespace == "production")' all-resources.yml

# Combine multiple resource files
yq eval-all '.' deployments/*.yml > all-deployments.yml

# Add namespace to all resources
yq -i '.metadata.namespace = "production"' resources/*.yml

# Update all images across resources
yq -i '(..|.image? | select(.)) |= sub("v1.0", "v2.0")' all-resources.yml
```

## Docker Compose Workflows

### Service Management
```bash
# Update service image
yq -i '.services.web.image = "nginx:1.21-alpine"' docker-compose.yml

# Add new service
yq -i '.services.redis = {
  "image": "redis:alpine",
  "ports": ["6379:6379"],
  "volumes": ["redis_data:/data"]
}' docker-compose.yml

# Update all service images to latest
yq -i '.services.[].image |= sub(":.*", ":latest")' docker-compose.yml

# Add environment variable to service
yq -i '.services.app.environment.NODE_ENV = "production"' docker-compose.yml

# Add volume to service
yq -i '.services.app.volumes += ["./data:/app/data"]' docker-compose.yml
```

### Environment Configurations
```bash
# Merge base + environment override
yq eval-all 'select(fileIndex == 0) * select(fileIndex == 1)' \
  docker-compose.yml docker-compose.prod.yml > docker-compose.final.yml

# Extract environment variables
yq '.services.app.environment | to_entries | .[] | .key + "=" + .value' \
  docker-compose.yml > .env

# Replace environment with file reference
yq -i 'del(.services.app.environment) | .services.app.env_file = [".env"]' \
  docker-compose.yml

# Generate env-specific compose file
for env in dev staging prod; do
  yq ".services.[].environment.ENVIRONMENT = \"$env\"" \
    docker-compose.yml > docker-compose.$env.yml
done
```

### Network and Volume Configuration
```bash
# Add network to service
yq -i '.services.app.networks = ["backend"]' docker-compose.yml

# Create network definition
yq -i '.networks.backend = {"driver": "bridge"}' docker-compose.yml

# Add volume definition
yq -i '.volumes.postgres_data = {"driver": "local"}' docker-compose.yml

# Get all exposed ports
yq '.services | to_entries | .[] | .key + ": " + (.value.ports | join(", "))' \
  docker-compose.yml
```

## CI/CD Configuration

### GitHub Actions
```bash
# Update action version
yq -i '(.jobs.build.steps[] | select(.uses | test("actions/checkout"))).uses = "actions/checkout@v4"' \
  .github/workflows/ci.yml

# Add environment variable
yq -i '.jobs.test.env.NODE_ENV = "test"' .github/workflows/ci.yml

# Add job step
yq -i '.jobs.build.steps += [{
  "name": "Run tests",
  "run": "npm test"
}]' .github/workflows/ci.yml

# Update trigger branches
yq -i '.on.push.branches = ["main", "develop"]' .github/workflows/ci.yml

# Add matrix strategy
yq -i '.jobs.test.strategy.matrix = {
  "node-version": ["16.x", "18.x", "20.x"],
  "os": ["ubuntu-latest", "windows-latest"]
}' .github/workflows/ci.yml
```

### GitLab CI
```bash
# Update stage
yq -i '.build.stage = "compile"' .gitlab-ci.yml

# Add script step
yq -i '.test.script += ["npm run lint"]' .gitlab-ci.yml

# Update variables
yq -i '.variables.NODE_VERSION = "18"' .gitlab-ci.yml

# Add new job
yq -i '.security-scan = {
  "stage": "test",
  "script": ["npm audit"],
  "allow_failure": true
}' .gitlab-ci.yml

# Extend template
yq -i '.deploy.extends = ".deployment-template"' .gitlab-ci.yml
```

### Jenkins/CircleCI
```bash
# Update CircleCI executor
yq -i '.jobs.build.docker[0].image = "cimg/node:18.0"' .circleci/config.yml

# Add CircleCI workflow job
yq -i '.workflows.build-test.jobs += ["security-scan"]' .circleci/config.yml

# Update Jenkinsfile (if YAML format)
yq -i '.pipeline.agent.docker.image = "node:18-alpine"' Jenkinsfile.yml
```

## Configuration Management

### Multi-Environment Configs
```bash
# Create environment-specific configs
for env in dev staging production; do
  yq eval-all 'select(fileIndex == 0) * select(fileIndex == 1)' \
    config.base.yml config.$env.yml > config/config.$env.yml
done

# Update config per environment
yq -i ".environment = \"production\" |
  .api_url = \"https://api.production.com\" |
  .database.host = \"prod-db.example.com\"" config.production.yml

# Extract secrets to separate file
yq '{secrets: .secrets}' config.yml > secrets.yml
yq -i 'del(.secrets)' config.yml

# Merge all environment configs
yq eval-all '. as $item ireduce ({}; . * $item)' config/*.yml > merged.yml
```

### Feature Flags
```bash
# Enable feature flag
yq -i '.features.new_ui = true' config.yml

# Disable all beta features
yq -i '.features | to_entries | map(select(.key | test("beta"))) |
  from_entries | to_entries | .[] | .value = false' config.yml

# List enabled features
yq '.features | to_entries | map(select(.value == true)) | .[].key' config.yml

# Add feature with metadata
yq -i '.features.ai_assistant = {
  "enabled": true,
  "rollout_percentage": 10,
  "allowed_users": ["beta-testers"]
}' config.yml
```

### Database Configurations
```bash
# Update database connection
yq -i '.database.host = "localhost" |
  .database.port = 5432 |
  .database.name = "myapp_prod"' config.yml

# Add connection pool settings
yq -i '.database.pool = {
  "min": 2,
  "max": 10,
  "idle": 10000
}' config.yml

# Extract database config
yq '.database' config.yml > database.yml

# Generate connection string
yq -r '
  "postgresql://" +
  .database.username + ":" +
  .database.password + "@" +
  .database.host + ":" +
  (.database.port | tostring) + "/" +
  .database.name
' config.yml
```

## Data Transformation

### Format Conversions
```bash
# YAML to JSON
yq -o json '.' config.yml > config.json

# JSON to YAML
yq -P '.' config.json > config.yml

# YAML to XML
yq -o xml '.' data.yml > data.xml

# CSV to JSON
yq -p csv -o json '.' data.csv > data.json

# Properties to YAML
yq -p props '.' application.properties > application.yml

# Generate .env from YAML
yq -o props '.environment' config.yml > .env
```

### Structure Transformations
```bash
# Flatten nested structure
yq '.users | to_entries | map({
  "user_id": .key,
  "email": .value.email,
  "name": .value.profile.name
})' users.yml

# Convert array to object
yq '[.items[] | {(.id): .}] | add' items.yml

# Pivot data
yq 'group_by(.category) | map({
  category: .[0].category,
  total: (map(.amount) | add),
  count: length
})' transactions.yml

# Normalize data
yq '.products | map({
  id,
  name: .product_name,
  price: (.price | tonumber),
  available: (.stock > 0)
})' products.yml
```

## Validation and Linting

### Schema Validation
```bash
# Check required fields
yq 'has("apiVersion") and has("kind") and has("metadata")' resource.yml

# Validate structure
yq 'select(.kind == "Deployment" and (.spec.replicas | type) == "number")' \
  deployment.yml || echo "Invalid deployment"

# Check for deprecated fields
yq '.. | select(has("selector") and has("matchLabels") | not)' deployment.yml

# Validate environment variables
yq '.services.[].environment | select(. == null or length == 0)' \
  docker-compose.yml && echo "Warning: Empty environment"
```

### Formatting and Cleanup
```bash
# Auto-format YAML
yq -i '.' *.yml

# Sort keys alphabetically
yq -i 'sort_keys(.)' config.yml

# Remove null/empty values
yq -i 'del(..|select(. == null or . == "" or . == []))' config.yml

# Normalize indentation
yq -i -I 2 '.' *.yml

# Remove comments
yq -i --no-comments '.' config.yml

# Add header comment
yq '. | headComment = "Auto-generated config file\nDo not edit manually"' \
  config.yml > config.generated.yml
```

## Advanced Workflows

### Template Generation
```bash
# Generate Kubernetes manifests from template
export APP_NAME=myapp
export VERSION=1.0.0
export REPLICAS=3

yq "
  .metadata.name = env(APP_NAME) |
  .spec.replicas = (env(REPLICAS) | tonumber) |
  .spec.template.spec.containers[0].image = env(APP_NAME) + \":\" + env(VERSION)
" deployment.template.yml > deployment.yml

# Batch generate from list
yq -r '.applications[]' apps.yml | while read app; do
  yq ".metadata.name = \"$app\" |
    .spec.selector.matchLabels.app = \"$app\"" \
    template.yml > "$app-deployment.yml"
done
```

### Monitoring and Reporting
```bash
# Generate deployment report
yq '.spec.template.spec.containers[] | {
  name,
  image,
  resources: .resources.requests
}' deployments/*.yml -o json | jq -s '.'

# List all images in use
yq '.spec.template.spec.containers[].image' deployments/*.yml | sort -u

# Check resource limits
yq 'select(.spec.template.spec.containers[].resources.limits == null) |
  .metadata.name' deployments/*.yml

# Count resources by kind
yq '.kind' manifests/*.yml | sort | uniq -c
```

### Backup and Migration
```bash
# Backup with timestamp
cp config.yml "config.$(date +%Y%m%d-%H%M%S).yml.bak"
yq -i '.version = "2.0"' config.yml

# Migrate deprecated fields
yq -i '
  .apiVersion = "apps/v1" |
  .spec.selector.matchLabels = .spec.template.metadata.labels |
  del(.spec.selector.matchExpressions)
' deployment.yml

# Bulk migration
for file in *.yml; do
  yq -i '.apiVersion = "v2"' "$file"
  echo "Migrated $file"
done
```

### Complex Merging
```bash
# Deep merge with array concatenation
yq eval-all '
  . as $item ireduce ({};
    . * $item |
    .arrays = (.arrays // []) + ($item.arrays // []) |
    unique_by(.arrays[].id)
  )
' base.yml override.yml

# Conditional merge
yq eval-all '
  select(fileIndex == 0) as $base |
  select(fileIndex == 1) as $override |
  $base |
  if ($override.environment == "production") then
    . * $override
  else
    .
  end
' base.yml env.yml

# Merge with conflict resolution
yq eval-all '
  select(fileIndex == 0) as $a |
  select(fileIndex == 1) as $b |
  $a * $b |
  .metadata.labels = ($a.metadata.labels // {}) * ($b.metadata.labels // {})
' file1.yml file2.yml
```
