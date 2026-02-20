# jq Examples

## API Processing

### Extract User Data
```bash
curl -s 'https://api.github.com/users/octocat/repos' | jq '.[].name'

# Get repo names and star counts
curl -s 'https://api.github.com/users/octocat/repos' | \
  jq '.[] | {name, stars: .stargazers_count}'

# Filter active repos only
curl -s 'https://api.github.com/users/octocat/repos' | \
  jq '[.[] | select(.archived == false) | {name, url: .html_url}]'
```

### Transform Response Structure
```bash
# Convert GitHub API format to simplified structure
curl -s 'https://api.github.com/repos/jq/cli-jq' | \
  jq '{
    project: .name,
    description: .description,
    stats: {
      stars: .stargazers_count,
      forks: .forks_count,
      issues: .open_issues_count
    },
    urls: {
      homepage: .homepage,
      clone: .clone_url
    }
  }'
```

### Pagination and Aggregation
```bash
# Combine multiple API pages
for page in {1..3}; do
  curl -s "https://api.github.com/users/octocat/repos?page=$page"
done | jq -s 'add | unique_by(.id)'

# Get total star count across all repos
curl -s 'https://api.github.com/users/octocat/repos' | \
  jq '[.[].stargazers_count] | add'
```

## Log Analysis

### Parse JSON Logs
```bash
# Extract error messages
cat app.log | jq 'select(.level == "error") | .message'

# Group errors by type
cat app.log | jq -s '
  group_by(.error_code) |
  map({
    code: .[0].error_code,
    count: length,
    examples: [.[0].message, .[1].message] | map(select(. != null))
  })
'

# Filter by time range
cat app.log | jq '
  select(.timestamp >= "2025-01-01" and .timestamp < "2025-02-01")
'
```

### Performance Metrics
```bash
# Calculate average response time
cat access.log | jq -s '
  map(.response_time) |
  add / length
'

# Find slowest endpoints
cat access.log | jq -s '
  group_by(.endpoint) |
  map({
    endpoint: .[0].endpoint,
    avg_time: (map(.response_time) | add / length),
    max_time: (map(.response_time) | max),
    count: length
  }) |
  sort_by(.avg_time) |
  reverse |
  .[0:10]
'

# Percentile calculation (95th)
cat access.log | jq -s '
  map(.response_time) |
  sort |
  .[((length * 0.95) | floor)]
'
```

### Error Rate Tracking
```bash
# Calculate error rate by hour
cat app.log | jq -s '
  group_by(.timestamp[0:13]) |
  map({
    hour: .[0].timestamp[0:13],
    total: length,
    errors: map(select(.level == "error")) | length,
    error_rate: ((map(select(.level == "error")) | length) / length * 100)
  })
'
```

## Configuration

### Update Config Files
```bash
# Change database host
jq '.database.host = "localhost"' config.json > config.tmp.json
mv config.tmp.json config.json

# Add new feature flag
jq '.features.new_ui = true' config.json > config.tmp.json
mv config.tmp.json config.json

# Update nested configuration
jq '.services.api.endpoints.users = "https://api.example.com/v2/users"' \
  config.json > config.tmp.json
mv config.tmp.json config.json
```

### Merge Configs
```bash
# Merge environment-specific config
jq -s '.[0] * .[1]' base-config.json prod-config.json > final-config.json

# Deep merge with override
jq -s 'reduce .[] as $item ({}; . * $item)' \
  base.json env.json overrides.json > config.json

# Merge arrays
jq -s '.[0] + .[1] | unique' plugins1.json plugins2.json
```

### Extract Config Subsets
```bash
# Extract database config only
jq '.database' config.json > db-config.json

# Get all API endpoints
jq '.services | to_entries | map({name: .key, url: .value.url})' \
  config.json
```

## Data Transformation

### CSV to JSON
```bash
# Parse CSV (with external tool)
echo "name,age,city
Alice,30,NYC
Bob,25,LA" | \
  csvtojson | jq '.[] | {name, age: (.age | tonumber), city}'
```

### Flatten Structures
```bash
# Flatten deeply nested object
echo '{
  "user": {
    "profile": {
      "contact": {
        "email": "alice@example.com"
      }
    }
  }
}' | jq '.user.profile.contact'

# Flatten array of arrays
echo '[[1,2],[3,4],[5,6]]' | jq 'flatten'

# Flatten to key-value pairs
echo '{
  "a": {"b": 1, "c": 2},
  "d": {"e": 3}
}' | jq 'to_entries | map({key: .key, values: .value | to_entries})'
```

### Convert Between Formats
```bash
# Array to object
echo '[
  {"key": "name", "value": "Alice"},
  {"key": "age", "value": 30}
]' | jq 'map({(.key): .value}) | add'

# Object to array
echo '{
  "name": "Alice",
  "age": 30
}' | jq 'to_entries | map({field: .key, value: .value})'

# Pivot data
echo '[
  {"date": "2025-01-01", "metric": "sales", "value": 100},
  {"date": "2025-01-01", "metric": "users", "value": 50}
]' | jq 'group_by(.date) | map({
  date: .[0].date,
  metrics: map({key: .metric, value: .value}) | from_entries
})'
```

## Package.json Operations

### Dependencies
```bash
# List all dependencies
jq '.dependencies + .devDependencies' package.json

# Find outdated packages (with npm)
npm outdated --json | jq 'to_entries | map({
  name: .key,
  current: .value.current,
  wanted: .value.wanted,
  latest: .value.latest
})'

# Extract version numbers only
jq '.dependencies | to_entries | map({
  name: .key,
  version: .value
})' package.json
```

### Scripts
```bash
# List all scripts
jq '.scripts' package.json

# Add new script
jq '.scripts["build:prod"] = "NODE_ENV=production npm run build"' \
  package.json > package.tmp.json
mv package.tmp.json package.json

# Remove script
jq 'del(.scripts.unused)' package.json > package.tmp.json
mv package.tmp.json package.json
```

## Docker and Kubernetes

### Docker Inspect
```bash
# Get container IP addresses
docker inspect $(docker ps -q) | \
  jq '.[] | {name: .Name, ip: .NetworkSettings.IPAddress}'

# Extract environment variables
docker inspect container_name | \
  jq '.[0].Config.Env | map(split("=") | {key: .[0], value: .[1]}) | from_entries'

# Get volume mounts
docker inspect container_name | \
  jq '.[0].Mounts | map({source: .Source, destination: .Destination, mode: .Mode})'
```

### Kubernetes Resources
```bash
# Get pod names and statuses
kubectl get pods -o json | \
  jq '.items[] | {name: .metadata.name, status: .status.phase}'

# Find pods with errors
kubectl get pods -o json | \
  jq '.items[] | select(.status.phase != "Running") | {
    name: .metadata.name,
    status: .status.phase,
    reason: .status.conditions[0].reason
  }'

# Extract resource limits
kubectl get pods -o json | \
  jq '.items[] | {
    name: .metadata.name,
    limits: .spec.containers[].resources.limits
  }'
```

## Testing and Validation

### Validate Structure
```bash
# Check if field exists
echo '{"name": "Alice"}' | \
  jq 'if has("email") then . else . + {email: null} end'

# Validate required fields
echo '{"name": "Alice"}' | \
  jq 'if (.name and .email) then "valid" else "missing fields" end'

# Type checking
echo '{"age": "30"}' | \
  jq 'if (.age | type) == "number" then . else error("age must be number") end'
```

### Generate Test Data
```bash
# Generate mock users
jq -n '[range(5) | {
  id: .,
  name: "User\(.)",
  email: "user\(.)@example.com",
  created: now | todate
}]'

# Create test fixtures
jq -n '{
  users: [
    {id: 1, name: "Alice", role: "admin"},
    {id: 2, name: "Bob", role: "user"}
  ],
  settings: {
    theme: "dark",
    notifications: true
  }
}'
```

## Git

### Parse Git Log
```bash
# Custom git log format
git log --pretty=format:'{"commit":"%H","author":"%an","date":"%ad","message":"%s"}' | \
  jq -s '.'

# Find commits by author
git log --pretty=format:'{"author":"%an","message":"%s"}' | \
  jq -s 'group_by(.author) | map({author: .[0].author, commits: length})'
```

### GitHub CLI
```bash
# List open PRs
gh pr list --json number,title,author | \
  jq '.[] | {pr: .number, title, author: .author.login}'

# Get PR review status
gh pr view 123 --json reviews | \
  jq '.reviews | group_by(.state) | map({state: .[0].state, count: length})'
```

## AWS CLI

### EC2 Instances
```bash
# List instances with specific tag
aws ec2 describe-instances | \
  jq '.Reservations[].Instances[] |
    select(.Tags[]? | .Key == "Environment" and .Value == "production") |
    {id: .InstanceId, type: .InstanceType, state: .State.Name}'

# Get security group rules
aws ec2 describe-security-groups | \
  jq '.SecurityGroups[] | {
    id: .GroupId,
    name: .GroupName,
    inbound: .IpPermissions | length,
    outbound: .IpPermissionsEgress | length
  }'
```

### S3 Buckets
```bash
# List bucket sizes
aws s3api list-buckets | \
  jq -r '.Buckets[].Name' | \
  while read bucket; do
    size=$(aws s3 ls s3://$bucket --recursive | \
           awk '{sum+=$3} END {print sum}')
    echo "{\"bucket\": \"$bucket\", \"size\": $size}"
  done | jq -s '.'
```

## Workflows

### ETL Pipeline
```bash
# Extract, transform, load
curl -s 'https://api.example.com/data' | \
  jq '.results[] |
    select(.active == true) |
    {
      id,
      name: .full_name,
      email: .contact.email,
      score: (.metrics.total / .metrics.count)
    }' | \
  while read -r line; do
    echo "$line" | curl -X POST https://api.destination.com/import \
      -H "Content-Type: application/json" \
      -d @-
  done
```

### Reports
```bash
# Generate HTML report from JSON
cat data.json | jq -r '
  "<html><body><table>",
  (.[] | "<tr><td>\(.name)</td><td>\(.value)</td></tr>"),
  "</table></body></html>"
' > report.html

# Create CSV from JSON
jq -r '["name","age","city"],
       (.[] | [.name, .age, .city]) |
       @csv' users.json > users.csv
```

### Batch Processing
```bash
# Process multiple files
for file in data/*.json; do
  jq '.items[] | select(.status == "pending")' "$file"
done | jq -s 'group_by(.category) | map({
  category: .[0].category,
  count: length,
  items: map(.id)
})'
```

## Advanced Patterns

### Recursion
```bash
# Find all values matching key anywhere in structure
echo '{
  "a": {"name": "Alice", "nested": {"name": "Bob"}},
  "b": {"name": "Charlie"}
}' | jq '.. | .name? | select(. != null)'

# Recursive key replacement
echo '{
  "old_key": 1,
  "nested": {"old_key": 2}
}' | jq 'walk(if type == "object" then
  with_entries(if .key == "old_key" then .key = "new_key" else . end)
  else . end)'
```

### Aggregations
```bash
# Calculate weighted average
echo '[
  {"item": "A", "value": 10, "weight": 2},
  {"item": "B", "value": 20, "weight": 3}
]' | jq '
  (map(.value * .weight) | add) / (map(.weight) | add)
'

# Group and aggregate
echo '[
  {"category": "A", "amount": 10},
  {"category": "B", "amount": 20},
  {"category": "A", "amount": 15}
]' | jq 'group_by(.category) | map({
  category: .[0].category,
  total: map(.amount) | add,
  avg: (map(.amount) | add / length),
  count: length
})'
```

### Conditionals
```bash
# Apply different transforms based on condition
echo '[
  {"type": "user", "name": "Alice"},
  {"type": "admin", "name": "Bob"}
]' | jq 'map(
  if .type == "admin" then
    . + {permissions: ["read", "write", "admin"]}
  else
    . + {permissions: ["read"]}
  end
)'

# Complex conditional logic
jq '
  if .status == "active" and .score > 80 then
    .tier = "premium"
  elif .status == "active" and .score > 50 then
    .tier = "standard"
  else
    .tier = "basic"
  end
'
```

## Performance

### Stream Large Files
```bash
jq -c '.[]' huge-array.json | while IFS= read -r obj; do
  echo "$obj" | jq 'select(.important == true)'
done

jq 'limit(100; .items[])' large-file.json               # First N items
```

### Filtering
```bash
jq 'first(.items[] | select(.id == 123))' data.json  # Early exit
jq -c '.items[]' data.json | process-items.sh         # Compact for pipelines
```
