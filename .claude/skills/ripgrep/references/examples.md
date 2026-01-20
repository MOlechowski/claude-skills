# ripgrep Examples - Real-World Usage Patterns

## Code Search and Navigation

### Finding Function Definitions
```bash
# Find all function definitions in JavaScript
rg "^function \w+\(" -tjs

# Find arrow functions
rg "const \w+ = \([^)]*\) =>" -tjs

# Find React components
rg "^(export )?(default )?(function|const) [A-Z]\w+" -tts -tjsx

# Find class methods
rg "^\s+(public|private|protected)?\s*\w+\([^)]*\)" -tts
```

### Import and Dependency Analysis
```bash
# Find all imports from specific package
rg "import.*from ['\"]react" -tjs -tts

# Find all require statements
rg "require\(['\"][^'\"]+['\"]" -o -tjs

# Find dynamic imports
rg "import\(['\"]" -tjs -tts

# Find all imports in project
rg "^import " -tjs -tts | rg -o "from ['\"]([^'\"]+)" | sort -u

# Find circular dependencies (first step)
rg "^import.*from ['\"]\.\./" -tts
```

### Variable and Reference Search
```bash
# Find all usages of specific variable
rg "\buserId\b" -tjs -tts

# Find variable declarations
rg "(const|let|var) userName" -tjs

# Find property access
rg "user\.email" -tjs

# Find destructuring usage
rg "const \{.*userName.*\}" -tjs
```

## Refactoring Support

### Before Renaming
```bash
# Find all occurrences with context
rg -C 3 "\boldFunctionName\b"

# Count usages per file
rg -c "\boldFunctionName\b" | rg -v ":0$" | sort -t: -k2 -rn

# Find in specific directories only
rg "\boldFunctionName\b" src/ lib/ -l

# Exclude test files
rg "\boldFunctionName\b" -Ttest
```

### API Migration
```bash
# Find old API usage
rg "oldApi\.(get|post|put)" -tjs -tts

# Preview replacement
rg "oldApi\." --replace "newApi."

# Find callback patterns to migrate to async/await
rg "\.then\(.*\)\.catch\(" -U -tjs

# Find deprecated methods
rg "@deprecated" -A 5 -tjs -tts
```

### Code Cleanup
```bash
# Find console.log statements
rg "console\.(log|debug|warn)" -tjs -tts -g '!tests/'

# Find debugger statements
rg "^\s*debugger;" -tjs -tts

# Find commented code
rg "^\s*//\s*(const|let|var|function)" -tjs

# Find unused imports (requires additional analysis)
rg "^import.*from" -tjs -tts -o
```

## Security Auditing

### Credential Detection
```bash
# Find hardcoded passwords
rg -i "(password|passwd|pwd)\s*=\s*['\"][^'\"]{3,}" -Ttest

# Find API keys
rg "(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*['\"][^'\"]{10,}" -i

# Find tokens
rg "(token|auth[_-]?token|bearer)\s*[:=]" -i -Ttest

# Find secrets in config files
rg -i "secret|private[_-]?key" -tjson -tyaml -ttoml
```

### SQL Injection Risks
```bash
# Find string concatenation in SQL
rg "execute.*\+.*" -tpy -tjs

# Find string interpolation in SQL
rg "execute.*\$\{.*\}" -tjs

# Find raw SQL without parameterization
rg "(execute|query)\(['\"].*\$\{" -tjs -tts

# Template string SQL
rg "sql\`.*\$\{" -tjs
```

### XSS Vulnerabilities
```bash
# Find innerHTML usage
rg "\.innerHTML\s*=" -tjs -tts

# Find dangerouslySetInnerHTML
rg "dangerouslySetInnerHTML" -tjsx -tts

# Find document.write
rg "document\.write" -tjs

# Find eval usage
rg "\beval\(" -tjs
```

### Unsafe Deserialization
```bash
# Find pickle usage in Python
rg "pickle\.(loads|load)" -tpy

# Find JSON.parse without try-catch
rg "JSON\.parse\([^)]+\)" -tjs | rg -v "try"

# Find eval in JSON
rg "eval.*JSON" -tjs
```

## Performance Analysis

### Performance Issues
```bash
# Find synchronous file operations
rg "fs\.(readFileSync|writeFileSync)" -tjs

# Find nested loops
rg "for.*{[\s\S]{0,100}for.*{" -U -tjs

# Find blocking operations
rg "(sleep|setTimeout)\(0\)" -tjs

# Find large array operations
rg "\.map\(.*\)\.filter\(.*\)\.map\(" -tjs
```

### Memory Leaks
```bash
# Find event listeners without cleanup
rg "addEventListener" -A 10 -tjs | rg -v "removeEventListener"

# Find setInterval without clear
rg "setInterval" -A 5 -tjs | rg -v "clearInterval"

# Find global variable assignment
rg "window\.\w+\s*=" -tjs

# Find circular references
rg "this\.\w+\s*=.*this" -tjs
```

## Testing and Quality

### Test Coverage
```bash
# Find untested files (no corresponding test)
rg --files -tjs src/ | while read f; do
  test_file="${f/src/tests}"
  test_file="${test_file/.js/.test.js}"
  [[ ! -f "$test_file" ]] && echo "$f has no test"
done

# Find test files
rg --files -g '*test.{js,ts}' -g '*spec.{js,ts}'

# Find skipped tests
rg "(it|test)\.skip\(" -tjs -tts

# Find focused tests
rg "(it|test)\.only\(" -tjs -tts
```

### Code Quality Issues
```bash
# Find magic numbers
rg "\b[0-9]{4,}\b" -tjs -g '!package-lock.json'

# Find long functions (rough heuristic)
rg "^function \w+.*\{" -A 100 -tjs | rg -c "^}$" | rg -v ":1$"

# Find deeply nested code
rg "^\s{20,}" -tjs

# Find TODO/FIXME comments
rg "(TODO|FIXME|HACK|XXX|BUG):" -i

# Find error suppression
rg "(//|/\*)\s*eslint-disable" -tjs -tts
```

## Documentation

### API Documentation
```bash
# Find undocumented exports
rg "^export (function|const|class)" -tts -A 1 | rg -v "^--$|/\*\*"

# Find JSDoc comments
rg "/\*\*" -A 10 -tjs

# Find missing return documentation
rg "@param" -A 5 -tjs | rg -v "@return"

# Find broken doc links
rg "\[.*\]\(\.\/[^\)]+\)" docs/
```

### Comments and Readability
```bash
# Find commented-out code
rg "^\s*//\s*(const|let|var|function|class)" -tjs

# Find long comments (possibly outdated docs)
rg "^\s*//.*" -tjs | awk 'length > 100'

# Find non-English comments (basic check)
rg "//.*[^\x00-\x7F]" -tjs
```

## Configuration and Environment

### Environment Variables
```bash
# Find all env var usage
rg "process\.env\.\w+" -o -tjs | sort -u

# Find missing env var checks
rg "process\.env\.\w+" -tjs | rg -v "if.*process\.env"

# Find .env file references
rg "(dotenv|\.env)" -tjs

# Find hardcoded env values
rg "process\.env\.\w+\s*\|\|" -tjs
```

### Configuration Files
```bash
# Find all config files
rg --files -g '*config.{js,json,yaml,yml,toml}'

# Find database connections
rg "(connection|conn).*string" -tjson -tyaml

# Find API endpoints
rg "(base_url|baseUrl|api_url).*http" -i -tjson -tyaml

# Find port configurations
rg "(port|PORT).*[0-9]{4,5}" -tjson -tyaml
```

## Git and Version Control

### Conflict Analysis
```bash
# Find merge conflict markers
rg "^(<<<<<<<|=======|>>>>>>>)" --no-ignore

# Find files with conflicts
rg "^(<<<<<<<|=======|>>>>>>>)" -l --no-ignore

# Show conflict context
rg "^(<<<<<<<|=======|>>>>>>>)" -C 5 --no-ignore
```

### Commit Analysis
```bash
# Find files changed frequently (use with git log)
git log --name-only --pretty=format: | sort | uniq -c | sort -rn | head -20

# Find large commits
git log --all --pretty=format:'%H' | \
  while read commit; do
    echo "$commit $(git diff-tree --no-commit-id --numstat -r $commit | \
      awk '{s+=$1+$2} END {print s}')"
  done | sort -k2 -rn | head -10

# Search in git history
git log -p | rg "sensitive_function"
```

## Project Statistics

### Code Metrics
```bash
# Count lines of code by file type
rg --files -tjs | xargs wc -l | sort -rn | head -20

# Count functions
rg "^function \w+\(" -tjs -c | awk -F: '{sum+=$2} END {print sum}'

# Count classes
rg "^(export )?(default )?class \w+" -tjs -c | awk -F: '{sum+=$2} END {print sum}'

# Count imports
rg "^import " -tjs -c | awk -F: '{sum+=$2} END {print sum}'
```

### Complexity Indicators
```bash
# Find files with many imports
rg -c "^import " -tjs | sort -t: -k2 -rn | head -10

# Find files with many functions
rg -c "^function " -tjs | sort -t: -k2 -rn | head -10

# Find complex conditionals
rg "if.*&&.*\|\|" -tjs -c | sort -t: -k2 -rn

# Find deeply nested ternaries
rg "\?.*\?.*\?" -tjs
```

## Dependency Management

### Package Analysis
```bash
# Find package imports
rg "from ['\"]([^.][^'\"]+)" -o -tjs -tts | sort -u

# Find version-specific imports
rg "@types/.*\":\s*\"" package.json

# Find peer dependencies
rg "peerDependencies" -A 20 package.json

# Find deprecated packages
rg "deprecated" package-lock.json
```

### License Compliance
```bash
# Find license information
rg "(license|License|LICENSE)" README.md package.json

# Find copyright notices
rg "Copyright.*[0-9]{4}" --no-heading

# Find SPDX identifiers
rg "SPDX-License-Identifier:" --no-heading
```

## Log Analysis

### Error Patterns
```bash
# Find error logs
rg "\"level\":\s*\"error\"" -g '*.log'

# Group errors by message
rg "\"message\":\"([^\"]+)\"" -o -g '*.log' | sort | uniq -c | sort -rn

# Find stack traces
rg "^\s+at\s+" -g '*.log' -A 5

# Time-based filtering (with grep)
rg "2025-01-" -g '*.log' | rg "ERROR"
```

### Performance Logs
```bash
# Find slow requests
rg "duration.*[0-9]{4,}" -g '*.log'

# Find response times
rg "response_time.*ms" -o -g '*.log' | rg -o "[0-9]+" | sort -rn | head -20

# Find memory usage
rg "memory.*MB" -g '*.log'

# HTTP status codes
rg "status\":\s*[45][0-9]{2}" -g '*.log' -c
```

## Docker and Kubernetes

### Dockerfile Analysis
```bash
# Find FROM statements
rg "^FROM " Dockerfile*

# Find exposed ports
rg "^EXPOSE " Dockerfile*

# Find environment variables
rg "^ENV " Dockerfile*

# Find COPY/ADD statements
rg "^(COPY|ADD) " Dockerfile*

# Find multi-stage builds
rg "^FROM .* AS " Dockerfile*
```

### Kubernetes Manifests
```bash
# Find all images
rg "image:" -g '*.yaml' -g '*.yml' k8s/

# Find resource limits
rg "limits:" -A 3 -g '*.yaml' k8s/

# Find secrets
rg "kind: Secret" -A 10 -g '*.yaml' k8s/

# Find configmaps
rg "kind: ConfigMap" -A 10 -g '*.yaml' k8s/

# Find service definitions
rg "kind: Service" -A 20 -g '*.yaml' k8s/
```

## Advanced Workflows

### Multi-Step Analysis
```bash
# Find API endpoints and their handlers
rg "router\.(get|post|put|delete)\(" -A 1 -tjs | \
  rg -o "\"([^\"]+)\"" | sort -u

# Find and count error types
rg "throw new (\w+Error)" -o -tjs | sort | uniq -c | sort -rn

# Extract and validate URLs
rg "https?://[^\s\"']+" -o | sort -u | \
  while read url; do curl -I "$url" 2>&1 | head -1; done
```

### Code Generation Support
```bash
# Extract type definitions
rg "^(export )?(type|interface) \w+" -tts -A 5

# Find all components with props
rg "^(export )?(function|const) \w+.*\{.*props" -tjsx -tts

# Extract API routes
rg "app\.(get|post|put|delete)\(['\"]([^'\"]+)" -o -tjs
```

### Batch Operations
```bash
# Find and replace across files
rg -l "oldPattern" | xargs sed -i '' 's/oldPattern/newPattern/g'

# Find files and run command
rg -l "TODO" | xargs -I {} sh -c 'echo "Processing: {}"'

# Count total matches across project
rg "pattern" -c | awk -F: '{sum+=$2} END {print sum}'
```
