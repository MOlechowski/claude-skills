# ripgrep Examples

## Code Search and Navigation

### Finding Function Definitions
```bash
rg "^function \w+\(" -tjs
rg "const \w+ = \([^)]*\) =>" -tjs
rg "^(export )?(default )?(function|const) [A-Z]\w+" -tts -tjsx
rg "^\s+(public|private|protected)?\s*\w+\([^)]*\)" -tts
```

### Import and Dependency Analysis
```bash
rg "import.*from ['\"]react" -tjs -tts
rg "require\(['\"][^'\"]+['\"]" -o -tjs
rg "import\(['\"]" -tjs -tts
rg "^import " -tjs -tts | rg -o "from ['\"]([^'\"]+)" | sort -u
rg "^import.*from ['\"]\.\./" -tts   # Circular deps check
```

### Variable and Reference Search
```bash
rg "\buserId\b" -tjs -tts
rg "(const|let|var) userName" -tjs
rg "user\.email" -tjs
rg "const \{.*userName.*\}" -tjs
```

## Refactoring Support

### Before Renaming
```bash
rg -C 3 "\boldFunctionName\b"
rg -c "\boldFunctionName\b" | rg -v ":0$" | sort -t: -k2 -rn
rg "\boldFunctionName\b" src/ lib/ -l
rg "\boldFunctionName\b" -Ttest
```

### API Migration
```bash
rg "oldApi\.(get|post|put)" -tjs -tts
rg "oldApi\." --replace "newApi."
rg "\.then\(.*\)\.catch\(" -U -tjs
rg "@deprecated" -A 5 -tjs -tts
```

### Code Cleanup
```bash
rg "console\.(log|debug|warn)" -tjs -tts -g '!tests/'
rg "^\s*debugger;" -tjs -tts
rg "^\s*//\s*(const|let|var|function)" -tjs
rg "^import.*from" -tjs -tts -o
```

## Security Auditing

### Credential Detection
```bash
rg -i "(password|passwd|pwd)\s*=\s*['\"][^'\"]{3,}" -Ttest
rg "(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*['\"][^'\"]{10,}" -i
rg "(token|auth[_-]?token|bearer)\s*[:=]" -i -Ttest
rg -i "secret|private[_-]?key" -tjson -tyaml -ttoml
```

### SQL Injection Risks
```bash
rg "execute.*\+.*" -tpy -tjs
rg "execute.*\$\{.*\}" -tjs
rg "(execute|query)\(['\"].*\$\{" -tjs -tts
rg "sql\`.*\$\{" -tjs
```

### XSS Vulnerabilities
```bash
rg "\.innerHTML\s*=" -tjs -tts
rg "dangerouslySetInnerHTML" -tjsx -tts
rg "document\.write" -tjs
rg "\beval\(" -tjs
```

### Unsafe Deserialization
```bash
rg "pickle\.(loads|load)" -tpy
rg "JSON\.parse\([^)]+\)" -tjs | rg -v "try"
rg "eval.*JSON" -tjs
```

## Performance Analysis

### Performance Issues
```bash
rg "fs\.(readFileSync|writeFileSync)" -tjs
rg "for.*{[\s\S]{0,100}for.*{" -U -tjs
rg "(sleep|setTimeout)\(0\)" -tjs
rg "\.map\(.*\)\.filter\(.*\)\.map\(" -tjs
```

### Memory Leaks
```bash
rg "addEventListener" -A 10 -tjs | rg -v "removeEventListener"
rg "setInterval" -A 5 -tjs | rg -v "clearInterval"
rg "window\.\w+\s*=" -tjs
rg "this\.\w+\s*=.*this" -tjs
```

## Testing and Quality

### Test Coverage
```bash
rg --files -tjs src/ | while read f; do
  test_file="${f/src/tests}"
  test_file="${test_file/.js/.test.js}"
  [[ ! -f "$test_file" ]] && echo "$f has no test"
done
rg --files -g '*test.{js,ts}' -g '*spec.{js,ts}'
rg "(it|test)\.skip\(" -tjs -tts
rg "(it|test)\.only\(" -tjs -tts
```

### Code Quality Issues
```bash
rg "\b[0-9]{4,}\b" -tjs -g '!package-lock.json'
rg "^function \w+.*\{" -A 100 -tjs | rg -c "^}$" | rg -v ":1$"
rg "^\s{20,}" -tjs
rg "(TODO|FIXME|HACK|XXX|BUG):" -i
rg "(//|/\*)\s*eslint-disable" -tjs -tts
```

## Documentation

### API Documentation
```bash
rg "^export (function|const|class)" -tts -A 1 | rg -v "^--$|/\*\*"
rg "/\*\*" -A 10 -tjs
rg "@param" -A 5 -tjs | rg -v "@return"
rg "\[.*\]\(\.\/[^\)]+\)" docs/
```

### Comments and Readability
```bash
rg "^\s*//\s*(const|let|var|function|class)" -tjs
rg "^\s*//.*" -tjs | awk 'length > 100'
rg "//.*[^\x00-\x7F]" -tjs
```

## Configuration and Environment

### Environment Variables
```bash
rg "process\.env\.\w+" -o -tjs | sort -u
rg "process\.env\.\w+" -tjs | rg -v "if.*process\.env"
rg "(dotenv|\.env)" -tjs
rg "process\.env\.\w+\s*\|\|" -tjs
```

### Configuration Files
```bash
rg --files -g '*config.{js,json,yaml,yml,toml}'
rg "(connection|conn).*string" -tjson -tyaml
rg "(base_url|baseUrl|api_url).*http" -i -tjson -tyaml
rg "(port|PORT).*[0-9]{4,5}" -tjson -tyaml
```

## Git and Version Control

### Conflict Analysis
```bash
rg "^(<<<<<<<|=======|>>>>>>>)" --no-ignore
rg "^(<<<<<<<|=======|>>>>>>>)" -l --no-ignore
rg "^(<<<<<<<|=======|>>>>>>>)" -C 5 --no-ignore
```

### Commit Analysis
```bash
git log --name-only --pretty=format: | sort | uniq -c | sort -rn | head -20
git log --all --pretty=format:'%H' | \
  while read commit; do
    echo "$commit $(git diff-tree --no-commit-id --numstat -r $commit | \
      awk '{s+=$1+$2} END {print s}')"
  done | sort -k2 -rn | head -10
git log -p | rg "sensitive_function"
```

## Project Statistics

### Code Metrics
```bash
rg --files -tjs | xargs wc -l | sort -rn | head -20
rg "^function \w+\(" -tjs -c | awk -F: '{sum+=$2} END {print sum}'
rg "^(export )?(default )?class \w+" -tjs -c | awk -F: '{sum+=$2} END {print sum}'
rg "^import " -tjs -c | awk -F: '{sum+=$2} END {print sum}'
```

### Complexity Indicators
```bash
rg -c "^import " -tjs | sort -t: -k2 -rn | head -10
rg -c "^function " -tjs | sort -t: -k2 -rn | head -10
rg "if.*&&.*\|\|" -tjs -c | sort -t: -k2 -rn
rg "\?.*\?.*\?" -tjs
```

## Dependency Management

### Package Analysis
```bash
rg "from ['\"]([^.][^'\"]+)" -o -tjs -tts | sort -u
rg "@types/.*\":\s*\"" package.json
rg "peerDependencies" -A 20 package.json
rg "deprecated" package-lock.json
```

### License Compliance
```bash
rg "(license|License|LICENSE)" README.md package.json
rg "Copyright.*[0-9]{4}" --no-heading
rg "SPDX-License-Identifier:" --no-heading
```

## Log Analysis

### Error Patterns
```bash
rg "\"level\":\s*\"error\"" -g '*.log'
rg "\"message\":\"([^\"]+)\"" -o -g '*.log' | sort | uniq -c | sort -rn
rg "^\s+at\s+" -g '*.log' -A 5
rg "2025-01-" -g '*.log' | rg "ERROR"
```

### Performance Logs
```bash
rg "duration.*[0-9]{4,}" -g '*.log'
rg "response_time.*ms" -o -g '*.log' | rg -o "[0-9]+" | sort -rn | head -20
rg "memory.*MB" -g '*.log'
rg "status\":\s*[45][0-9]{2}" -g '*.log' -c
```

## Docker and Kubernetes

### Dockerfile Analysis
```bash
rg "^FROM " Dockerfile*
rg "^EXPOSE " Dockerfile*
rg "^ENV " Dockerfile*
rg "^(COPY|ADD) " Dockerfile*
rg "^FROM .* AS " Dockerfile*
```

### Kubernetes Manifests
```bash
rg "image:" -g '*.yaml' -g '*.yml' k8s/
rg "limits:" -A 3 -g '*.yaml' k8s/
rg "kind: Secret" -A 10 -g '*.yaml' k8s/
rg "kind: ConfigMap" -A 10 -g '*.yaml' k8s/
rg "kind: Service" -A 20 -g '*.yaml' k8s/
```

## Advanced Workflows

### Multi-Step Analysis
```bash
rg "router\.(get|post|put|delete)\(" -A 1 -tjs | \
  rg -o "\"([^\"]+)\"" | sort -u
rg "throw new (\w+Error)" -o -tjs | sort | uniq -c | sort -rn
rg "https?://[^\s\"']+" -o | sort -u | \
  while read url; do curl -I "$url" 2>&1 | head -1; done
```

### Code Generation Support
```bash
rg "^(export )?(type|interface) \w+" -tts -A 5
rg "^(export )?(function|const) \w+.*\{.*props" -tjsx -tts
rg "app\.(get|post|put|delete)\(['\"]([^'\"]+)" -o -tjs
```

### Batch Operations
```bash
rg -l "oldPattern" | xargs sed -i '' 's/oldPattern/newPattern/g'
rg -l "TODO" | xargs -I {} sh -c 'echo "Processing: {}"'
rg "pattern" -c | awk -F: '{sum+=$2} END {print sum}'
```
