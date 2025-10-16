# Fastmod Examples by Use Case

Real-world examples of fastmod usage for common refactoring scenarios.

## Class/Type Renames

### Rename Class Across Codebase
```bash
# Step 1: Update class definition
fastmod -d src --extensions ts 'class UserManager' 'class UserService'

# Step 2: Update all references
fastmod -d src --extensions ts,tsx 'UserManager' 'UserService'

# Step 3: Update test files
fastmod -d tests --extensions test.ts 'UserManager' 'UserService'

# Step 4: Update imports
fastmod -d src --extensions ts,tsx 'import.*UserManager' 'import { UserService }'
```

### Rename with Namespace
```bash
# TypeScript namespace rename
fastmod 'MyNamespace\.OldClass' 'MyNamespace.NewClass'

# Go package rename
fastmod 'oldpkg\.Type' 'newpkg.Type'
```

## Function Signature Changes

### Add Parameter to All Calls
```bash
# Before: authenticate(user)
# After: authenticate(user, context)
fastmod 'authenticate\((.*?)\)' 'authenticate(${1}, context)'
```

### Change Parameter Order
```bash
# Before: connect(host, port, options)
# After: connect(options, host, port)
fastmod 'connect\(([^,]+),\s*([^,]+),\s*([^)]+)\)' 'connect(${3}, ${1}, ${2})'
```

### Add Default Values
```bash
# Before: function process(data)
# After: function process(data, timeout = 5000)
fastmod 'function process\(([^)]+)\)' 'function process(${1}, timeout = 5000)'
```

## Import/Export Updates

### Update Import Paths After Move
```bash
# Relative imports
fastmod "from '\.\./utils/" "from '../shared/"
fastmod "from '\./utils/" "from './helpers/"

# Absolute imports
fastmod "from '@/components/old" "from '@/components/new"
```

### Change Import Style
```bash
# CommonJS to ES6
fastmod "const (\w+) = require\('(.+?)'\)" "import ${1} from '${2}'"

# Named to default imports
fastmod "import \{ (\w+) \} from" "import ${1} from"
```

### Update Package Names
```bash
# After package rename
fastmod '@old-org/package' '@new-org/package'
fastmod 'old-package-name' 'new-package-name'
```

## Framework Migrations

### React Props Updates
```bash
# Size props
fastmod 'size="small"' 'size="sm"'
fastmod 'size="medium"' 'size="md"'
fastmod 'size="large"' 'size="lg"'

# Prop name changes
fastmod '<Button type=' '<Button variant='
fastmod 'onClick=' 'onPress='

# Boolean props
fastmod 'disabled={true}' 'disabled'
```

### API Version Migration
```bash
# Endpoint updates
fastmod '/api/v1/' '/api/v2/'

# Method changes
fastmod '\.get\(' '.fetch('
fastmod 'axios\.' 'http.'
```

### CSS Framework Updates
```bash
# Tailwind v2 to v3
fastmod 'bg-opacity-' 'bg-'
fastmod 'text-opacity-' 'text-'

# Bootstrap class renames
fastmod 'pull-left' 'float-start'
fastmod 'pull-right' 'float-end'
```

## Configuration Changes

### Environment Variables
```bash
# Rename env vars in code
fastmod 'process\.env\.OLD_VAR' 'process.env.NEW_VAR'
fastmod 'REACT_APP_OLD' 'REACT_APP_NEW'
```

### Config Keys
```bash
# Update config object keys
fastmod 'config\.oldKey' 'config.newKey'
fastmod '"oldSetting":' '"newSetting":'
```

## Code Style Updates

### Convert Function Syntax
```bash
# Function declaration to arrow function
fastmod 'function (\w+)\((.*?)\) \{' 'const ${1} = (${2}) => {'

# Method to arrow function
fastmod '(\w+): function\((.*?)\) \{' '${1}: (${2}) => {'
```

### Modernize Syntax
```bash
# var to const/let (review each)
fastmod '\bvar\b' 'const'

# String concatenation to template literals (simple cases)
fastmod '"' + (\w+) + "' '`' + (\w+) + '`'
```

### Formatting Updates
```bash
# Add trailing commas
fastmod '(\w+): (\w+)\n\}' '${1}: ${2},\n}'

# Consistent spacing
fastmod 'if\(' 'if ('
fastmod '\){'  ') {'
```

## Database & ORM

### Query Updates
```bash
# Update query methods
fastmod '\.findOne\(' '.findUnique('
fastmod '\.find\(' '.findMany('

# Schema changes
fastmod '@Column\(\)' '@Column({ type: "varchar" })'
```

### Table/Model Renames
```bash
fastmod 'from users' 'from app_users'
fastmod 'User\.' 'AppUser.'
```

## Testing

### Update Test Framework
```bash
# Jest to Vitest
fastmod "from 'jest'" "from 'vitest'"
fastmod 'jest\.' 'vi.'

# Mocha to Jest
fastmod 'describe\(' 'test.describe('
fastmod 'it\(' 'test('
```

### Assertion Library Changes
```bash
# Chai to Jest
fastmod '\.should\.equal' '.toBe'
fastmod 'expect\(.*\)\.to\.be\.true' 'expect(${1}).toBe(true)'
```

### Mock Updates
```bash
# Update mock syntax
fastmod 'jest\.mock\(' 'vi.mock('
fastmod 'jest\.fn\(' 'vi.fn('
```

## Documentation

### Update Markdown Links
```bash
# Docs restructure
fastmod '\]\(/docs/old/' '](/docs/new/'
fastmod '\.md\)' '.html)'
```

### Code Comment Updates
```bash
# Update JSDoc tags
fastmod '@param \{Object\}' '@param {Record<string, unknown>}'
fastmod '@returns \{void\}' '@returns {Promise<void>}'
```

## Git & Repository

### Update URLs
```bash
# After repository move
fastmod 'github\.com/old-org/' 'github.com/new-org/'
fastmod 'gitlab\.com/old-repo' 'gitlab.com/new-repo'
```

### License Headers
```bash
# Update copyright year
fastmod 'Copyright 2023' 'Copyright 2024'
fastmod 'Copyright \(c\) 2023' 'Copyright (c) 2024'
```

## Language-Specific Examples

### TypeScript
```bash
# Update type annotations
fastmod ': any' ': unknown'
fastmod 'as any' 'as unknown'

# Interface to type
fastmod 'interface (\w+) \{' 'type ${1} = {'
```

### Python
```bash
# Python 2 to 3
fastmod 'print (.+)$' 'print(${1})'
fastmod "except (\w+), (\w+):" "except ${1} as ${2}:"

# Type hints
fastmod 'def (\w+)\((.*?)\):' 'def ${1}(${2}) -> None:'
```

### Go
```bash
# Error handling updates
fastmod 'errors\.New' 'fmt.Errorf'
fastmod 'err != nil \{\n\s+return err' 'err != nil {\n\t\treturn fmt.Errorf("operation failed: %w", err)'
```

### Rust
```bash
# Ownership patterns
fastmod '&mut (\w+)' '&${1}'
fastmod '\.clone\(\)' '' # Remove unnecessary clones (review carefully!)

# Macro updates
fastmod 'println!\(' 'log::info!('
```

## Multi-Step Refactoring

### Complete API Rename
```bash
# 1. Update function definitions
fastmod 'export function oldApi' 'export function newApi'

# 2. Update function calls
fastmod 'oldApi\(' 'newApi('

# 3. Update imports
fastmod 'import.*oldApi' 'import { newApi }'

# 4. Update type definitions
fastmod 'OldApiResponse' 'NewApiResponse'

# 5. Update tests
fastmod 'describe\("oldApi"' 'describe("newApi"'
```

### Component Library Upgrade
```bash
# 1. Update component imports
fastmod "from 'old-lib'" "from 'new-lib'"

# 2. Update component names
fastmod '<OldButton' '<Button'

# 3. Update props
fastmod 'variant="primary"' 'color="primary"'

# 4. Update event handlers
fastmod 'onChange=' 'onValueChange='

# 5. Update exports
fastmod 'export.*from.*old-lib' 'export * from "new-lib"'
```

## Tips for Complex Refactoring

1. **Start Small**: Test pattern on single file or directory first
2. **One Change at a Time**: Don't combine multiple transformations
3. **Validate Between Steps**: Run tests after each fastmod operation
4. **Use Git Branches**: Create refactoring branch for easy rollback
5. **Document Patterns**: Save successful fastmod commands for future reference

## Pattern Library

Save commonly used patterns:

```bash
# Create a patterns file
cat > fastmod-patterns.sh << 'EOF'
#!/bin/bash
# Common fastmod patterns for this project

# Rename service classes
alias rename-service='fastmod -d src/services --extensions ts'

# Update API calls
alias update-api='fastmod -d src/api --extensions ts,tsx'

# Fix imports
alias fix-imports='fastmod -d src --extensions ts,tsx,js,jsx'
EOF

chmod +x fastmod-patterns.sh
```
