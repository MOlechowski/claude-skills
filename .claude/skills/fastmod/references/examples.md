# Fastmod Examples

## Class/Type Renames

### Rename Class
```bash
# 1: Class definition
fastmod -d src --extensions ts 'class UserManager' 'class UserService'

# 2: All references
fastmod -d src --extensions ts,tsx 'UserManager' 'UserService'

# 3: Tests
fastmod -d tests --extensions test.ts 'UserManager' 'UserService'

# 4: Imports
fastmod -d src --extensions ts,tsx 'import.*UserManager' 'import { UserService }'
```

### Namespace Rename
```bash
fastmod 'MyNamespace\.OldClass' 'MyNamespace.NewClass'
fastmod 'oldpkg\.Type' 'newpkg.Type'
```

## Function Signatures

### Add Parameter
```bash
fastmod 'authenticate\((.*?)\)' 'authenticate(${1}, context)'
```

### Change Parameter Order
```bash
fastmod 'connect\(([^,]+),\s*([^,]+),\s*([^)]+)\)' 'connect(${3}, ${1}, ${2})'
```

### Add Default Values
```bash
fastmod 'function process\(([^)]+)\)' 'function process(${1}, timeout = 5000)'
```

## Imports

### Update Paths
```bash
fastmod "from '\.\./utils/" "from '../shared/"
fastmod "from '\./utils/" "from './helpers/"
fastmod "from '@/components/old" "from '@/components/new"
```

### Change Style
```bash
# CommonJS to ES6
fastmod "const (\w+) = require\('(.+?)'\)" "import ${1} from '${2}'"

# Named to default
fastmod "import \{ (\w+) \} from" "import ${1} from"
```

### Package Names
```bash
fastmod '@old-org/package' '@new-org/package'
fastmod 'old-package-name' 'new-package-name'
```

## Framework Migrations

### React Props
```bash
fastmod 'size="small"' 'size="sm"'
fastmod 'size="medium"' 'size="md"'
fastmod '<Button type=' '<Button variant='
fastmod 'disabled={true}' 'disabled'
```

### API Version
```bash
fastmod '/api/v1/' '/api/v2/'
fastmod '\.get\(' '.fetch('
fastmod 'axios\.' 'http.'
```

### CSS Frameworks
```bash
fastmod 'bg-opacity-' 'bg-'
fastmod 'pull-left' 'float-start'
```

## Config Changes

### Environment Variables
```bash
fastmod 'process\.env\.OLD_VAR' 'process.env.NEW_VAR'
fastmod 'REACT_APP_OLD' 'REACT_APP_NEW'
```

### Config Keys
```bash
fastmod 'config\.oldKey' 'config.newKey'
fastmod '"oldSetting":' '"newSetting":'
```

## Code Style

### Function Syntax
```bash
fastmod 'function (\w+)\((.*?)\) \{' 'const ${1} = (${2}) => {'
fastmod '(\w+): function\((.*?)\) \{' '${1}: (${2}) => {'
```

### Modernize
```bash
fastmod '\bvar\b' 'const'
```

### Formatting
```bash
fastmod 'if\(' 'if ('
fastmod '\){'  ') {'
```

## Database & ORM

### Queries
```bash
fastmod '\.findOne\(' '.findUnique('
fastmod '\.find\(' '.findMany('
fastmod '@Column\(\)' '@Column({ type: "varchar" })'
```

### Tables/Models
```bash
fastmod 'from users' 'from app_users'
fastmod 'User\.' 'AppUser.'
```

## Testing

### Framework Updates
```bash
fastmod "from 'jest'" "from 'vitest'"
fastmod 'jest\.' 'vi.'
fastmod 'it\(' 'test('
```

### Assertions
```bash
fastmod '\.should\.equal' '.toBe'
```

### Mocks
```bash
fastmod 'jest\.mock\(' 'vi.mock('
fastmod 'jest\.fn\(' 'vi.fn('
```

## Documentation

### Markdown Links
```bash
fastmod '\]\(/docs/old/' '](/docs/new/'
fastmod '\.md\)' '.html)'
```

### JSDoc
```bash
fastmod '@param \{Object\}' '@param {Record<string, unknown>}'
fastmod '@returns \{void\}' '@returns {Promise<void>}'
```

## Git & Repo

```bash
fastmod 'github\.com/old-org/' 'github.com/new-org/'
fastmod 'Copyright 2023' 'Copyright 2024'
```

## Language-Specific

### TypeScript
```bash
fastmod ': any' ': unknown'
fastmod 'interface (\w+) \{' 'type ${1} = {'
```

### Python
```bash
fastmod 'print (.+)$' 'print(${1})'
fastmod "except (\w+), (\w+):" "except ${1} as ${2}:"
```

### Go
```bash
fastmod 'errors\.New' 'fmt.Errorf'
```

### Rust
```bash
fastmod 'println!\(' 'log::info!('
```

## Multi-Step Refactoring

### API Rename
```bash
fastmod 'export function oldApi' 'export function newApi'
fastmod 'oldApi\(' 'newApi('
fastmod 'import.*oldApi' 'import { newApi }'
fastmod 'OldApiResponse' 'NewApiResponse'
```

### Component Library Upgrade
```bash
fastmod "from 'old-lib'" "from 'new-lib'"
fastmod '<OldButton' '<Button'
fastmod 'variant="primary"' 'color="primary"'
fastmod 'onChange=' 'onValueChange='
```

## Tips

1. **Start Small**: Test on single file first
2. **One at a Time**: Don't combine transformations
3. **Validate**: Run tests after each operation
4. **Use Branches**: Easy rollback
5. **Document**: Save successful patterns
