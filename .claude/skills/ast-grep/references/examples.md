# ast-grep Examples

## React Refactoring

### Convert Class Components to Functional
```bash
# Find class components
sg -p 'class $NAME extends React.Component {
  render() {
    return $JSX
  }
}' --lang tsx

# Convert to function component
sg -p 'class $NAME extends React.Component {
  render() {
    return $JSX
  }
}' -r 'function $NAME() {
  return $JSX
}' --lang tsx --interactive
```

### useState Hook Patterns
```bash
# Find all useState declarations
sg -p 'const [$STATE, $SETTER] = useState($INIT)' --lang tsx

# Find useState with complex initial state
sg -p 'const [$STATE, $SETTER] = useState(() => $INIT)' --lang tsx

# Find useState without destructuring
sg -p 'const $VAR = useState($INIT)' --lang tsx

# Refactor to use initial function
sg -p 'const [$STATE, $SETTER] = useState($COMPLEX_INIT)' \
   -r 'const [$STATE, $SETTER] = useState(() => $COMPLEX_INIT)' \
   --lang tsx
```

### useEffect Dependency Arrays
```bash
# Find useEffect with empty deps
sg -p 'useEffect(() => { $$$BODY }, [])' --lang tsx

# Find useEffect without deps (risky)
sg -p 'useEffect(() => { $$$BODY })' \
   --not-has '}, [$$$DEPS]' \
   --lang tsx

# Find useEffect using state not in deps
sg -p 'useEffect(() => { $$$BODY }, [$$$DEPS])' \
   --has '$STATE' \
   --lang tsx
```

### Props Destructuring
```bash
# Find components not destructuring props
sg -p 'function $NAME(props) { $$$BODY }' --lang tsx

# Convert to destructured props
sg -p 'function $NAME(props) {
  return <div>{props.$PROP}</div>
}' -r 'function $NAME({ $PROP }) {
  return <div>{$PROP}</div>
}' --lang tsx

# Find components with many props
sg -p 'function $NAME({ $$$PROPS })' \
   --lang tsx --json | \
   jq 'select(.metavars.PROPS | length > 5)'
```

## TypeScript Patterns

### Type Annotations
```bash
# Find untyped function parameters
sg -p 'function $NAME($PARAM) { $$$BODY }' \
   --lang ts

# Find functions missing return type
sg -p 'function $NAME($$$PARAMS) { $$$BODY }' \
   --not-has '):' \
   --lang ts

# Add return type annotation
sg -p 'function $NAME($$$PARAMS) {
  return $VALUE
}' -r 'function $NAME($$$PARAMS): ReturnType<typeof $VALUE> {
  return $VALUE
}' --lang ts
```

### Interface vs Type
```bash
# Find all type aliases
sg -p 'type $NAME = $DEF' --lang ts

# Find all interfaces
sg -p 'interface $NAME { $$$PROPS }' --lang ts

# Convert type to interface
sg -p 'type $NAME = {
  $$$PROPS
}' -r 'interface $NAME {
  $$$PROPS
}' --lang ts
```

### Generic Constraints
```bash
# Find unconstrained generics
sg -p 'function $NAME<$T>($$$PARAMS) { $$$BODY }' \
   --not-has 'extends' \
   --lang ts

# Find overly broad generics
sg -p '<$T extends any>' --lang ts

# Add constraint
sg -p 'function $NAME<$T>($PARAM: $T) { $$$BODY }' \
   -r 'function $NAME<$T extends object>($PARAM: $T) { $$$BODY }' \
   --lang ts
```

## Error Handling

### Missing Try-Catch
```bash
# Find await without try-catch
sg -p 'await $PROMISE' \
   --not-inside 'try { $$$BODY } catch ($ERR) { $$$HANDLER }' \
   --lang js

# Find async functions lacking error handling
sg -p 'async function $NAME() {
  await $PROMISE
  $$$REST
}' --not-has 'try' --lang js

# Add try-catch wrapper
sg -p 'await $PROMISE' \
   -r 'try {
  await $PROMISE
} catch (error) {
  console.error("Error:", error);
  throw error;
}' --lang js
```

### Promise Chains vs Async/Await
```bash
# Find Promise.then chains
sg -p '$PROMISE.then($HANDLER)' --lang js

# Convert to async/await
sg -p '$PROMISE.then($SUCCESS).catch($ERROR)' \
   -r 'try {
  const result = await $PROMISE;
  $SUCCESS(result);
} catch (error) {
  $ERROR(error);
}' --lang js

# Find unhandled rejections
sg -p '$PROMISE.then($HANDLER)' \
   --not-has '.catch' \
   --lang js
```

### Error Throwing Patterns
```bash
# Find throw without Error object
sg -p 'throw $MSG' \
   --not-has 'new Error' \
   --lang js

# Find caught errors not logged
sg -p 'catch ($ERR) { $$$BODY }' \
   --not-has 'console.error' \
   --not-has 'logger' \
   --lang js

# Improve error throwing
sg -p 'throw $MSG' \
   -r 'throw new Error($MSG)' \
   --lang js
```

## Code Quality

### Magic Numbers
```bash
# Find numeric literals in code
sg -p '$VAR * $NUM' \
   --lang js | \
   grep -E '[0-9]{2,}'

# Find array index access
sg -p '$ARR[$NUM]' --lang js

# Extract to constant
sg -p 'if ($VAR > 100)' \
   -r 'const THRESHOLD = 100;
if ($VAR > THRESHOLD)' \
   --lang js
```

### Long Parameter Lists
```bash
# Find functions with many params
sg -p 'function $NAME($P1, $P2, $P3, $P4, $P5, $$$MORE)' --lang js

# Suggest object parameter pattern
sg -p 'function $NAME($P1, $P2, $P3, $P4)' \
   -r 'function $NAME({ $P1, $P2, $P3, $P4 })' \
   --lang js
```

### Nested Conditionals
```bash
# Find deeply nested if statements
sg -p 'if ($COND1) {
  if ($COND2) {
    if ($COND3) {
      $$$BODY
    }
  }
}' --lang js

# Find nested ternaries
sg -p '$COND1 ? ($COND2 ? $A : $B) : $C' --lang js
```

## Security Patterns

### SQL Injection Risks
```bash
# Find string concatenation in SQL
sg -p 'query($SQL + $VAR)' --lang js

# Find template literals in SQL
sg -p 'query(`$$$SQL ${$VAR} $$$`)' --lang js

# Find execute with interpolation
sg -p 'execute(`SELECT * FROM users WHERE id = ${$ID}`)' --lang js

# Suggest parameterized queries
sg -p 'query(`SELECT * FROM users WHERE id = ${$ID}`)' \
   -r 'query("SELECT * FROM users WHERE id = ?", [$ID])' \
   --lang js
```

### XSS Vulnerabilities
```bash
# Find innerHTML assignments
sg -p '$EL.innerHTML = $HTML' --lang js

# Find dangerouslySetInnerHTML
sg -p '<$COMP dangerouslySetInnerHTML={{ __html: $HTML }} />' --lang tsx

# Find document.write
sg -p 'document.write($CONTENT)' --lang js

# Find eval usage
sg -p 'eval($CODE)' --lang js
```

### Hardcoded Credentials
```bash
# Find hardcoded passwords
sg -p '$VAR = "password"' --lang js
sg -p 'password: "$PASSWORD"' --lang js

# Find API keys
sg -p 'const API_KEY = "$KEY"' --lang js

# Find secret assignments
sg -p '$VAR = { secret: "$SECRET" }' --lang js
```

## API and Network

### Fetch Patterns
```bash
# Find fetch without error handling
sg -p 'fetch($URL)' \
   --not-inside 'try { $$$BODY } catch ($ERR) { $$$HANDLER }' \
   --lang js

# Find fetch without await
sg -p 'fetch($URL)' \
   --not-has 'await' \
   --not-inside 'then' \
   --lang js

# Add error handling
sg -p 'const $RES = await fetch($URL)' \
   -r 'const $RES = await fetch($URL).catch(error => {
  logger.error("Fetch failed:", error);
  throw error;
})' --lang js
```

### REST API Endpoints
```bash
# Find all API route definitions
sg -p 'app.$METHOD($PATH, $HANDLER)' --lang js

# Find unprotected routes
sg -p 'router.post($PATH, $HANDLER)' \
   --not-has 'auth' \
   --lang js

# Find routes without validation
sg -p 'app.post($PATH, async ($REQ, $RES) => {
  $$$BODY
})' --not-has 'validate' --lang js
```

### GraphQL Patterns
```bash
# Find GraphQL queries
sg -p 'gql`
  query $NAME {
    $$$FIELDS
  }
`' --lang js

# Find mutations lacking error handling
sg -p 'mutation $NAME {
  $$$BODY
}' --not-has 'catch' --lang js
```

## Performance Optimization

### Loop Optimization
```bash
# Find nested loops
sg -p 'for ($I of $ARR1) {
  for ($J of $ARR2) {
    $$$BODY
  }
}' --lang js

# Find array ops in loops
sg -p 'for ($I of $ARR) {
  $ARR2.push($ITEM)
}' --lang js

# Suggest map/reduce
sg -p 'for ($ITEM of $ARR) {
  $RESULT.push($TRANSFORM)
}' -r '$RESULT = $ARR.map($ITEM => $TRANSFORM)' --lang js
```

### Unnecessary Re-renders (React)
```bash
# Find inline function props
sg -p '<$COMP onClick={() => $HANDLER} />' --lang tsx

# Find inline object props
sg -p '<$COMP style={{ $$$PROPS }} />' --lang tsx

# Find missing React.memo
sg -p 'function $COMP({ $$$PROPS }) {
  return $JSX
}' --not-has 'React.memo' --lang tsx
```

### Bundle Size
```bash
# Find large library imports
sg -p 'import $SPEC from "lodash"' --lang js

# Suggest specific imports
sg -p 'import _ from "lodash"' \
   -r 'import { $METHOD } from "lodash/$METHOD"' \
   --lang js

# Find moment.js (suggest date-fns)
sg -p 'import moment from "moment"' --lang js
```

## Testing Patterns

### Missing Tests
```bash
# Find exported functions without tests
sg -p 'export function $NAME($$$PARAMS) { $$$BODY }' --lang js | \
  while read -r match; do
    name=$(echo "$match" | jq -r '.metavars.NAME')
    sg -p "describe('$name'" test/ --quiet || echo "No test for $name"
  done
```

### Test Structure
```bash
# Find tests without assertions
sg -p 'it($DESC, () => {
  $$$BODY
})' --not-has 'expect' --lang js

# Find async tests without await
sg -p 'it($DESC, async () => {
  $$$BODY
})' --not-has 'await' --lang js

# Find tests with console.log
sg -p 'it($DESC, () => {
  console.log($MSG)
  $$$BODY
})' --lang js
```

### Mock Patterns
```bash
# Find unmocked API calls in tests
sg -p 'fetch($URL)' \
   --inside 'describe($SUITE, () => { $$$TESTS })' \
   --not-has 'jest.mock' \
   --lang js

# Find jest.fn() without implementation
sg -p 'jest.fn()' \
   --not-has 'mockImplementation' \
   --lang js
```

## Documentation

### JSDoc Patterns
```bash
# Find exported functions without JSDoc
sg -p 'export function $NAME($$$PARAMS) { $$$BODY }' \
   --not-precedes '/**' \
   --lang js

# Find @param without type
sg -p '* @param $NAME' \
   --not-has '{' \
   --lang js

# Find incomplete JSDoc
sg -p '/**
 * $DESC
 * @param $PARAM
 */' --not-has '@return' --lang js
```

## Code Migration

### CommonJS to ESM
```bash
# Find require statements
sg -p 'const $VAR = require($MODULE)' --lang js

# Convert to import
sg -p 'const $VAR = require($MODULE)' \
   -r 'import $VAR from $MODULE' \
   --lang js

# Find module.exports
sg -p 'module.exports = $EXPORT' --lang js

# Convert to export
sg -p 'module.exports = $EXPORT' \
   -r 'export default $EXPORT' \
   --lang js
```

### Deprecated API Migration
```bash
# Find deprecated lifecycle methods
sg -p 'componentWillMount() { $$$BODY }' --lang tsx

# Suggest useEffect
sg -p 'componentDidMount() { $$$BODY }' \
   -r 'useEffect(() => {
  $$$BODY
}, [])' --lang tsx

# Find findDOMNode usage
sg -p 'ReactDOM.findDOMNode($COMP)' --lang js
```

## Custom Linting Rules

### Enforce Coding Standards
```yaml
# rules/no-var.yml
id: no-var
message: Use const or let instead of var
severity: error
language: JavaScript
rule:
  pattern: var $NAME = $VALUE
fix: const $NAME = $VALUE
```

### Enforce Best Practices
```yaml
# rules/require-await.yml
id: require-await-in-async
message: Async function should use await
severity: warning
language: TypeScript
rule:
  pattern: async function $NAME() { $$$BODY }
  not:
    has:
      pattern: await $EXPR
```

### Security Rules
```yaml
# rules/no-eval.yml
id: no-eval
message: eval() is dangerous and should not be used
severity: error
language: JavaScript
rule:
  any:
    - pattern: eval($CODE)
    - pattern: Function($CODE)
    - pattern: setTimeout($CODE)
      has:
        pattern: $STRING
```

## Complex Transformations

### Modernize Callbacks to Promises
```bash
# Find callback pattern
sg -p 'function $NAME($PARAMS, callback) {
  $$$BODY
  callback($ERR, $RESULT)
}' --lang js

# Convert to Promise
sg -p 'function $NAME($PARAMS, callback) {
  $$$BODY
  callback(null, $RESULT)
}' -r 'async function $NAME($PARAMS) {
  $$$BODY
  return $RESULT
}' --lang js
```

### Refactor Large Functions
```bash
# Find long functions
sg -p 'function $NAME() { $$$BODY }' --lang js | \
  jq 'select(.metavars.BODY | length > 50)'

# Extract helper functions
sg -p 'function $NAME() {
  // Step 1
  $$$STEP1
  // Step 2
  $$$STEP2
}' -r 'function $NAME() {
  step1();
  step2();
}

function step1() { $$$STEP1 }
function step2() { $$$STEP2 }' --lang js
```
