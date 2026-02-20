# ast-grep Examples

## React Refactoring

### Convert Class to Functional Components
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
# Find useState declarations
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
# useEffect with empty deps
sg -p 'useEffect(() => { $$$BODY }, [])' --lang tsx

# useEffect without deps (risky)
sg -p 'useEffect(() => { $$$BODY })' \
   --not-has '}, [$$$DEPS]' \
   --lang tsx

# useEffect using state not in deps
sg -p 'useEffect(() => { $$$BODY }, [$$$DEPS])' \
   --has '$STATE' \
   --lang tsx
```

### Props Destructuring
```bash
# Components not destructuring props
sg -p 'function $NAME(props) { $$$BODY }' --lang tsx

# Convert to destructured props
sg -p 'function $NAME(props) {
  return <div>{props.$PROP}</div>
}' -r 'function $NAME({ $PROP }) {
  return <div>{$PROP}</div>
}' --lang tsx

# Components with many props
sg -p 'function $NAME({ $$$PROPS })' \
   --lang tsx --json | \
   jq 'select(.metavars.PROPS | length > 5)'
```

## TypeScript Patterns

### Type Annotations
```bash
# Untyped function parameters
sg -p 'function $NAME($PARAM) { $$$BODY }' \
   --lang ts

# Functions missing return type
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
# Type aliases
sg -p 'type $NAME = $DEF' --lang ts

# Interfaces
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
# Unconstrained generics
sg -p 'function $NAME<$T>($$$PARAMS) { $$$BODY }' \
   --not-has 'extends' \
   --lang ts

# Overly broad generics
sg -p '<$T extends any>' --lang ts

# Add constraint
sg -p 'function $NAME<$T>($PARAM: $T) { $$$BODY }' \
   -r 'function $NAME<$T extends object>($PARAM: $T) { $$$BODY }' \
   --lang ts
```

## Error Handling

### Missing Try-Catch
```bash
# await without try-catch
sg -p 'await $PROMISE' \
   --not-inside 'try { $$$BODY } catch ($ERR) { $$$HANDLER }' \
   --lang js

# async functions lacking error handling
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
# Promise.then chains
sg -p '$PROMISE.then($HANDLER)' --lang js

# Convert to async/await
sg -p '$PROMISE.then($SUCCESS).catch($ERROR)' \
   -r 'try {
  const result = await $PROMISE;
  $SUCCESS(result);
} catch (error) {
  $ERROR(error);
}' --lang js

# Unhandled rejections
sg -p '$PROMISE.then($HANDLER)' \
   --not-has '.catch' \
   --lang js
```

### Error Throwing Patterns
```bash
# throw without Error object
sg -p 'throw $MSG' \
   --not-has 'new Error' \
   --lang js

# Caught errors not logged
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
# Numeric literals in code
sg -p '$VAR * $NUM' \
   --lang js | \
   grep -E '[0-9]{2,}'

# Array index access
sg -p '$ARR[$NUM]' --lang js

# Extract to constant
sg -p 'if ($VAR > 100)' \
   -r 'const THRESHOLD = 100;
if ($VAR > THRESHOLD)' \
   --lang js
```

### Long Parameter Lists
```bash
# Functions with many params
sg -p 'function $NAME($P1, $P2, $P3, $P4, $P5, $$$MORE)' --lang js

# Suggest object parameter pattern
sg -p 'function $NAME($P1, $P2, $P3, $P4)' \
   -r 'function $NAME({ $P1, $P2, $P3, $P4 })' \
   --lang js
```

### Nested Conditionals
```bash
# Deeply nested if statements
sg -p 'if ($COND1) {
  if ($COND2) {
    if ($COND3) {
      $$$BODY
    }
  }
}' --lang js

# Nested ternaries
sg -p '$COND1 ? ($COND2 ? $A : $B) : $C' --lang js
```

## Security Patterns

### SQL Injection Risks
```bash
# String concatenation in SQL
sg -p 'query($SQL + $VAR)' --lang js

# Template literals in SQL
sg -p 'query(`$$$SQL ${$VAR} $$$`)' --lang js

# Execute with interpolation
sg -p 'execute(`SELECT * FROM users WHERE id = ${$ID}`)' --lang js

# Suggest parameterized queries
sg -p 'query(`SELECT * FROM users WHERE id = ${$ID}`)' \
   -r 'query("SELECT * FROM users WHERE id = ?", [$ID])' \
   --lang js
```

### XSS Vulnerabilities
```bash
# innerHTML assignments
sg -p '$EL.innerHTML = $HTML' --lang js

# dangerouslySetInnerHTML
sg -p '<$COMP dangerouslySetInnerHTML={{ __html: $HTML }} />' --lang tsx

# document.write
sg -p 'document.write($CONTENT)' --lang js

# eval usage
sg -p 'eval($CODE)' --lang js
```

### Hardcoded Credentials
```bash
# Hardcoded passwords
sg -p '$VAR = "password"' --lang js
sg -p 'password: "$PASSWORD"' --lang js

# API keys
sg -p 'const API_KEY = "$KEY"' --lang js

# Secret assignments
sg -p '$VAR = { secret: "$SECRET" }' --lang js
```

## API and Network

### Fetch Patterns
```bash
# fetch without error handling
sg -p 'fetch($URL)' \
   --not-inside 'try { $$$BODY } catch ($ERR) { $$$HANDLER }' \
   --lang js

# fetch without await
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
# API route definitions
sg -p 'app.$METHOD($PATH, $HANDLER)' --lang js

# Unprotected routes
sg -p 'router.post($PATH, $HANDLER)' \
   --not-has 'auth' \
   --lang js

# Routes without validation
sg -p 'app.post($PATH, async ($REQ, $RES) => {
  $$$BODY
})' --not-has 'validate' --lang js
```

### GraphQL Patterns
```bash
# GraphQL queries
sg -p 'gql`
  query $NAME {
    $$$FIELDS
  }
`' --lang js

# Mutations lacking error handling
sg -p 'mutation $NAME {
  $$$BODY
}' --not-has 'catch' --lang js
```

## Performance Optimization

### Loop Optimization
```bash
# Nested loops
sg -p 'for ($I of $ARR1) {
  for ($J of $ARR2) {
    $$$BODY
  }
}' --lang js

# Array ops in loops
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
# Inline function props
sg -p '<$COMP onClick={() => $HANDLER} />' --lang tsx

# Inline object props
sg -p '<$COMP style={{ $$$PROPS }} />' --lang tsx

# Missing React.memo
sg -p 'function $COMP({ $$$PROPS }) {
  return $JSX
}' --not-has 'React.memo' --lang tsx
```

### Bundle Size
```bash
# Large library imports
sg -p 'import $SPEC from "lodash"' --lang js

# Suggest specific imports
sg -p 'import _ from "lodash"' \
   -r 'import { $METHOD } from "lodash/$METHOD"' \
   --lang js

# moment.js (suggest date-fns)
sg -p 'import moment from "moment"' --lang js
```

## Testing Patterns

### Missing Tests
```bash
# Exported functions without tests
sg -p 'export function $NAME($$$PARAMS) { $$$BODY }' --lang js | \
  while read -r match; do
    name=$(echo "$match" | jq -r '.metavars.NAME')
    sg -p "describe('$name'" test/ --quiet || echo "No test for $name"
  done
```

### Test Structure
```bash
# Tests without assertions
sg -p 'it($DESC, () => {
  $$$BODY
})' --not-has 'expect' --lang js

# Async tests without await
sg -p 'it($DESC, async () => {
  $$$BODY
})' --not-has 'await' --lang js

# Tests with console.log
sg -p 'it($DESC, () => {
  console.log($MSG)
  $$$BODY
})' --lang js
```

### Mock Patterns
```bash
# Unmocked API calls in tests
sg -p 'fetch($URL)' \
   --inside 'describe($SUITE, () => { $$$TESTS })' \
   --not-has 'jest.mock' \
   --lang js

# jest.fn() without implementation
sg -p 'jest.fn()' \
   --not-has 'mockImplementation' \
   --lang js
```

## Documentation

### JSDoc Patterns
```bash
# Exported functions without JSDoc
sg -p 'export function $NAME($$$PARAMS) { $$$BODY }' \
   --not-precedes '/**' \
   --lang js

# @param without type
sg -p '* @param $NAME' \
   --not-has '{' \
   --lang js

# Incomplete JSDoc
sg -p '/**
 * $DESC
 * @param $PARAM
 */' --not-has '@return' --lang js
```

## Code Migration

### CommonJS to ESM
```bash
# require statements
sg -p 'const $VAR = require($MODULE)' --lang js

# Convert to import
sg -p 'const $VAR = require($MODULE)' \
   -r 'import $VAR from $MODULE' \
   --lang js

# module.exports
sg -p 'module.exports = $EXPORT' --lang js

# Convert to export
sg -p 'module.exports = $EXPORT' \
   -r 'export default $EXPORT' \
   --lang js
```

### Deprecated API Migration
```bash
# Deprecated lifecycle methods
sg -p 'componentWillMount() { $$$BODY }' --lang tsx

# Suggest useEffect
sg -p 'componentDidMount() { $$$BODY }' \
   -r 'useEffect(() => {
  $$$BODY
}, [])' --lang tsx

# findDOMNode usage
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
message: eval() is dangerous
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
# Callback pattern
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
# Long functions
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
