# GNU Parallel Quick Reference

## Replacement Strings

| String | Description | `/path/to/file.txt` → |
|--------|-------------|----------------------|
| `{}` | Full input | `/path/to/file.txt` |
| `{.}` | Remove extension | `/path/to/file` |
| `{/}` | Basename | `file.txt` |
| `{//}` | Directory | `/path/to` |
| `{/.}` | Basename, no ext | `file` |
| `{#}` | Job number | `1`, `2`, `3`... |
| `{%}` | Job slot | `1`-`N` (cycles) |

## Input Sources

```bash
parallel cmd ::: A B C          # Arguments
parallel cmd :::: file.txt      # Lines from file
cat file | parallel cmd         # Stdin
parallel cmd ::: A B ::: 1 2    # Cartesian product
parallel --link cmd ::: A B ::: 1 2  # Paired (A-1, B-2)
```

## Common Flags

| Flag | Description |
|------|-------------|
| `-j N` | N parallel jobs |
| `-j 100%` | One job per core |
| `-j 50%` | Half cores |
| `--dry-run` | Show commands, don't run |
| `--verbose` | Print commands as run |
| `--progress` | Show progress |
| `--eta` | Show estimated time |
| `--bar` | Progress bar |
| `--keep-order` | Output in input order |
| `--tag` | Prefix output with input |
| `--group` | Don't interleave output |

## Job Control

```bash
parallel -j4 cmd ::: items              # 4 jobs max
parallel --joblog log.txt cmd ::: items # Log jobs
parallel --resume --joblog log.txt ...  # Resume
parallel --timeout 60 cmd ::: items     # 60s timeout
parallel --retries 3 cmd ::: items      # Retry 3x
```

## Error Handling

```bash
parallel --halt now,fail=1 ...    # Stop on first failure
parallel --halt soon,fail=20% ... # Stop at 20% failures
parallel --halt now,success=1 ... # Stop on first success
```

## Output Control

```bash
parallel --results dir/ cmd ::: items   # Output to files
parallel 'cmd {} > {/.}.out' ::: items  # Custom output
parallel --tag cmd ::: items            # Tag with input
```

## Column Processing

```bash
parallel --colsep '\t' echo {1} {2} :::: data.tsv
parallel --colsep ',' cmd {1} {2} :::: data.csv
```

## Common Patterns

```bash
# Convert images
parallel convert {} {.}.png ::: *.jpg

# Compress files
parallel gzip ::: *.log

# Download URLs
parallel wget ::: url1 url2 url3

# Process with find
find . -name "*.txt" | parallel wc -l

# Export function
export -f myfunc && parallel myfunc ::: items
```
