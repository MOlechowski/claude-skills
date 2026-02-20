# GNU Parallel Quick Reference

## Replacement Strings

| String | `/path/to/file.txt` -> |
|--------|------------------------|
| `{}` | `/path/to/file.txt` |
| `{.}` | `/path/to/file` |
| `{/}` | `file.txt` |
| `{//}` | `/path/to` |
| `{/.}` | `file` |
| `{#}` | `1`, `2`, `3`... |
| `{%}` | `1`-`N` (cycles) |

## Input Sources

```bash
parallel cmd ::: A B C              # Arguments
parallel cmd :::: file.txt          # Lines from file
cat file | parallel cmd             # Stdin
parallel cmd ::: A B ::: 1 2        # Cartesian product
parallel --link cmd ::: A B ::: 1 2 # Paired (A-1, B-2)
```

## Common Flags

| Flag | Description |
|------|-------------|
| `-j N` | N parallel jobs |
| `-j 100%` | One per core |
| `-j 50%` | Half cores |
| `--dry-run` | Show commands only |
| `--verbose` | Print commands |
| `--progress` | Show progress |
| `--eta` | Estimated time |
| `--bar` | Progress bar |
| `--keep-order` | Output in input order |
| `--tag` | Prefix with input |
| `--group` | No interleaving |

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
parallel convert {} {.}.png ::: *.jpg
parallel gzip ::: *.log
parallel wget ::: url1 url2 url3
find . -name "*.txt" | parallel wc -l
export -f myfunc && parallel myfunc ::: items
```
