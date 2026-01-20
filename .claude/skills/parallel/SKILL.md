---
name: parallel
description: "Execute shell jobs in parallel using GNU parallel. Use when: batch processing files, running same command on multiple inputs, CPU-intensive transforms, replacing slow loops. Triggers: run in parallel, batch process, parallelize, convert all images, process files concurrently."
---

# GNU Parallel Skill

## Basic Usage

### Input Sources

**From arguments (:::)**
```bash
parallel echo ::: A B C
```

**From file (::::)**
```bash
parallel echo :::: items.txt
```

**From stdin (pipe)**
```bash
cat items.txt | parallel echo
```

**Multiple input sources**
```bash
parallel echo ::: A B ::: 1 2
# Cartesian product: A 1, A 2, B 1, B 2
```

**Linked inputs (one-to-one)**
```bash
parallel --link echo ::: A B C ::: 1 2 3
# Paired: A 1, B 2, C 3
```

### Basic Command Patterns

```bash
parallel gzip ::: *.txt
parallel echo "Processing {}" ::: *.log
parallel -j4 convert {} {.}.png ::: *.jpg
```

## Replacement Strings

| String | Description | `/path/to/file.txt` -> |
|--------|-------------|------------------------|
| `{}` | Full input | `/path/to/file.txt` |
| `{.}` | Without extension | `/path/to/file` |
| `{/}` | Basename | `file.txt` |
| `{//}` | Directory | `/path/to` |
| `{/.}` | Basename without ext | `file` |
| `{#}` | Job number | `3` |
| `{%}` | Job slot number | `2` |

### Replacement String Examples

```bash
# Maintain directory structure
parallel convert {} {.}.png ::: images/*.jpg

# Output to different directory
parallel convert {} output/{/.}.png ::: images/*.jpg

# Use job number for unique output
parallel 'echo {} > output_{#}.txt' ::: A B C
```

### Custom Delimiters

```bash
parallel --colsep '\t' echo {1} {2} :::: data.tsv
parallel --colsep ',' echo "Name: {1}, Age: {2}" :::: people.csv
parallel --colsep '\t' mv {1} {2} :::: rename_pairs.tsv
```

## Job Control

### Concurrency

```bash
parallel -j4 command ::: items      # 4 jobs
parallel -j100% command ::: items   # One per core (default)
parallel -j50% command ::: items    # Half cores
parallel -j1 command ::: items      # Sequential
```

### Progress Feedback

```bash
parallel --progress command ::: items   # Progress bar
parallel --eta command ::: items        # ETA
parallel --verbose command ::: items    # Show commands
parallel --bar command ::: items        # Completion %
```

### Job Logging

```bash
parallel --joblog jobs.log command ::: items
parallel --resume --joblog jobs.log command ::: items
parallel --resume-failed --joblog jobs.log command ::: items
```

## Error Handling

### Halt Conditions

```bash
parallel --halt now,fail=1 command ::: items      # Stop on first failure
parallel --halt soon,fail=20% command ::: items   # Stop at 20% failures
parallel --halt never command ::: items           # Never stop (default)
parallel --halt now,success=1 grep pattern ::: files  # Stop on first success
```

### Retry and Timeout

```bash
parallel --retries 3 command ::: items    # Retry 3x
parallel --timeout 60 command ::: items   # 60s timeout
```

## Output Control

### Output Organization

```bash
parallel --keep-order command ::: items         # Preserve input order
parallel --group command ::: items              # No interleaving
parallel --tag command ::: items                # Tag with input
parallel --tagstring '{/.}:' command ::: *.txt  # Custom tag
```

### Output to Files

```bash
parallel --results output_dir command ::: items
parallel 'command {} > {/.}.out' ::: *.txt
```

## Remote Execution

```bash
parallel --sshlogin host1,host2 command ::: items
parallel --sshloginfile hosts.txt command ::: items
parallel --sshlogin :,host1,host2 command ::: items   # Include local
parallel --transferfile {} --sshlogin host command {} ::: files
parallel --return {}.out --sshlogin host 'command {} > {}.out' ::: files
```

## Advanced Patterns

### Semaphore Mode

```bash
for item in *; do
    sem -j4 command "$item"
done
sem --wait
```

### Complex Commands

```bash
parallel 'grep pattern {} | wc -l' ::: *.log

my_func() { echo "Processing $1"; }
export -f my_func
parallel my_func ::: items
```

### Batching

```bash
parallel -N3 echo ::: A B C D E F        # 3 items per job
parallel -N2 echo {1} and {2} ::: A B C D  # Paired
```

## Best Practices

### DO

- Use `--dry-run` to test before execution
- Use `--joblog` for long-running jobs
- Quote complex commands
- Use `--keep-order` when order matters
- Set reasonable `-j` limits for I/O-bound tasks

### DON'T

- Use for tasks with inter-dependencies
- Spawn more jobs than system can handle
- Forget error handling in batch jobs
- Omit `--no-run-if-empty` if input might be empty

## Troubleshooting

**Jobs not running in parallel**
```bash
parallel -j4 --verbose command ::: items
```

**Output interleaved**
```bash
parallel --group command ::: items
```

**Shell expansion issues**
```bash
parallel 'echo {} | wc -c' ::: items
```

## Quick Reference

See `quick-reference.md` for command reference.

## Examples

See `examples.md` for real-world patterns.
