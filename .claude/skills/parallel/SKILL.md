---
name: parallel
description: Execute shell jobs in parallel using GNU parallel. Use when: batch processing files, running same command on multiple inputs, CPU-intensive transforms, replacing slow loops. Triggers: "run in parallel", "batch process", "parallelize", "convert all images", "process files concurrently".
---

# GNU Parallel Skill

## Basic Usage

### Input Sources

**From arguments (:::)**
```bash
parallel echo ::: A B C
# Output: A, B, C (in parallel)
```

**From file (::::)**
```bash
parallel echo :::: items.txt
# Processes each line of items.txt
```

**From stdin (pipe)**
```bash
cat items.txt | parallel echo
# Same as above, via pipe
```

**Multiple input sources**
```bash
parallel echo ::: A B ::: 1 2
# Output: A 1, A 2, B 1, B 2 (cartesian product)
```

**Linked inputs (one-to-one)**
```bash
parallel --link echo ::: A B C ::: 1 2 3
# Output: A 1, B 2, C 3
```

### Basic Command Patterns

```bash
# Simple substitution
parallel gzip ::: *.txt

# With explicit placeholder
parallel echo "Processing {}" ::: *.log

# Command with options (4 jobs at a time)
parallel -j4 convert {} {.}.png ::: *.jpg
```

## Replacement Strings

| String | Description | Example Input | Result |
|--------|-------------|---------------|--------|
| `{}` | Full input | `/path/to/file.txt` | `/path/to/file.txt` |
| `{.}` | Without extension | `/path/to/file.txt` | `/path/to/file` |
| `{/}` | Basename | `/path/to/file.txt` | `file.txt` |
| `{//}` | Directory | `/path/to/file.txt` | `/path/to` |
| `{/.}` | Basename without ext | `/path/to/file.txt` | `file` |
| `{#}` | Job number | (3rd job) | `3` |
| `{%}` | Job slot number | (slot 2 of 4) | `2` |

### Replacement String Examples

```bash
# Convert maintaining directory structure
parallel convert {} {.}.png ::: images/*.jpg
# /images/photo.jpg -> /images/photo.png

# Output to different directory
parallel convert {} output/{/.}.png ::: images/*.jpg
# /images/photo.jpg -> output/photo.png

# Use job number for unique output
parallel 'echo {} > output_{#}.txt' ::: A B C
# Creates output_1.txt, output_2.txt, output_3.txt
```

### Custom Delimiters

```bash
# Tab-separated columns
parallel --colsep '\t' echo {1} {2} :::: data.tsv

# CSV processing
parallel --colsep ',' echo "Name: {1}, Age: {2}" :::: people.csv

# Multiple columns
parallel --colsep '\t' mv {1} {2} :::: rename_pairs.tsv
```

## Job Control

### Concurrency

```bash
# Limit to 4 parallel jobs
parallel -j4 command ::: items

# One job per CPU core (default)
parallel -j100% command ::: items

# Half the cores
parallel -j50% command ::: items

# Sequential (for testing)
parallel -j1 command ::: items
```

### Progress and Feedback

```bash
# Show progress bar
parallel --progress command ::: items

# Show ETA
parallel --eta command ::: items

# Verbose output
parallel --verbose command ::: items

# Show completed percentage
parallel --bar command ::: items
```

### Job Logging

```bash
# Log all jobs
parallel --joblog jobs.log command ::: items

# Resume from failed jobs
parallel --resume --joblog jobs.log command ::: items

# Resume and retry failed
parallel --resume-failed --joblog jobs.log command ::: items
```

## Error Handling

### Halt Conditions

```bash
# Stop on first failure
parallel --halt now,fail=1 command ::: items

# Stop after 20% failures
parallel --halt soon,fail=20% command ::: items

# Never stop (default)
parallel --halt never command ::: items

# Stop on success (find first match)
parallel --halt now,success=1 grep pattern ::: files
```

### Retry and Timeout

```bash
# Retry failed jobs 3 times
parallel --retries 3 command ::: items

# Kill jobs taking more than 60 seconds
parallel --timeout 60 command ::: items
```

## Output Control

### Output Organization

```bash
# Keep output order same as input
parallel --keep-order command ::: items

# Group output (don't interleave lines)
parallel --group command ::: items

# Tag output with input
parallel --tag command ::: items
# Output: item1\tresult1

# Tag with custom string
parallel --tagstring '{/.}:' command ::: *.txt
```

### Output to Files

```bash
# Results to individual files
parallel --results output_dir command ::: items

# Simple output files
parallel 'command {} > {/.}.out' ::: *.txt
```

## Remote Execution

```bash
# Run on remote hosts
parallel --sshlogin host1,host2 command ::: items

# From hosts file
parallel --sshloginfile hosts.txt command ::: items

# Include local machine
parallel --sshlogin :,host1,host2 command ::: items

# Transfer input files to remote
parallel --transferfile {} --sshlogin host command {} ::: files

# Return output files
parallel --return {}.out --sshlogin host 'command {} > {}.out' ::: files
```

## Advanced Patterns

### Semaphore Mode

```bash
# Use parallel as a semaphore for rate limiting
for item in *; do
    sem -j4 command "$item"
done
sem --wait
```

### Complex Commands

```bash
# Multi-command pipeline
parallel 'grep pattern {} | wc -l' ::: *.log

# With shell functions (export first)
my_func() { echo "Processing $1"; }
export -f my_func
parallel my_func ::: items
```

### Batching

```bash
# Process N items per job
parallel -N3 echo ::: A B C D E F
# Output: A B C, D E F

# With replacement
parallel -N2 echo {1} and {2} ::: A B C D
# Output: A and B, C and D
```

## Best Practices

### DO

- Use `--dry-run` to test commands before execution
- Use `--joblog` for long-running batch jobs
- Quote complex commands properly
- Use `--keep-order` when output order matters
- Set reasonable `-j` limits for I/O-bound tasks

### DON'T

- Don't use for tasks with inter-dependencies
- Don't spawn more jobs than the system can handle
- Don't forget to handle errors in batch jobs
- Don't use without `--no-run-if-empty` if input might be empty

## Troubleshooting

**Jobs not running in parallel**
```bash
# Check -j setting
parallel -j4 --verbose command ::: items
```

**Output interleaved**
```bash
# Use --group or --keep-order
parallel --group command ::: items
```

**Shell expansion issues**
```bash
# Quote the command
parallel 'echo {} | wc -c' ::: items
```

## Quick Reference

See `quick-reference.md` for a concise command reference.

## Examples

See `examples.md` for real-world usage patterns.

