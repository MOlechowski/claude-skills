---
name: parallel
description: |
  Expert guidance for GNU parallel, a shell tool for executing jobs in parallel.

  Use this skill when:
  - Running the same command on multiple files/inputs
  - Parallelizing shell pipelines
  - Batch processing with controlled concurrency
  - Replacing slow sequential loops with parallel execution

  Examples:
  - "convert all images in parallel"
  - "run this command on each file concurrently"
  - "parallelize this loop"
  - "process CSV files with GNU parallel"
---

# GNU Parallel Skill

You are an expert in GNU parallel, the shell tool for executing jobs in parallel using one or more computers.

## Core Capabilities

1. Execute commands in parallel across multiple inputs
2. Control concurrency with job slots
3. Use replacement strings for flexible command construction
4. Process input from arguments, files, or stdin
5. Distribute jobs across remote machines
6. Track progress and maintain job logs

## Overview

GNU parallel is a shell tool for executing jobs in parallel. It can:
- Replace `xargs` with parallel execution
- Replace shell loops with parallel processing
- Distribute work across multiple machines
- Handle complex input/output patterns

### When to Use

- Processing multiple files with the same command
- Batch operations that are I/O or CPU bound
- Replacing sequential `for` loops
- Distributing work across cores or machines

### When NOT to Use

- Tasks with dependencies between items
- Operations requiring strict ordering
- Single-item operations
- Tasks where overhead exceeds benefit

## Installation

```bash
# macOS
brew install parallel

# Debian/Ubuntu
sudo apt install parallel

# RHEL/CentOS
sudo yum install parallel

# Verify installation
parallel --version
```

**Note:** Conflicts with `moreutils` package (both provide `parallel`). Install moreutils without parallel: `brew install moreutils --without-parallel`

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

**Simple substitution**
```bash
parallel gzip ::: *.txt
# Runs: gzip file1.txt, gzip file2.txt, ...
```

**With explicit placeholder**
```bash
parallel echo "Processing {}" ::: *.log
```

**Command with options**
```bash
parallel -j4 convert {} {.}.png ::: *.jpg
# Convert jpg to png, 4 jobs at a time
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
# /images/photo.jpg → /images/photo.png

# Output to different directory
parallel convert {} output/{/.}.png ::: images/*.jpg
# /images/photo.jpg → output/photo.png

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

**Job log format:**
```
Seq  Host  Starttime       JobRuntime  Send  Receive  Exitval  Signal  Command
1    :     1642000000.000  1.234       0     100      0        0       command item1
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

### Retry Logic

```bash
# Retry failed jobs 3 times
parallel --retries 3 command ::: items

# Retry with delay
parallel --retries 3 --delay 5 command ::: items
```

### Timeout

```bash
# Kill jobs taking more than 60 seconds
parallel --timeout 60 command ::: items

# Timeout with signal
parallel --timeout 60 --termseq INT,1000,TERM,2000,KILL command ::: items
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
# Creates: output_dir/1/item1/stdout, output_dir/1/item1/stderr

# Simple output files
parallel 'command {} > {/.}.out' ::: *.txt
```

## Remote Execution

### SSH Distribution

```bash
# Run on remote hosts
parallel --sshlogin host1,host2 command ::: items

# With login details
parallel --sshlogin user@host1,user@host2 command ::: items

# From hosts file
parallel --sshloginfile hosts.txt command ::: items

# Include local machine
parallel --sshlogin :,host1,host2 command ::: items
```

### File Transfer

```bash
# Transfer input files to remote
parallel --transferfile {} --sshlogin host command {} ::: files

# Return output files
parallel --return {}.out --sshlogin host 'command {} > {}.out' ::: files

# Cleanup remote files after
parallel --cleanup --transferfile {} --return {}.out --sshlogin host command ::: files
```

## Integration with Other Tools

### With find

```bash
# Process found files
find . -name "*.log" | parallel gzip

# Using find's -exec replacement
find . -name "*.jpg" -print0 | parallel -0 convert {} {.}.png
```

### With xargs Comparison

```bash
# xargs (sequential by default)
cat files.txt | xargs -I{} command {}

# xargs parallel
cat files.txt | xargs -P4 -I{} command {}

# GNU parallel (parallel by default, more features)
cat files.txt | parallel command {}
```

### Piping and Chaining

```bash
# Pipe output to another parallel
parallel command1 ::: items | parallel command2

# Process and aggregate
parallel grep pattern ::: *.log | sort | uniq -c
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

### Conditional Execution

```bash
# Only run if file exists
parallel '[ -f {} ] && command {}' ::: items

# Skip empty inputs
parallel --no-run-if-empty command ::: possibly_empty_list
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

### Tips

1. **Test first:** `parallel --dry-run command ::: items`
2. **Debug:** `parallel --verbose command ::: items`
3. **Resume interrupted jobs:** Use `--joblog` and `--resume`
4. **Memory-bound tasks:** Limit with `-j` based on memory, not cores
5. **Citation:** First run shows citation notice; use `parallel --citation` to silence

## Troubleshooting

### Common Issues

**"parallel: command not found"**
```bash
brew install parallel  # macOS
apt install parallel   # Debian/Ubuntu
```

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

## Resources

- [GNU Parallel Manual](https://www.gnu.org/software/parallel/man.html)
- [GNU Parallel Tutorial](https://www.gnu.org/software/parallel/parallel_tutorial.html)
- [Ole Tange's Book](https://doi.org/10.5281/zenodo.1146014)
