# GNU Parallel Examples

## File Conversion

### Image Processing

```bash
# Convert JPG to PNG
parallel convert {} {.}.png ::: *.jpg

# Resize images
parallel convert {} -resize 800x600 resized/{/} ::: images/*.jpg

# Convert to WebP with quality
parallel cwebp -q 80 {} -o {.}.webp ::: *.png

# Batch thumbnails
parallel convert {} -thumbnail 150x150 thumbs/{/} ::: photos/*.jpg
```

### Video Processing

```bash
# Transcode videos
parallel ffmpeg -i {} -c:v libx264 {.}.mp4 ::: *.avi

# Extract audio
parallel ffmpeg -i {} -vn -acodec mp3 {.}.mp3 ::: *.mp4

# Generate thumbnails from videos
parallel ffmpeg -i {} -ss 00:00:05 -vframes 1 {.}.jpg ::: *.mp4
```

### Document Conversion

```bash
# Markdown to HTML
parallel pandoc {} -o {.}.html ::: *.md

# PDF to text
parallel pdftotext {} {.}.txt ::: *.pdf

# Compress PDFs
parallel gs -sDEVICE=pdfwrite -dCompatibilityLevel=1.4 \
    -dPDFSETTINGS=/ebook -dNOPAUSE -dQUIET -dBATCH \
    -sOutputFile=compressed/{/} {} ::: *.pdf
```

## Data Processing

### CSV/JSON

```bash
# Process CSV rows
parallel --colsep ',' 'echo "User: {1}, Email: {2}"' :::: users.csv

# Convert JSON files
parallel 'jq .data {} > processed/{/.}_data.json' ::: *.json

# Validate JSON
parallel 'jq empty {} && echo "{}: valid" || echo "{}: invalid"' ::: *.json
```

### Log Processing

```bash
# Count errors per log
parallel 'echo "{/}: $(grep -c ERROR {})"' ::: logs/*.log

# Extract timestamps
parallel 'grep -oP "\d{4}-\d{2}-\d{2}" {} | sort -u > {.}_dates.txt' ::: *.log

# Compress old logs
find logs/ -name "*.log" -mtime +30 | parallel gzip
```

### Text Processing

```bash
# Word count
parallel wc -w ::: *.txt | awk '{sum+=$1} END {print sum}'

# Find pattern in files
parallel grep -l "TODO" ::: src/*.py

# Replace in files
parallel sed -i 's/old/new/g' ::: *.txt
```

## Network Operations

### Downloads

```bash
# Download URLs
parallel wget -q ::: url1 url2 url3

# Download from file
parallel wget -q :::: urls.txt

# Parallel curl with retry
parallel --retries 3 'curl -sS {} > {#}.html' :::: urls.txt

# Download with rate limit (2 concurrent)
parallel -j2 wget -q ::: urls
```

### API Calls

```bash
# Fetch API data
parallel 'curl -s "https://api.example.com/users/{}" > user_{}.json' ::: 1 2 3 4 5

# POST requests
parallel 'curl -X POST -d @{} https://api.example.com/submit' ::: data/*.json

# Health checks
parallel 'curl -s -o /dev/null -w "{}: %{http_code}\n" {}' ::: urls
```

## Build & Test

### Compilation

```bash
# Compile C files
parallel gcc -c {} -o {.}.o ::: *.c

# Build multiple projects
parallel 'cd {} && make' ::: project1 project2 project3
```

### Testing

```bash
# Run tests in parallel
parallel pytest {} ::: tests/test_*.py

# Test multiple Python versions
parallel 'python{} -m pytest tests/' ::: 3.8 3.9 3.10 3.11

# Run linters
parallel --tag '{}' ::: 'eslint src/' 'prettier --check src/' 'tsc --noEmit'
```

### Docker

```bash
# Build multiple images
parallel docker build -t myapp:{} -f Dockerfile.{} . ::: dev staging prod

# Pull images
parallel docker pull ::: nginx:latest redis:latest postgres:latest

# Stop containers
docker ps -q | parallel docker stop
```

## System Administration

### File Operations

```bash
# Copy to multiple destinations
parallel cp important.txt {} ::: /backup1 /backup2 /backup3

# Sync directories
parallel rsync -av src/ {}/ ::: dest1 dest2

# Find and delete old files
find /tmp -mtime +7 -type f | parallel rm
```

### Remote Execution

```bash
# Run command on multiple servers
parallel --sshlogin server1,server2,server3 'df -h'

# Deploy to servers
parallel --sshlogin :,server1,server2 'cd /app && git pull && systemctl restart app'

# Collect logs from servers
parallel --sshlogin server1,server2 --return /var/log/app.log \
    'cat /var/log/app.log' ::: ignored
```

## Advanced Patterns

### With Progress Tracking

```bash
# Long job with progress
parallel --progress --eta 'sleep 1 && echo done: {}' ::: {1..100}
```

### Resume Interrupted Jobs

```bash
# Start with logging
parallel --joblog jobs.log convert {} {.}.png ::: *.jpg

# Resume if interrupted
parallel --resume --joblog jobs.log convert {} {.}.png ::: *.jpg
```

### Batching Items

```bash
# Process 10 items per job
parallel -N10 'echo "Batch: {}"' ::: {1..50}

# Paired processing
parallel -N2 'echo "{1} vs {2}"' ::: A B C D E F
```

### Output Organization

```bash
# Structured output directory
parallel --results results/ 'process {}' ::: items

# Tagged output
parallel --tag 'wc -l {}' ::: *.txt
```
