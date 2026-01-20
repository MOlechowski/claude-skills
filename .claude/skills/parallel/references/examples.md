# GNU Parallel Examples

## File Conversion

### Images

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

### Videos

```bash
# Transcode videos
parallel ffmpeg -i {} -c:v libx264 {.}.mp4 ::: *.avi

# Extract audio
parallel ffmpeg -i {} -vn -acodec mp3 {.}.mp3 ::: *.mp4

# Generate thumbnails from videos
parallel ffmpeg -i {} -ss 00:00:05 -vframes 1 {.}.jpg ::: *.mp4
```

### Documents

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

### CSV/JSON Files

```bash
# Process CSV rows
parallel --colsep ',' 'echo "User: {1}, Email: {2}"' :::: users.csv

# Convert JSON files
parallel 'jq .data {} > processed/{/.}_data.json' ::: *.json

# Validate JSON
parallel 'jq empty {} && echo "{}: valid" || echo "{}: invalid"' ::: *.json
```

### Logs

```bash
# Count errors
parallel 'echo "{/}: $(grep -c ERROR {})"' ::: logs/*.log

# Extract timestamps
parallel 'grep -oP "\d{4}-\d{2}-\d{2}" {} | sort -u > {.}_dates.txt' ::: *.log

# Compress old
find logs/ -name "*.log" -mtime +30 | parallel gzip
```

### Text

```bash
# Total word count
parallel wc -w ::: *.txt | awk '{sum+=$1} END {print sum}'

# Find pattern
parallel grep -l "TODO" ::: src/*.py

# Replace
parallel sed -i 's/old/new/g' ::: *.txt
```

## Network Operations

### Downloads

```bash
# URLs
parallel wget -q ::: url1 url2 url3

# From file
parallel wget -q :::: urls.txt

# Curl with retry
parallel --retries 3 'curl -sS {} > {#}.html' :::: urls.txt

# Rate limit (2 concurrent)
parallel -j2 wget -q ::: urls
```

### APIs

```bash
# Fetch data
parallel 'curl -s "https://api.example.com/users/{}" > user_{}.json' ::: 1 2 3 4 5

# POST
parallel 'curl -X POST -d @{} https://api.example.com/submit' ::: data/*.json

# Health checks
parallel 'curl -s -o /dev/null -w "{}: %{http_code}\n" {}' ::: urls
```

## Build & Test

### Compile

```bash
# C files
parallel gcc -c {} -o {.}.o ::: *.c

# Multiple projects
parallel 'cd {} && make' ::: project1 project2 project3
```

### Test

```bash
# Run tests
parallel pytest {} ::: tests/test_*.py

# Multiple Python versions
parallel 'python{} -m pytest tests/' ::: 3.8 3.9 3.10 3.11

# Linters
parallel --tag '{}' ::: 'eslint src/' 'prettier --check src/' 'tsc --noEmit'
```

### Docker

```bash
# Build images
parallel docker build -t myapp:{} -f Dockerfile.{} . ::: dev staging prod

# Pull
parallel docker pull ::: nginx:latest redis:latest postgres:latest

# Stop
docker ps -q | parallel docker stop
```

## System Administration

### Files

```bash
# Copy to multiple destinations
parallel cp important.txt {} ::: /backup1 /backup2 /backup3

# Sync directories
parallel rsync -av src/ {}/ ::: dest1 dest2

# Delete old files
find /tmp -mtime +7 -type f | parallel rm
```

### Remote

```bash
# Run on servers
parallel --sshlogin server1,server2,server3 'df -h'

# Deploy
parallel --sshlogin :,server1,server2 'cd /app && git pull && systemctl restart app'

# Collect logs
parallel --sshlogin server1,server2 --return /var/log/app.log \
    'cat /var/log/app.log' ::: ignored
```

## Advanced Patterns

### Progress Tracking

```bash
parallel --progress --eta 'sleep 1 && echo done: {}' ::: {1..100}
```

### Resume Jobs

```bash
# Start with log
parallel --joblog jobs.log convert {} {.}.png ::: *.jpg

# Resume
parallel --resume --joblog jobs.log convert {} {.}.png ::: *.jpg
```

### Batching

```bash
# 10 items per job
parallel -N10 'echo "Batch: {}"' ::: {1..50}

# Paired
parallel -N2 'echo "{1} vs {2}"' ::: A B C D E F
```

### Output

```bash
# Structured directory
parallel --results results/ 'process {}' ::: items

# Tagged
parallel --tag 'wc -l {}' ::: *.txt
```
