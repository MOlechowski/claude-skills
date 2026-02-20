# GNU Parallel Examples

## File Conversion

### Images

```bash
parallel convert {} {.}.png ::: *.jpg
parallel convert {} -resize 800x600 resized/{/} ::: images/*.jpg
parallel cwebp -q 80 {} -o {.}.webp ::: *.png
parallel convert {} -thumbnail 150x150 thumbs/{/} ::: photos/*.jpg
```

### Videos

```bash
parallel ffmpeg -i {} -c:v libx264 {.}.mp4 ::: *.avi
parallel ffmpeg -i {} -vn -acodec mp3 {.}.mp3 ::: *.mp4
parallel ffmpeg -i {} -ss 00:00:05 -vframes 1 {.}.jpg ::: *.mp4
```

### Documents

```bash
parallel pandoc {} -o {.}.html ::: *.md
parallel pdftotext {} {.}.txt ::: *.pdf
parallel gs -sDEVICE=pdfwrite -dCompatibilityLevel=1.4 \
    -dPDFSETTINGS=/ebook -dNOPAUSE -dQUIET -dBATCH \
    -sOutputFile=compressed/{/} {} ::: *.pdf
```

## Data Processing

### CSV/JSON Files

```bash
parallel --colsep ',' 'echo "User: {1}, Email: {2}"' :::: users.csv
parallel 'jq .data {} > processed/{/.}_data.json' ::: *.json
parallel 'jq empty {} && echo "{}: valid" || echo "{}: invalid"' ::: *.json
```

### Logs

```bash
parallel 'echo "{/}: $(grep -c ERROR {})"' ::: logs/*.log
parallel 'grep -oP "\d{4}-\d{2}-\d{2}" {} | sort -u > {.}_dates.txt' ::: *.log
find logs/ -name "*.log" -mtime +30 | parallel gzip
```

### Text

```bash
parallel wc -w ::: *.txt | awk '{sum+=$1} END {print sum}'
parallel grep -l "TODO" ::: src/*.py
parallel sed -i 's/old/new/g' ::: *.txt
```

## Network Operations

### Downloads

```bash
parallel wget -q ::: url1 url2 url3
parallel wget -q :::: urls.txt
parallel --retries 3 'curl -sS {} > {#}.html' :::: urls.txt
parallel -j2 wget -q ::: urls  # Rate limited
```

### APIs

```bash
parallel 'curl -s "https://api.example.com/users/{}" > user_{}.json' ::: 1 2 3 4 5
parallel 'curl -X POST -d @{} https://api.example.com/submit' ::: data/*.json
parallel 'curl -s -o /dev/null -w "{}: %{http_code}\n" {}' ::: urls
```

## Build & Test

### Compile

```bash
parallel gcc -c {} -o {.}.o ::: *.c
parallel 'cd {} && make' ::: project1 project2 project3
```

### Test

```bash
parallel pytest {} ::: tests/test_*.py
parallel 'python{} -m pytest tests/' ::: 3.8 3.9 3.10 3.11
parallel --tag '{}' ::: 'eslint src/' 'prettier --check src/' 'tsc --noEmit'
```

### Docker

```bash
parallel docker build -t myapp:{} -f Dockerfile.{} . ::: dev staging prod
parallel docker pull ::: nginx:latest redis:latest postgres:latest
docker ps -q | parallel docker stop
```

## System Administration

### Files

```bash
parallel cp important.txt {} ::: /backup1 /backup2 /backup3
parallel rsync -av src/ {}/ ::: dest1 dest2
find /tmp -mtime +7 -type f | parallel rm
```

### Remote

```bash
parallel --sshlogin server1,server2,server3 'df -h'
parallel --sshlogin :,server1,server2 'cd /app && git pull && systemctl restart app'
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
parallel --joblog jobs.log convert {} {.}.png ::: *.jpg
parallel --resume --joblog jobs.log convert {} {.}.png ::: *.jpg
```

### Batching

```bash
parallel -N10 'echo "Batch: {}"' ::: {1..50}
parallel -N2 'echo "{1} vs {2}"' ::: A B C D E F
```

### Output

```bash
parallel --results results/ 'process {}' ::: items
parallel --tag 'wc -l {}' ::: *.txt
```
