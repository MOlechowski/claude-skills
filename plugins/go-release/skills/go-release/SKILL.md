---
name: go-release
description: "[Go] Release automation: cross-compilation, archives, checksums, changelogs, GitHub/GitLab releases, Docker images, Homebrew. Use for: releasing Go binaries, CI/CD release pipelines. Triggers: goreleaser, go release, cross compile, release binary."
---

# GoReleaser

Release automation for Go projects.

## Installation

```bash
# macOS
brew install goreleaser

# Go install
go install github.com/goreleaser/goreleaser@latest

# Download binary
curl -sfL https://goreleaser.com/static/run | bash
```

## Quick Start

```bash
# Initialize config
goreleaser init

# Build snapshot (no release)
goreleaser build --snapshot --clean

# Test release locally
goreleaser release --snapshot --clean

# Actual release (needs GITHUB_TOKEN)
goreleaser release --clean
```

## Minimal Configuration

```yaml
# .goreleaser.yaml
version: 2

builds:
  - env:
      - CGO_ENABLED=0
    goos:
      - linux
      - darwin
      - windows
    goarch:
      - amd64
      - arm64

archives:
  - formats:
      - tar.gz
    name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"

checksum:
  name_template: 'checksums.txt'

changelog:
  sort: asc
  filters:
    exclude:
      - '^docs:'
      - '^test:'
```

## Build Configuration

### Basic Build

```yaml
builds:
  - main: ./cmd/myapp
    binary: myapp
    env:
      - CGO_ENABLED=0
    ldflags:
      - -s -w
      - -X main.version={{.Version}}
      - -X main.commit={{.Commit}}
    goos:
      - linux
      - darwin
      - windows
    goarch:
      - amd64
      - arm64
```

### Multiple Binaries

```yaml
builds:
  - id: cli
    main: ./cmd/cli
    binary: myapp
    goos: [linux, darwin, windows]
    goarch: [amd64, arm64]

  - id: server
    main: ./cmd/server
    binary: myapp-server
    goos: [linux]
    goarch: [amd64]
```

### Build Hooks

```yaml
builds:
  - main: ./cmd/myapp
    hooks:
      pre:
        - go generate ./...
      post:
        - upx {{ .Path }}
```

## Archives

```yaml
archives:
  - id: default
    formats:
      - tar.gz
      - zip
    format_overrides:
      - goos: windows
        formats:
          - zip
    name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
    files:
      - README.md
      - LICENSE
      - completions/*
```

## Checksums

```yaml
checksum:
  name_template: 'checksums.txt'
  algorithm: sha256
```

## Changelog

```yaml
changelog:
  sort: asc
  use: github
  groups:
    - title: Features
      regexp: "^feat"
    - title: Bug Fixes
      regexp: "^fix"
    - title: Documentation
      regexp: "^docs"
  filters:
    exclude:
      - '^chore:'
      - '^ci:'
      - Merge pull request
```

## GitHub/GitLab Releases

### GitHub

```yaml
release:
  github:
    owner: myuser
    name: myrepo
  draft: false
  prerelease: auto
  name_template: "v{{ .Version }}"
  header: |
    ## What's Changed
  footer: |
    **Full Changelog**: https://github.com/myuser/myrepo/compare/{{ .PreviousTag }}...{{ .Tag }}
```

### GitLab

```yaml
release:
  gitlab:
    owner: myuser
    name: myrepo
```

## Docker Images

```yaml
dockers:
  - image_templates:
      - "ghcr.io/myuser/myapp:{{ .Version }}"
      - "ghcr.io/myuser/myapp:latest"
    dockerfile: Dockerfile
    build_flag_templates:
      - "--platform=linux/amd64"
    extra_files:
      - config.yaml

  - image_templates:
      - "ghcr.io/myuser/myapp:{{ .Version }}-arm64"
    dockerfile: Dockerfile
    goarch: arm64
    build_flag_templates:
      - "--platform=linux/arm64"
```

### Multi-Platform Manifest

```yaml
docker_manifests:
  - name_template: "ghcr.io/myuser/myapp:{{ .Version }}"
    image_templates:
      - "ghcr.io/myuser/myapp:{{ .Version }}-amd64"
      - "ghcr.io/myuser/myapp:{{ .Version }}-arm64"
```

## Homebrew

```yaml
brews:
  - repository:
      owner: myuser
      name: homebrew-tap
    name: myapp
    homepage: https://github.com/myuser/myapp
    description: "My awesome CLI tool"
    license: MIT
    install: |
      bin.install "myapp"
      bash_completion.install "completions/myapp.bash"
      zsh_completion.install "completions/myapp.zsh"
    test: |
      system "#{bin}/myapp", "--version"
```

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write
  packages: write

jobs:
  goreleaser:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Login to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Run GoReleaser
        uses: goreleaser/goreleaser-action@v5
        with:
          version: latest
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### GitLab CI

```yaml
release:
  stage: release
  image: goreleaser/goreleaser
  only:
    - tags
  script:
    - goreleaser release --clean
  variables:
    GITLAB_TOKEN: $CI_JOB_TOKEN
```

## Common Commands

```bash
# Check config
goreleaser check

# Build only (no release)
goreleaser build --snapshot --clean

# Local release test
goreleaser release --snapshot --clean

# Release (requires tag)
git tag v1.0.0
git push origin v1.0.0
goreleaser release --clean

# Skip parts
goreleaser release --skip=publish --skip=docker
```

## Template Variables

| Variable | Example |
|----------|---------|
| .Version | 1.0.0 |
| .Tag | v1.0.0 |
| .ShortCommit | abc1234 |
| .Commit | abc1234... |
| .Date | 2024-01-15 |
| .ProjectName | myapp |
| .Os | linux |
| .Arch | amd64 |
| .Arm | 7 |
| .Binary | myapp |

## Full Configuration Example

```yaml
version: 2

before:
  hooks:
    - go mod tidy
    - go generate ./...

builds:
  - main: ./cmd/myapp
    env:
      - CGO_ENABLED=0
    ldflags:
      - -s -w -X main.version={{.Version}}
    goos:
      - linux
      - darwin
      - windows
    goarch:
      - amd64
      - arm64
    ignore:
      - goos: windows
        goarch: arm64

archives:
  - formats:
      - tar.gz
    format_overrides:
      - goos: windows
        formats:
          - zip
    files:
      - LICENSE
      - README.md

checksum:
  name_template: 'checksums.txt'

snapshot:
  version_template: "{{ incpatch .Version }}-next"

changelog:
  sort: asc
  filters:
    exclude:
      - '^docs:'
      - '^test:'
      - '^chore:'

release:
  draft: false
  prerelease: auto
```

See [references/config.md](references/config.md) for full configuration options.
