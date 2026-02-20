# GoReleaser Configuration Reference

Full configuration options for `.goreleaser.yaml`.

## Version

```yaml
version: 2  # Config version (required for v2 features)
```

## Project Info

```yaml
project_name: myapp  # Defaults to directory name
```

## Before Hooks

```yaml
before:
  hooks:
    - go mod tidy
    - go generate ./...
    - ./scripts/pre-build.sh
```

## Builds

```yaml
builds:
  - id: myapp
    main: ./cmd/myapp
    binary: myapp
    dir: .

    # Build flags
    flags:
      - -trimpath
    ldflags:
      - -s -w
      - -X main.version={{.Version}}
      - -X main.commit={{.Commit}}
      - -X main.date={{.Date}}
    tags:
      - netgo

    # Environment
    env:
      - CGO_ENABLED=0

    # Targets
    goos:
      - linux
      - darwin
      - windows
    goarch:
      - amd64
      - arm64
      - arm
    goarm:
      - "7"
    goamd64:
      - v3

    # Ignore combinations
    ignore:
      - goos: darwin
        goarch: arm
      - goos: windows
        goarch: arm64

    # Hooks
    hooks:
      pre:
        - go generate ./...
      post:
        - upx --best {{ .Path }}

    # Build mode
    mod_timestamp: "{{ .CommitTimestamp }}"
    buildmode: default
```

## Archives

```yaml
archives:
  - id: default
    builds:
      - myapp

    # Format
    formats:
      - tar.gz
      - zip
    format_overrides:
      - goos: windows
        formats:
          - zip

    # Naming
    name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"

    # Files to include
    files:
      - LICENSE
      - README.md
      - CHANGELOG.md
      - completions/**/*
      - docs/*

    # Options
    wrap_in_directory: true
    strip_binary_directory: false
```

## Checksums

```yaml
checksum:
  name_template: "checksums.txt"
  algorithm: sha256
  extra_files:
    - glob: ./dist/*.sig
```

## Signing

```yaml
signs:
  - artifacts: checksum
    args:
      - "--batch"
      - "--local-user"
      - "{{ .Env.GPG_FINGERPRINT }}"
      - "--output"
      - "${signature}"
      - "--detach-sign"
      - "${artifact}"
```

## Changelog

```yaml
changelog:
  sort: asc
  use: github  # github, gitlab, github-native

  # Grouping
  groups:
    - title: Features
      regexp: "^.*feat[(\\w)]*:+.*$"
      order: 0
    - title: Bug Fixes
      regexp: "^.*fix[(\\w)]*:+.*$"
      order: 1
    - title: Documentation
      regexp: "^.*docs[(\\w)]*:+.*$"
      order: 2
    - title: Other
      order: 999

  # Filters
  filters:
    exclude:
      - "^docs:"
      - "^test:"
      - "^chore:"
      - "^ci:"
      - "Merge pull request"
      - "Merge branch"
```

## Release

```yaml
release:
  # GitHub/GitLab
  github:
    owner: myuser
    name: myrepo
  # gitlab:
  #   owner: myuser
  #   name: myrepo

  # Options
  draft: false
  prerelease: auto  # true, false, auto
  make_latest: true

  # Templates
  name_template: "v{{ .Version }}"
  header: |
    ## What's Changed

  footer: |
    **Full Changelog**: https://github.com/{{ .Env.GITHUB_REPOSITORY }}/compare/{{ .PreviousTag }}...{{ .Tag }}

  # Extra files
  extra_files:
    - glob: ./dist/*.sig
```

## Docker

```yaml
dockers:
  - id: amd64
    goos: linux
    goarch: amd64

    # Images
    image_templates:
      - "ghcr.io/myuser/myapp:{{ .Version }}-amd64"
      - "ghcr.io/myuser/myapp:latest-amd64"

    # Build
    dockerfile: Dockerfile
    use: docker
    build_flag_templates:
      - "--pull"
      - "--platform=linux/amd64"
      - "--label=org.opencontainers.image.title={{ .ProjectName }}"
      - "--label=org.opencontainers.image.version={{ .Version }}"

    # Files
    extra_files:
      - config.yaml
      - scripts/

  - id: arm64
    goos: linux
    goarch: arm64
    image_templates:
      - "ghcr.io/myuser/myapp:{{ .Version }}-arm64"
    dockerfile: Dockerfile
    build_flag_templates:
      - "--platform=linux/arm64"
```

## Docker Manifests

```yaml
docker_manifests:
  - name_template: "ghcr.io/myuser/myapp:{{ .Version }}"
    image_templates:
      - "ghcr.io/myuser/myapp:{{ .Version }}-amd64"
      - "ghcr.io/myuser/myapp:{{ .Version }}-arm64"

  - name_template: "ghcr.io/myuser/myapp:latest"
    image_templates:
      - "ghcr.io/myuser/myapp:latest-amd64"
      - "ghcr.io/myuser/myapp:latest-arm64"
```

## Homebrew

```yaml
brews:
  - name: myapp
    repository:
      owner: myuser
      name: homebrew-tap
      token: "{{ .Env.HOMEBREW_TAP_GITHUB_TOKEN }}"

    # Metadata
    homepage: "https://github.com/myuser/myapp"
    description: "My awesome CLI tool"
    license: "MIT"

    # Installation
    install: |
      bin.install "myapp"
      bash_completion.install "completions/myapp.bash" => "myapp"
      zsh_completion.install "completions/myapp.zsh" => "_myapp"

    # Testing
    test: |
      system "#{bin}/myapp", "--version"

    # Dependencies
    dependencies:
      - name: git
```

## Snapcraft

```yaml
snapcrafts:
  - name: myapp
    summary: My awesome CLI tool
    description: |
      Longer description of what myapp does.
    grade: stable
    confinement: strict
    license: MIT
    apps:
      myapp:
        command: myapp
        plugs: ["home", "network"]
```

## Scoop

```yaml
scoops:
  - repository:
      owner: myuser
      name: scoop-bucket
    homepage: "https://github.com/myuser/myapp"
    description: "My awesome CLI tool"
    license: MIT
```

## AUR

```yaml
aurs:
  - name: myapp-bin
    homepage: "https://github.com/myuser/myapp"
    description: "My awesome CLI tool"
    maintainers:
      - "User <user@example.com>"
    license: MIT
    private_key: "{{ .Env.AUR_KEY }}"
    git_url: "ssh://aur@aur.archlinux.org/myapp-bin.git"
```

## Announce

```yaml
announce:
  # Discord
  discord:
    enabled: true
    message_template: "{{ .ProjectName }} {{ .Tag }} is out! Check it out: {{ .ReleaseURL }}"

  # Slack
  slack:
    enabled: true
    channel: "#releases"
    message_template: "{{ .ProjectName }} {{ .Tag }} is out!"

  # Twitter
  twitter:
    enabled: true
    message_template: "{{ .ProjectName }} {{ .Tag }} is out!"
```

## Snapshot

```yaml
snapshot:
  version_template: "{{ incpatch .Version }}-next"
```

## Source

```yaml
source:
  enabled: true
  name_template: "{{ .ProjectName }}-{{ .Version }}"
  format: tar.gz
```

## SBOMs

```yaml
sboms:
  - artifacts: archive
    documents:
      - "${artifact}.sbom.json"
```

## Template Variables

| Variable | Description |
|----------|-------------|
| .Version | Version without v prefix |
| .Tag | Full tag (v1.0.0) |
| .ShortCommit | Short commit hash |
| .Commit | Full commit hash |
| .Date | Build date |
| .Timestamp | Unix timestamp |
| .ProjectName | Project name |
| .Os | Target OS |
| .Arch | Target arch |
| .Arm | ARM version |
| .Binary | Binary name |
| .Env.VAR | Environment variable |
| .PreviousTag | Previous git tag |
| .ReleaseURL | GitHub release URL |

## Functions

```yaml
# Available in templates
name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"

# String manipulation
"{{ .Name | tolower }}"
"{{ .Name | toupper }}"
"{{ .Name | title }}"
"{{ .Name | replace \" \" \"_\" }}"

# Version manipulation
"{{ incmajor .Version }}"  # 1.0.0 -> 2.0.0
"{{ incminor .Version }}"  # 1.0.0 -> 1.1.0
"{{ incpatch .Version }}"  # 1.0.0 -> 1.0.1

# Conditionals
"{{ if .IsSnapshot }}dev{{ else }}{{ .Version }}{{ end }}"
```
