#!/usr/bin/env python3
"""
Detect common IAC anti-patterns in Terraform/OpenTofu code.

Usage:
    python3 detect_antipatterns.py ./terraform
    python3 detect_antipatterns.py ./infrastructure --format json
"""

import argparse
import json
import re
import sys
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class AntiPattern:
    name: str
    severity: str  # low, medium, high, critical
    file: str
    line: int
    code: str
    problem: str
    fix: str


def find_tf_files(root: Path) -> list:
    """Find all .tf files in directory."""
    return list(root.rglob("*.tf"))


def check_hardcoded_values(root: Path) -> list:
    """Check for hardcoded values that should be variables."""

    patterns = []

    for tf_file in find_tf_files(root):
        content = tf_file.read_text()
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            # Skip comments and variable blocks
            if line.strip().startswith("#") or line.strip().startswith("//"):
                continue

            # Hardcoded AMI IDs
            if re.search(r'ami-[a-f0-9]{8,17}', line) and "var." not in line and "data." not in line:
                patterns.append(AntiPattern(
                    name="hardcoded-ami",
                    severity="medium",
                    file=str(tf_file.relative_to(root)),
                    line=i,
                    code=line.strip(),
                    problem="Hardcoded AMI ID",
                    fix="Use data.aws_ami or variable for AMI ID"
                ))

            # Hardcoded CIDR blocks
            if re.search(r'cidr_block\s*=\s*"[\d./]+"', line) and "var." not in line:
                patterns.append(AntiPattern(
                    name="hardcoded-cidr",
                    severity="low",
                    file=str(tf_file.relative_to(root)),
                    line=i,
                    code=line.strip(),
                    problem="Hardcoded CIDR block",
                    fix="Use variable for CIDR configuration"
                ))

            # Hardcoded account IDs
            if re.search(r'\d{12}', line) and "var." not in line:
                patterns.append(AntiPattern(
                    name="hardcoded-account-id",
                    severity="medium",
                    file=str(tf_file.relative_to(root)),
                    line=i,
                    code=line.strip(),
                    problem="Hardcoded AWS account ID",
                    fix="Use data.aws_caller_identity.current.account_id"
                ))

    return patterns


def check_security_issues(root: Path) -> list:
    """Check for security anti-patterns."""

    patterns = []

    for tf_file in find_tf_files(root):
        content = tf_file.read_text()
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            # Open security groups
            if "0.0.0.0/0" in line and ("ingress" in content[max(0, content.find(line)-200):content.find(line)+200].lower()):
                patterns.append(AntiPattern(
                    name="open-security-group",
                    severity="high",
                    file=str(tf_file.relative_to(root)),
                    line=i,
                    code=line.strip(),
                    problem="Security group allows ingress from 0.0.0.0/0",
                    fix="Restrict to specific CIDR blocks or security groups"
                ))

            # Wildcard IAM permissions
            if re.search(r'Action\s*=\s*\[?\s*"\*"', line) or re.search(r'"Action"\s*:\s*\[?\s*"\*"', line):
                patterns.append(AntiPattern(
                    name="wildcard-iam-action",
                    severity="critical",
                    file=str(tf_file.relative_to(root)),
                    line=i,
                    code=line.strip(),
                    problem="Wildcard IAM action grants excessive permissions",
                    fix="Specify explicit actions following least privilege"
                ))

            if re.search(r'Resource\s*=\s*\[?\s*"\*"', line) or re.search(r'"Resource"\s*:\s*\[?\s*"\*"', line):
                patterns.append(AntiPattern(
                    name="wildcard-iam-resource",
                    severity="high",
                    file=str(tf_file.relative_to(root)),
                    line=i,
                    code=line.strip(),
                    problem="Wildcard IAM resource is overly permissive",
                    fix="Specify explicit resource ARNs"
                ))

            # Secrets in code
            for keyword in ["password", "secret", "api_key", "token"]:
                if re.search(rf'{keyword}\s*=\s*"[^"$]{{8,}}"', line, re.IGNORECASE):
                    patterns.append(AntiPattern(
                        name="secret-in-code",
                        severity="critical",
                        file=str(tf_file.relative_to(root)),
                        line=i,
                        code=line.strip()[:50] + "...",  # Truncate to avoid exposing secret
                        problem=f"Potential secret ({keyword}) hardcoded in code",
                        fix="Use Vault, AWS Secrets Manager, or sensitive variables"
                    ))

            # Public S3 buckets
            if "acl" in line.lower() and "public" in line.lower():
                patterns.append(AntiPattern(
                    name="public-s3-bucket",
                    severity="critical",
                    file=str(tf_file.relative_to(root)),
                    line=i,
                    code=line.strip(),
                    problem="S3 bucket with public ACL",
                    fix="Use aws_s3_bucket_public_access_block to block public access"
                ))

            # Unencrypted storage
            if "encrypted" in line.lower() and "false" in line.lower():
                patterns.append(AntiPattern(
                    name="unencrypted-storage",
                    severity="high",
                    file=str(tf_file.relative_to(root)),
                    line=i,
                    code=line.strip(),
                    problem="Storage encryption disabled",
                    fix="Enable encryption at rest"
                ))

    return patterns


def check_scale_blockers(root: Path) -> list:
    """Check for patterns that will cause issues at scale."""

    patterns = []

    # Check for large files (potential monolithic state)
    for tf_file in find_tf_files(root):
        content = tf_file.read_text()
        lines = content.splitlines()
        resource_count = len(re.findall(r'^resource\s+"', content, re.MULTILINE))

        if resource_count > 50:
            patterns.append(AntiPattern(
                name="monolithic-config",
                severity="medium",
                file=str(tf_file.relative_to(root)),
                line=1,
                code=f"{resource_count} resources in single file",
                problem="Too many resources in single file",
                fix="Split into modules by domain or lifecycle"
            ))

        # Inline provider configuration in modules
        if "module" in str(tf_file):
            if re.search(r'provider\s+"\w+"\s*\{', content):
                patterns.append(AntiPattern(
                    name="inline-provider-in-module",
                    severity="medium",
                    file=str(tf_file.relative_to(root)),
                    line=1,
                    code="provider block in module",
                    problem="Provider configured inside module",
                    fix="Accept provider via providers argument"
                ))

        # Check for count instead of for_each with lists
        for i, line in enumerate(lines, 1):
            if re.search(r'count\s*=\s*length\(', line):
                patterns.append(AntiPattern(
                    name="count-with-length",
                    severity="low",
                    file=str(tf_file.relative_to(root)),
                    line=i,
                    code=line.strip(),
                    problem="Using count with length() can cause index issues",
                    fix="Use for_each with toset() for stable resource addressing"
                ))

    return patterns


def check_missing_features(root: Path) -> list:
    """Check for missing recommended features."""

    patterns = []

    # Check for lifecycle rules
    all_content = ""
    for tf_file in find_tf_files(root):
        all_content += tf_file.read_text()

    if "aws_db_instance" in all_content and "deletion_protection" not in all_content:
        patterns.append(AntiPattern(
            name="no-deletion-protection",
            severity="medium",
            file="(multiple files)",
            line=0,
            code="aws_db_instance without deletion_protection",
            problem="RDS instance without deletion protection",
            fix="Add deletion_protection = true for production databases"
        ))

    if "aws_s3_bucket" in all_content and "versioning" not in all_content:
        patterns.append(AntiPattern(
            name="no-s3-versioning",
            severity="low",
            file="(multiple files)",
            line=0,
            code="aws_s3_bucket without versioning",
            problem="S3 bucket without versioning enabled",
            fix="Add aws_s3_bucket_versioning resource"
        ))

    # Check for no tagging
    if re.search(r'resource\s+"aws_', all_content) and "tags" not in all_content:
        patterns.append(AntiPattern(
            name="no-tags",
            severity="medium",
            file="(multiple files)",
            line=0,
            code="AWS resources without tags",
            problem="Resources missing tags for cost allocation",
            fix="Add tags to all resources"
        ))

    return patterns


def generate_text_report(patterns: list, root: str) -> str:
    """Generate human-readable report."""

    lines = [
        "=" * 60,
        "Anti-Pattern Detection Report",
        "=" * 60,
        "",
        f"Scanned: {root}",
        f"Total issues found: {len(patterns)}",
        "",
    ]

    # Group by severity
    critical = [p for p in patterns if p.severity == "critical"]
    high = [p for p in patterns if p.severity == "high"]
    medium = [p for p in patterns if p.severity == "medium"]
    low = [p for p in patterns if p.severity == "low"]

    for severity, items in [("CRITICAL", critical), ("HIGH", high), ("MEDIUM", medium), ("LOW", low)]:
        if items:
            lines.append(f"{severity} ({len(items)}):")
            lines.append("-" * 40)
            for p in items:
                lines.append(f"  [{p.name}] {p.file}:{p.line}")
                lines.append(f"    Code: {p.code}")
                lines.append(f"    Problem: {p.problem}")
                lines.append(f"    Fix: {p.fix}")
                lines.append("")

    lines.append("=" * 60)
    lines.append(f"Summary: {len(critical)} critical, {len(high)} high, {len(medium)} medium, {len(low)} low")
    lines.append("=" * 60)

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Detect IAC anti-patterns"
    )
    parser.add_argument(
        "path",
        help="Path to IAC directory"
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format"
    )

    args = parser.parse_args()

    root = Path(args.path).resolve()

    if not root.exists():
        print(f"Error: Directory {root} does not exist")
        sys.exit(1)

    tf_files = find_tf_files(root)
    if not tf_files:
        print(f"Error: No .tf files found in {root}")
        sys.exit(1)

    # Run all checks
    patterns = []
    patterns.extend(check_hardcoded_values(root))
    patterns.extend(check_security_issues(root))
    patterns.extend(check_scale_blockers(root))
    patterns.extend(check_missing_features(root))

    # Output
    if args.format == "json":
        output = {
            "root": str(root),
            "issues": [asdict(p) for p in patterns],
            "summary": {
                "critical": len([p for p in patterns if p.severity == "critical"]),
                "high": len([p for p in patterns if p.severity == "high"]),
                "medium": len([p for p in patterns if p.severity == "medium"]),
                "low": len([p for p in patterns if p.severity == "low"]),
            }
        }
        print(json.dumps(output, indent=2))
    else:
        print(generate_text_report(patterns, str(root)))

    # Exit with error if there are critical issues
    if any(p.severity == "critical" for p in patterns):
        sys.exit(1)


if __name__ == "__main__":
    main()
