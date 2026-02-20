#!/usr/bin/env python3
"""
Analyze existing IAC codebase and generate improvement suggestions.

Usage:
    python3 analyze_iac.py ./terraform
    python3 analyze_iac.py ./infrastructure --format json
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Finding:
    category: str
    severity: str  # info, warning, error
    message: str
    file: Optional[str] = None
    line: Optional[int] = None
    suggestion: Optional[str] = None


@dataclass
class AnalysisReport:
    root_path: str
    terraform_files: int = 0
    modules_found: list = field(default_factory=list)
    state_backend: Optional[str] = None
    provider_versions: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)

    def add_finding(self, finding: Finding):
        self.findings.append(finding)


def find_tf_files(root: Path) -> list:
    """Find all .tf files in directory."""
    return list(root.rglob("*.tf"))


def analyze_structure(report: AnalysisReport, root: Path) -> None:
    """Analyze project structure."""

    # Check for common directory patterns
    has_modules = (root / "modules").exists()
    has_environments = (root / "environments").exists()

    if not has_modules and report.terraform_files > 5:
        report.add_finding(Finding(
            category="structure",
            severity="warning",
            message="No modules/ directory found",
            suggestion="Consider organizing reusable code into modules/"
        ))

    if not has_environments and report.terraform_files > 10:
        report.add_finding(Finding(
            category="structure",
            severity="info",
            message="No environments/ directory found",
            suggestion="Consider separating environments into environments/ or using workspaces"
        ))

    # Check for monolithic files
    for tf_file in find_tf_files(root):
        line_count = len(tf_file.read_text().splitlines())
        if line_count > 500:
            report.add_finding(Finding(
                category="structure",
                severity="warning",
                file=str(tf_file.relative_to(root)),
                message=f"Large file ({line_count} lines)",
                suggestion="Consider splitting into smaller files or modules"
            ))


def analyze_state_config(report: AnalysisReport, root: Path) -> None:
    """Analyze state backend configuration."""

    backend_found = False

    for tf_file in find_tf_files(root):
        content = tf_file.read_text()

        # Check for backend configuration
        backend_match = re.search(r'backend\s+"(\w+)"', content)
        if backend_match:
            backend_found = True
            report.state_backend = backend_match.group(1)

        # Check for local state (no backend)
        if 'terraform {' in content and 'backend' not in content:
            if not backend_found:
                report.add_finding(Finding(
                    category="state",
                    severity="warning",
                    file=str(tf_file.relative_to(root)),
                    message="No remote backend configured",
                    suggestion="Configure remote backend (S3, GCS, Azure Blob, or Terraform Cloud)"
                ))

    # Check for state files in repo
    state_files = list(root.rglob("*.tfstate"))
    if state_files:
        report.add_finding(Finding(
            category="state",
            severity="error",
            message=f"State files found in repository: {[str(f.relative_to(root)) for f in state_files]}",
            suggestion="Remove state files from git and use remote backend"
        ))


def analyze_providers(report: AnalysisReport, root: Path) -> None:
    """Analyze provider configurations."""

    for tf_file in find_tf_files(root):
        content = tf_file.read_text()

        # Check for required_providers block
        provider_matches = re.findall(
            r'(\w+)\s*=\s*\{[^}]*source\s*=\s*"([^"]+)"[^}]*version\s*=\s*"([^"]+)"',
            content,
            re.DOTALL
        )

        for name, source, version in provider_matches:
            report.provider_versions[name] = {"source": source, "version": version}

        # Check for unpinned providers
        unpinned = re.findall(r'provider\s+"(\w+)"\s*\{(?![^}]*version)', content)
        for provider in unpinned:
            if provider not in report.provider_versions:
                report.add_finding(Finding(
                    category="providers",
                    severity="warning",
                    file=str(tf_file.relative_to(root)),
                    message=f"Provider '{provider}' version not pinned",
                    suggestion="Add version constraint in required_providers block"
                ))


def analyze_modules(report: AnalysisReport, root: Path) -> None:
    """Analyze module usage."""

    for tf_file in find_tf_files(root):
        content = tf_file.read_text()

        # Find module blocks
        module_matches = re.findall(
            r'module\s+"(\w+)"\s*\{[^}]*source\s*=\s*"([^"]+)"',
            content,
            re.DOTALL
        )

        for name, source in module_matches:
            report.modules_found.append({"name": name, "source": source})

            # Check for unversioned modules
            if "git::" in source or "github.com" in source:
                if "?ref=" not in source and "//=" not in source:
                    report.add_finding(Finding(
                        category="modules",
                        severity="warning",
                        file=str(tf_file.relative_to(root)),
                        message=f"Module '{name}' has no version pinned",
                        suggestion="Add ?ref=v1.0.0 to module source"
                    ))


def analyze_variables(report: AnalysisReport, root: Path) -> None:
    """Analyze variable definitions and usage."""

    for tf_file in find_tf_files(root):
        content = tf_file.read_text()

        # Check for variables without descriptions
        var_matches = re.findall(
            r'variable\s+"(\w+)"\s*\{([^}]*)\}',
            content,
            re.DOTALL
        )

        for name, body in var_matches:
            if "description" not in body:
                report.add_finding(Finding(
                    category="variables",
                    severity="info",
                    file=str(tf_file.relative_to(root)),
                    message=f"Variable '{name}' missing description",
                    suggestion="Add description for documentation"
                ))

            # Check for sensitive variables without sensitive flag
            if any(word in name.lower() for word in ["password", "secret", "key", "token"]):
                if "sensitive" not in body:
                    report.add_finding(Finding(
                        category="security",
                        severity="warning",
                        file=str(tf_file.relative_to(root)),
                        message=f"Variable '{name}' may contain sensitive data",
                        suggestion="Add sensitive = true to prevent value exposure"
                    ))


def analyze_outputs(report: AnalysisReport, root: Path) -> None:
    """Analyze output definitions."""

    for tf_file in find_tf_files(root):
        content = tf_file.read_text()

        # Check for outputs without descriptions
        output_matches = re.findall(
            r'output\s+"(\w+)"\s*\{([^}]*)\}',
            content,
            re.DOTALL
        )

        for name, body in output_matches:
            if "description" not in body:
                report.add_finding(Finding(
                    category="outputs",
                    severity="info",
                    file=str(tf_file.relative_to(root)),
                    message=f"Output '{name}' missing description",
                    suggestion="Add description for documentation"
                ))


def generate_text_report(report: AnalysisReport) -> str:
    """Generate human-readable report."""

    lines = [
        "=" * 60,
        "IAC Analysis Report",
        "=" * 60,
        "",
        f"Root path: {report.root_path}",
        f"Terraform files: {report.terraform_files}",
        f"State backend: {report.state_backend or 'Not configured'}",
        f"Modules found: {len(report.modules_found)}",
        "",
    ]

    if report.provider_versions:
        lines.append("Provider versions:")
        for name, info in report.provider_versions.items():
            lines.append(f"  - {name}: {info['version']}")
        lines.append("")

    # Group findings by severity
    errors = [f for f in report.findings if f.severity == "error"]
    warnings = [f for f in report.findings if f.severity == "warning"]
    info = [f for f in report.findings if f.severity == "info"]

    if errors:
        lines.append("ERRORS:")
        for finding in errors:
            lines.append(f"  [{finding.category}] {finding.message}")
            if finding.file:
                lines.append(f"    File: {finding.file}")
            if finding.suggestion:
                lines.append(f"    Fix: {finding.suggestion}")
        lines.append("")

    if warnings:
        lines.append("WARNINGS:")
        for finding in warnings:
            lines.append(f"  [{finding.category}] {finding.message}")
            if finding.file:
                lines.append(f"    File: {finding.file}")
            if finding.suggestion:
                lines.append(f"    Fix: {finding.suggestion}")
        lines.append("")

    if info:
        lines.append("INFO:")
        for finding in info:
            lines.append(f"  [{finding.category}] {finding.message}")
            if finding.file:
                lines.append(f"    File: {finding.file}")
            if finding.suggestion:
                lines.append(f"    Fix: {finding.suggestion}")
        lines.append("")

    lines.append("=" * 60)
    lines.append(f"Summary: {len(errors)} errors, {len(warnings)} warnings, {len(info)} info")
    lines.append("=" * 60)

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze IAC codebase and generate improvement suggestions"
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

    report = AnalysisReport(
        root_path=str(root),
        terraform_files=len(tf_files)
    )

    # Run analysis
    analyze_structure(report, root)
    analyze_state_config(report, root)
    analyze_providers(report, root)
    analyze_modules(report, root)
    analyze_variables(report, root)
    analyze_outputs(report, root)

    # Output
    if args.format == "json":
        # Convert dataclasses to dicts for JSON
        output = {
            "root_path": report.root_path,
            "terraform_files": report.terraform_files,
            "modules_found": report.modules_found,
            "state_backend": report.state_backend,
            "provider_versions": report.provider_versions,
            "findings": [asdict(f) for f in report.findings]
        }
        print(json.dumps(output, indent=2))
    else:
        print(generate_text_report(report))

    # Exit with error if there are errors
    if any(f.severity == "error" for f in report.findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
