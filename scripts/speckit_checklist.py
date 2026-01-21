#!/usr/bin/env python3
"""
speckit_checklist.py - Phase 6: CHECKLIST

Generates domain-specific quality checklists based on spec content.

Usage:
    speckit_checklist.py [OPTIONS]

Options:
    --type <type>    Force specific checklist type (api, ux, security, performance, general)
    --json           Output in JSON format
    --help, -h       Show this help message

Examples:
    speckit_checklist.py
    speckit_checklist.py --type api
    speckit_checklist.py --json
"""

import sys
import json
import re
import argparse
from pathlib import Path

# Add scripts directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from common import (
    Status,
    EXIT_SUCCESS,
    EXIT_VALIDATION_ERROR,
    EXIT_MISSING_PREREQ,
    log_phase,
    validate_prerequisites,
    load_template
)


# Domain keyword mappings
CHECKLIST_KEYWORDS = {
    "api": ["api", "endpoint", "rest", "graphql", "http", "request", "response", "route"],
    "ux": ["ui", "ux", "interface", "frontend", "user experience", "component", "page", "form", "button"],
    "security": ["auth", "security", "permission", "token", "password", "login", "role", "access"],
    "performance": ["performance", "latency", "throughput", "cache", "optimize", "speed", "load"]
}

# Checklist templates for each domain
CHECKLIST_TEMPLATES = {
    "api": """# API Checklist

## Endpoints
- [ ] All endpoints documented
- [ ] Request/response schemas defined
- [ ] Error responses specified
- [ ] Authentication requirements clear

## Data Validation
- [ ] Input validation rules defined
- [ ] Required vs optional fields specified
- [ ] Data types documented

## Error Handling
- [ ] Error codes defined
- [ ] Error message format consistent
- [ ] Edge cases covered

## Testing
- [ ] Happy path tests planned
- [ ] Error case tests planned
- [ ] Integration tests planned
""",

    "ux": """# UX Checklist

## User Interface
- [ ] All screens/pages identified
- [ ] Navigation flow documented
- [ ] Responsive design considered

## User Experience
- [ ] User journey mapped
- [ ] Error states designed
- [ ] Loading states designed
- [ ] Empty states designed

## Accessibility
- [ ] Keyboard navigation
- [ ] Screen reader support
- [ ] Color contrast
- [ ] Focus indicators

## Testing
- [ ] Usability testing planned
- [ ] Cross-browser testing
- [ ] Mobile testing
""",

    "security": """# Security Checklist

## Authentication
- [ ] Auth method specified (JWT, OAuth, etc.)
- [ ] Session management defined
- [ ] Password requirements documented

## Authorization
- [ ] Role definitions clear
- [ ] Permission model documented
- [ ] Access control rules defined

## Data Protection
- [ ] Sensitive data identified
- [ ] Encryption requirements specified
- [ ] Data retention policy defined

## Testing
- [ ] Security testing planned
- [ ] Penetration testing scope
- [ ] Vulnerability scanning
""",

    "performance": """# Performance Checklist

## Requirements
- [ ] Response time targets defined
- [ ] Throughput requirements specified
- [ ] Concurrent user estimates

## Optimization
- [ ] Caching strategy defined
- [ ] Database query optimization
- [ ] Asset optimization (images, JS, CSS)

## Monitoring
- [ ] Performance metrics identified
- [ ] Alerting thresholds defined
- [ ] Profiling approach planned

## Testing
- [ ] Load testing planned
- [ ] Stress testing scope
- [ ] Performance benchmarks defined
""",

    "general": """# General Quality Checklist

## Requirements
- [ ] All requirements documented
- [ ] Acceptance criteria defined
- [ ] Edge cases identified

## Design
- [ ] Architecture documented
- [ ] Dependencies identified
- [ ] Integration points clear

## Implementation
- [ ] Code structure planned
- [ ] Coding standards defined
- [ ] Documentation requirements

## Testing
- [ ] Unit tests planned
- [ ] Integration tests planned
- [ ] Acceptance tests planned
"""
}


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Phase 6: CHECKLIST - Generate quality checklists",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Checklist Types:
    api         - API/endpoint specific checks
    ux          - User interface/experience checks
    security    - Security/auth checks
    performance - Performance/optimization checks
    general     - General quality checks

Examples:
    %(prog)s
    %(prog)s --type api
    %(prog)s --json
"""
    )
    parser.add_argument(
        "--type",
        choices=["api", "ux", "security", "performance", "general"],
        help="Force specific checklist type"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format"
    )

    return parser.parse_args()


def detect_checklist_types(content: str) -> list:
    """
    Scan content for domain keywords to determine checklist types.

    Returns list of detected checklist types.
    """
    detected = []
    content_lower = content.lower()

    for checklist_type, keywords in CHECKLIST_KEYWORDS.items():
        # Count keyword matches
        match_count = sum(1 for kw in keywords if kw in content_lower)
        if match_count >= 2:  # Require at least 2 keyword matches
            detected.append({
                "type": checklist_type,
                "confidence": min(match_count / len(keywords), 1.0)
            })

    # Sort by confidence
    detected.sort(key=lambda x: x["confidence"], reverse=True)

    # Always include general if no specific matches
    if not detected:
        detected.append({"type": "general", "confidence": 1.0})

    return detected


def execute_phase(args, paths: dict) -> dict:
    """
    Execute Phase 6: CHECKLIST.

    Generates quality checklists based on spec content.
    """
    log_phase(6, "CHECKLIST", "start")

    feature_dir = Path(paths.get("FEATURE_DIR", ""))
    spec_file = feature_dir / "spec.md"

    if not spec_file.exists():
        log_phase(6, "CHECKLIST", "error")
        return {
            "status": "error",
            "phase": 6,
            "error": f"spec.md not found: {spec_file}"
        }

    content = spec_file.read_text()

    # Determine checklist types
    if args.type:
        checklist_types = [{"type": args.type, "confidence": 1.0}]
        print(f"  {Status.INFO} Using specified type: {args.type}")
    else:
        print(f"  {Status.RUNNING} Detecting checklist types from spec...")
        checklist_types = detect_checklist_types(content)
        type_names = [ct["type"] for ct in checklist_types]
        print(f"  {Status.INFO} Detected types: {', '.join(type_names)}")

    # Create checklists directory
    checklists_dir = feature_dir / "checklists"
    checklists_dir.mkdir(exist_ok=True)

    # Generate checklists
    created_files = []
    for ct in checklist_types:
        checklist_type = ct["type"]
        template_content = CHECKLIST_TEMPLATES.get(checklist_type, CHECKLIST_TEMPLATES["general"])

        # Try to load custom template first
        custom_template = load_template(f"checklist-{checklist_type}-template.md")
        if custom_template:
            template_content = custom_template

        checklist_file = checklists_dir / f"checklist-{checklist_type}.md"

        try:
            checklist_file.write_text(template_content)
            created_files.append(str(checklist_file))
            print(f"  {Status.SUCCESS} Created: checklist-{checklist_type}.md")
        except Exception as e:
            print(f"  {Status.WARNING} Failed to create checklist-{checklist_type}.md: {e}")

    log_phase(6, "CHECKLIST", "complete")

    return {
        "status": "complete",
        "phase": 6,
        "checklists_created": len(created_files),
        "checklist_types": [ct["type"] for ct in checklist_types],
        "files": created_files
    }


def main():
    args = parse_args()

    # Validate prerequisites
    validation = validate_prerequisites(require_tasks=False)
    if not validation["valid"]:
        print(f"{Status.ERROR} {validation['error']}")
        sys.exit(EXIT_MISSING_PREREQ)

    paths = validation["paths"]
    print(f"{Status.RUNNING} Generating quality checklists...")

    result = execute_phase(args, paths)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["status"] == "complete":
            print(f"\n{Status.SUCCESS} Phase 6 complete: CHECKLIST")
            print(f"  Checklists created: {result['checklists_created']}")
            print(f"  Types: {', '.join(result['checklist_types'])}")
            print(f"\n{Status.INFO} Next: Run speckit_pr.py to create PR")
        else:
            print(f"\n{Status.ERROR} Phase 6 failed: {result.get('error', 'Unknown error')}")

    sys.exit(EXIT_SUCCESS if result["status"] == "complete" else EXIT_VALIDATION_ERROR)


if __name__ == "__main__":
    main()
