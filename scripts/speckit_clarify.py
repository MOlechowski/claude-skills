#!/usr/bin/env python3
"""
speckit_clarify.py - Phase 3: CLARIFY

Scans spec.md for ambiguities and generates clarification questions.

Usage:
    speckit_clarify.py [OPTIONS]

Options:
    --max-questions N  Maximum questions to generate (default: 5)
    --json             Output in JSON format
    --help, -h         Show this help message

Examples:
    speckit_clarify.py
    speckit_clarify.py --max-questions 3 --json
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
    get_feature_paths
)


# Ambiguity detection patterns
AMBIGUITY_PATTERNS = [
    (r"NEEDS CLARIFICATION", "explicit_marker", "Explicit clarification marker found"),
    (r"\[unclear\]", "explicit_marker", "Marked as unclear"),
    (r"\[TBD\]", "explicit_marker", "Marked as TBD"),
    (r"\[TODO\]", "explicit_marker", "Marked as TODO"),
    (r"(?:should|might|could|may)\s+(?:be|have|include|use)", "uncertainty", "Uncertain language"),
    (r"(?:possibly|probably|maybe|perhaps)", "uncertainty", "Hedging language"),
    (r"etc\.?(?:\s|$)", "vague", "Vague 'etc.' reference"),
    (r"and\s+(?:so\s+on|more)", "vague", "Vague continuation"),
    (r"(?:some|various|multiple)\s+\w+", "vague", "Vague quantifier"),
    (r"appropriate\s+\w+", "vague", "Vague 'appropriate' reference"),
    (r"as\s+needed", "vague", "Vague 'as needed' reference"),
    (r"\?\s*$", "question", "Unresolved question"),
]


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Phase 3: CLARIFY - Scan for ambiguities and generate questions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s
    %(prog)s --max-questions 3 --json
"""
    )
    parser.add_argument(
        "--max-questions",
        type=int,
        default=5,
        help="Maximum questions to generate (default: 5)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format"
    )

    return parser.parse_args()


def find_ambiguities(content: str) -> list:
    """
    Scan content for ambiguous sections.

    Returns list of ambiguity dictionaries with:
    - pattern: The regex pattern that matched
    - match: The matched text
    - category: Type of ambiguity
    - description: Human-readable description
    - line_num: Line number in content
    - context: Surrounding text
    """
    ambiguities = []
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        for pattern, category, description in AMBIGUITY_PATTERNS:
            matches = re.finditer(pattern, line, re.IGNORECASE)
            for match in matches:
                # Get context (the full line)
                context = line.strip()

                ambiguities.append({
                    "pattern": pattern,
                    "match": match.group(),
                    "category": category,
                    "description": description,
                    "line_num": line_num,
                    "context": context[:200]  # Limit context length
                })

    return ambiguities


def generate_questions(ambiguities: list, max_questions: int) -> list:
    """
    Generate clarification questions from ambiguities.

    Prioritizes explicit markers over inferred ambiguities.
    """
    questions = []

    # Sort by priority: explicit_marker > question > vague > uncertainty
    priority_order = {"explicit_marker": 0, "question": 1, "vague": 2, "uncertainty": 3}
    sorted_ambiguities = sorted(
        ambiguities,
        key=lambda x: priority_order.get(x["category"], 99)
    )

    for amb in sorted_ambiguities[:max_questions]:
        category = amb["category"]
        context = amb["context"]

        if category == "explicit_marker":
            question = f"Please clarify: {context}"
        elif category == "question":
            question = f"This question needs an answer: {context}"
        elif category == "vague":
            question = f"Please be more specific about: {context}"
        elif category == "uncertainty":
            question = f"Please confirm the requirement: {context}"
        else:
            question = f"Please clarify: {context}"

        questions.append({
            "question": question,
            "category": category,
            "line_num": amb["line_num"],
            "original_context": context
        })

    return questions


def execute_phase(args, paths: dict) -> dict:
    """
    Execute Phase 3: CLARIFY.

    Scans spec.md for ambiguities and generates clarification questions.
    """
    log_phase(3, "CLARIFY", "start")

    feature_dir = Path(paths.get("FEATURE_DIR", ""))
    spec_file = feature_dir / "spec.md"

    if not spec_file.exists():
        log_phase(3, "CLARIFY", "error")
        return {
            "status": "error",
            "phase": 3,
            "error": f"spec.md not found: {spec_file}"
        }

    content = spec_file.read_text()

    # Find ambiguities
    print(f"  {Status.RUNNING} Scanning for ambiguities...")
    ambiguities = find_ambiguities(content)

    if not ambiguities:
        print(f"  {Status.SUCCESS} No ambiguities found")
        log_phase(3, "CLARIFY", "complete")
        return {
            "status": "complete",
            "phase": 3,
            "ambiguities_found": 0,
            "questions": []
        }

    print(f"  {Status.INFO} Found {len(ambiguities)} potential ambiguities")

    # Generate questions
    questions = generate_questions(ambiguities, args.max_questions)
    print(f"  {Status.INFO} Generated {len(questions)} clarification questions")

    # Categorize findings
    categories = {}
    for amb in ambiguities:
        cat = amb["category"]
        categories[cat] = categories.get(cat, 0) + 1

    log_phase(3, "CLARIFY", "complete")

    return {
        "status": "complete",
        "phase": 3,
        "ambiguities_found": len(ambiguities),
        "categories": categories,
        "questions": questions
    }


def main():
    args = parse_args()

    # Get feature paths
    paths = get_feature_paths()
    if "error" in paths:
        print(f"{Status.ERROR} {paths['error']}")
        sys.exit(EXIT_MISSING_PREREQ)

    print(f"{Status.RUNNING} Scanning specification for ambiguities...")

    result = execute_phase(args, paths)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["status"] == "complete":
            print(f"\n{Status.SUCCESS} Phase 3 complete: CLARIFY")
            print(f"  Ambiguities found: {result['ambiguities_found']}")

            if result["questions"]:
                print(f"\n{Status.INFO} Clarification questions:")
                for i, q in enumerate(result["questions"], 1):
                    print(f"  {i}. [{q['category']}] {q['question']}")

                print(f"\n{Status.INFO} Next: Address these questions in spec.md, then run speckit_analyze.py")
            else:
                print(f"\n{Status.INFO} Next: Run speckit_analyze.py")
        else:
            print(f"\n{Status.ERROR} Phase 3 failed: {result.get('error', 'Unknown error')}")

    sys.exit(EXIT_SUCCESS if result["status"] == "complete" else EXIT_VALIDATION_ERROR)


if __name__ == "__main__":
    main()
