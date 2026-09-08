#!/usr/bin/env python3
"""Collect and report exact-version native discovery and activation evidence.

Usage:
  python scripts/collect_native_evidence.py [--host HOST] [--scope SCOPE] [--json] [--output PATH] [--check-only]

Conforms to schema: portable-resume/native-evidence-v1
Policy: docs/evidence/native-activation-policy-v1.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
for p in (str(SRC), str(REPO_ROOT)):
    if p in sys.path:
        sys.path.remove(p)
sys.path.insert(0, str(SRC))
sys.path.insert(1, str(REPO_ROOT))

try:
    from scripts.native_evidence import (  # noqa: E402
        ALL_SCOPES,
        EVIDENCE_SCHEMA_VERSION,
        collect_full_matrix_evidence,
        format_evidence_markdown_table,
        validate_destination_evidence_profiles,
    )
except ModuleNotFoundError:
    from native_evidence import (  # noqa: E402
        ALL_SCOPES,
        EVIDENCE_SCHEMA_VERSION,
        collect_full_matrix_evidence,
        format_evidence_markdown_table,
        validate_destination_evidence_profiles,
    )
from portable_resume.registry import enabled_destination_keys  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect native discovery/activation evidence for portable-resume-skills."
    )
    parser.add_argument(
        "--host",
        choices=sorted(enabled_destination_keys()),
        help="Specific destination host (defaults to all enabled destinations)",
    )
    parser.add_argument(
        "--scope",
        choices=ALL_SCOPES,
        help="Specific scope (defaults to all evaluation scopes)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON records",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="File path to write evidence JSON or Markdown table",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Validate profile declarations against the registry without running tests",
    )
    parser.add_argument(
        "--operator",
        default="automated-collector",
        help="Operator or identity tag to record",
    )
    parser.add_argument(
        "--ci-run-url",
        default=None,
        help="CI run URL if executed in GitHub Actions",
    )
    args = parser.parse_args()

    # Always validate profile completeness first
    try:
        validate_destination_evidence_profiles()
    except Exception as exc:
        sys.stderr.write(f"ERROR: Destination evidence profile validation failed: {exc}\n")
        return 1

    if args.check_only:
        dest_count = len(enabled_destination_keys())
        print(f"EVIDENCE_PROFILE_CHECK PASS destinations={dest_count} scopes={len(ALL_SCOPES)}")
        return 0

    hosts = (args.host,) if args.host else None
    scopes = (args.scope,) if args.scope else None

    records = collect_full_matrix_evidence(
        hosts=hosts,
        scopes=scopes,
        operator=args.operator,
        ci_run_url=args.ci_run_url,
        repo_root=REPO_ROOT,
    )

    # Validate all produced records
    for rec in records:
        rec.validate()

    if args.json:
        data = {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "record_count": len(records),
            "records": [r.to_dict() for r in records],
        }
        output_text = json.dumps(data, indent=2, sort_keys=True)
    else:
        output_text = format_evidence_markdown_table(records)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output_text, encoding="utf-8")
        print(f"Wrote {len(records)} evidence records to {args.output}")
    else:
        print(output_text)

    # Return non-zero if any attempted scope failed (not-run is acceptable and honest)
    failed_records = [r for r in records if r.state == "failed"]
    if failed_records:
        sys.stderr.write(f"WARNING: {len(failed_records)} records reported state='failed'\n")
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
