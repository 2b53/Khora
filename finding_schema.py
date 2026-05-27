"""
Helpers for writing normalized Khora findings bundles.
"""

from datetime import datetime
import json
from pathlib import Path

RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)


def make_finding(
    module,
    title,
    severity="info",
    category="general",
    target=None,
    description=None,
    evidence=None,
    references=None,
    metadata=None,
):
    """Create a normalized Khora finding object."""
    return {
        "module": module,
        "title": title,
        "severity": severity,
        "category": category,
        "target": target,
        "description": description,
        "evidence": evidence or {},
        "references": references or [],
        "metadata": metadata or {},
        "timestamp": datetime.now().isoformat(),
    }


def write_bundle(module, target, findings, timestamp, source_files=None, metadata=None):
    """Write a normalized findings bundle to results/."""
    bundle_file = RESULTS_DIR / f"{module}_findings_bundle_{timestamp}.json"
    with open(bundle_file, "w") as handle:
        json.dump(
            {
                "framework": "Khora",
                "schema_version": "1.0",
                "module": module,
                "target": target,
                "timestamp": datetime.now().isoformat(),
                "finding_count": len(findings),
                "source_files": source_files or [],
                "metadata": metadata or {},
                "findings": findings,
            },
            handle,
            indent=2,
        )
    return bundle_file
