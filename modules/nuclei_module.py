"""
Nuclei assessment module for template-based web and service checks.
"""

from datetime import datetime
from pathlib import Path
import json
import logging
import os
import shutil
import subprocess

from finding_schema import make_finding, write_bundle

logger = logging.getLogger("Khora.Nuclei")

RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)


def find_nuclei_binary():
    """Locate a nuclei executable in PATH."""
    return shutil.which("nuclei")


def build_targets(target):
    """Build a small default target set for HTTP-focused nuclei checks."""
    return [f"http://{target}", f"https://{target}"]


def write_targets_file(targets, timestamp):
    """Persist targets to a file for repeatable runs."""
    targets_file = RESULTS_DIR / f"nuclei_targets_{timestamp}.txt"
    with open(targets_file, "w") as handle:
        for target in targets:
            handle.write(f"{target}\n")
    return targets_file


def run_nuclei_scan(targets_file, output_file):
    """Run nuclei and write JSONL output."""
    nuclei_path = find_nuclei_binary()
    if not nuclei_path:
        raise FileNotFoundError("nuclei executable not found in PATH")

    cmd = [
        nuclei_path,
        "-l",
        str(targets_file),
        "-jsonl",
        "-o",
        str(output_file),
        "-silent",
    ]

    templates_dir = os.environ.get("KHORA_NUCLEI_TEMPLATES")
    if templates_dir:
        cmd.extend(["-t", templates_dir])

    logger.info(f"Running nuclei: {' '.join(cmd)}")
    completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "command": cmd,
    }


def parse_jsonl(output_file):
    """Parse nuclei JSONL output into summary data."""
    findings = []
    normalized_findings = []
    severities = {}

    if not output_file.exists():
        return findings, normalized_findings, severities

    with open(output_file, "r") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping invalid nuclei JSONL line")
                continue

            info = entry.get("info", {})
            severity = (info.get("severity") or "unknown").lower()
            severities[severity] = severities.get(severity, 0) + 1
            findings.append(
                {
                    "template_id": entry.get("template-id"),
                    "name": info.get("name"),
                    "severity": severity,
                    "matched_at": entry.get("matched-at"),
                    "host": entry.get("host"),
                    "type": entry.get("type"),
                }
            )
            normalized_findings.append(
                make_finding(
                    module="nuclei",
                    title=info.get("name") or entry.get("template-id") or "Nuclei finding",
                    severity=severity,
                    category=entry.get("type") or "web",
                    target=entry.get("host") or entry.get("matched-at"),
                    description=info.get("description"),
                    evidence={
                        "template_id": entry.get("template-id"),
                        "matched_at": entry.get("matched-at"),
                        "matcher_name": entry.get("matcher-name"),
                    },
                    references=info.get("reference") or [],
                    metadata={
                        "host": entry.get("host"),
                        "type": entry.get("type"),
                    },
                )
            )

    return findings, normalized_findings, severities


def write_summary(target, targets, command_result, findings, severities, timestamp):
    """Persist a Khora summary alongside raw nuclei output."""
    summary_file = RESULTS_DIR / f"nuclei_summary_{timestamp}.json"
    with open(summary_file, "w") as handle:
        json.dump(
            {
                "framework": "Khora",
                "module": "nuclei",
                "target": target,
                "targets": targets,
                "timestamp": datetime.now().isoformat(),
                "returncode": command_result["returncode"],
                "severities": severities,
                "finding_count": len(findings),
                "findings": findings,
                "stderr": command_result["stderr"][-2000:],
            },
            handle,
            indent=2,
        )
    return summary_file


def print_summary(targets, findings, severities, output_file, summary_file):
    """Print a concise operator summary."""
    print("\n" + "=" * 70)
    print("NUCLEI ASSESSMENT MODULE".center(70))
    print("=" * 70)
    print("Targets:")
    for target in targets:
        print(f"  - {target}")

    print(f"\nFindings: {len(findings)}")
    if severities:
        print("Severity summary:")
        for severity in sorted(severities):
            print(f"  - {severity}: {severities[severity]}")
    else:
        print("Severity summary:")
        print("  - no findings recorded")

    print(f"\nRaw output: {output_file}")
    print(f"Summary:    {summary_file}")
    print("=" * 70 + "\n")


def run(target, lhost, lport=4444):
    """Module entrypoint."""
    del lhost
    del lport

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    targets = build_targets(target)
    targets_file = write_targets_file(targets, timestamp)
    output_file = RESULTS_DIR / f"nuclei_findings_{timestamp}.jsonl"

    print(f"\n{'=' * 70}")
    print("NUCLEI ASSESSMENT MODULE".center(70))
    print("=" * 70)
    print(f"Primary target: {target}")
    print(f"Prepared targets file: {targets_file}\n")

    try:
        command_result = run_nuclei_scan(targets_file, output_file)
    except FileNotFoundError as exc:
        print(f"[!] {exc}")
        print("[!] Install nuclei and ensure it is available in PATH.")
        logger.error(str(exc))
        return

    findings, normalized_findings, severities = parse_jsonl(output_file)
    summary_file = write_summary(target, targets, command_result, findings, severities, timestamp)
    bundle_file = write_bundle(
        module="nuclei",
        target=target,
        findings=normalized_findings,
        timestamp=timestamp,
        source_files=[str(targets_file), str(output_file), str(summary_file)],
        metadata={"targets": targets, "severities": severities, "returncode": command_result["returncode"]},
    )
    print_summary(targets, findings, severities, output_file, summary_file)
    print(f"Bundle:     {bundle_file}\n")

    if command_result["returncode"] not in (0,):
        logger.warning(f"Nuclei exited with code {command_result['returncode']}")
        if command_result["stderr"].strip():
            print("[!] nuclei reported warnings or errors:")
            print(command_result["stderr"][-1000:])

    logger.info("Nuclei module completed")
