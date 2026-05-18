#!/usr/bin/env python3
"""Khora Framework status report."""

from pathlib import Path


def generate_status_report():
    """Generate a simple status report aligned with the current repo state."""

    print("\n" + "=" * 70)
    print("KHORA SECURITY TESTING FRAMEWORK v2.1".center(70))
    print("Project Status Report".center(70))
    print("=" * 70 + "\n")

    modules_path = Path("modules")
    modules = sorted(m.stem for m in modules_path.glob("*_module.py"))

    print("[*] MODULE FILES: {}".format(len(modules)))
    for module_name in modules:
        print("    - {}".format(module_name))

    print()

    print("[*] FRAMEWORK FILES")
    features = [
        ("client.py", "Main CLI entry point"),
        ("exploit_chains.py", "Chain loading and orchestration"),
        ("reporting.py", "Standalone reporting helpers"),
        ("sessions.py", "Session lifecycle management"),
        ("test_khora.py", "Validation script"),
    ]
    for filename, description in features:
        status = "OK" if Path(filename).exists() else "MISSING"
        print("    {} {} - {}".format(status, filename, description))

    print()

    print("[*] DOCUMENTATION")
    docs = [
        ("README.md", "Repository overview"),
        ("SECURITY.md", "Project security policy"),
        ("docs/setup.md", "Setup guide"),
        ("docs/QUICKREF.md", "Quick reference"),
        ("docs/CHANGELOG.md", "Status-aware changelog"),
    ]
    for filename, description in docs:
        status = "OK" if Path(filename).exists() else "MISSING"
        print("    {} {} - {}".format(status, filename, description))

    print()

    lines = 0
    for py_file in Path("modules").glob("*.py"):
        with open(py_file, encoding="utf-8", errors="replace") as handle:
            lines += len(handle.readlines())

    python_files = len(list(Path(".").glob("*.py")))
    markdown_files = len(list(Path(".").rglob("*.md")))

    print("[*] CODE STATISTICS")
    print("    Module Code: {} lines".format(lines))
    print("    Python Files: {}".format(python_files))
    print("    Markdown Files: {}".format(markdown_files))
    print("    Total Modules: {}".format(len(modules)))

    print()

    print("=" * 70)
    print("KHORA v2.1 CURRENTLY IN DEVELOPMENT".center(70))
    print(
        "Status:\n"
        "  - Module files present\n"
        "  - Documentation aligned to codebase\n"
        "  - Dynamic validation not confirmed in this report".center(70)
    )
    print("=" * 70 + "\n")

    return True


if __name__ == "__main__":
    generate_status_report()
