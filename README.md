# Khora v2.1

Khora is a Python-based security testing framework with pluggable modules, session tracking, attack-chain execution, and reporting.

## Current Status

- `client.py` provides the main CLI, module loading, chain execution, logging, and session reports.
- `modules/` contains the current module entry points used by the framework.
- `exploit_chains.py` provides pre-built chain profiles.
- Documentation has been aligned to the actual client and module structure.

## Implemented Framework Areas

- Module discovery and execution through `client.py`
- Session lifecycle management in `sessions.py`
- JSON session reporting in `client.py`
- Standalone report generation helpers in `reporting.py`
- Attack chain profile loading through `exploit_chains.py`

## Repository Layout

```text
Khora/
|- client.py
|- exploit_chains.py
|- reporting.py
|- sessions.py
|- status_report.py
|- test_khora.py
|- modules/
|- payloads/
|- exploits/
|- docs/
|- results/
|- logs/
```

## Getting Started

1. Create and activate a Python 3.8+ virtual environment.
2. Install dependencies from `requirements.txt`.
3. Run `python client.py --list` to verify the CLI loads.
4. Review `docs/setup.md` and `docs/QUICKSTART.md` for the documented project workflow.

## Documentation

- [docs/README.md](docs/README.md)
- [docs/setup.md](docs/setup.md)
- [docs/QUICKSTART.md](docs/QUICKSTART.md)
- [docs/QUICKREF.md](docs/QUICKREF.md)
- [docs/CHANGELOG.md](docs/CHANGELOG.md)
- [docs/Troubleshooting.md](docs/Troubleshooting.md)
- [docs/SECURITY.md](docs/SECURITY.md)

## Safety and Scope

Use this project only in environments you own or where you have explicit written authorization. The documentation in this repository is intended to describe the framework and its current code state, not to provide operational attack playbooks.
