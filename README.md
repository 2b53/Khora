# Khora Framework v2.1

Khora is a Python-based assessment framework for module-driven security validation, session tracking, chain execution, and reporting.

## Framework Scope

- `client.py` provides the primary operator CLI.
- `modules/` contains the active module entry points.
- `exploit_chains.py` provides reusable chain profiles.
- `sessions.py` persists assessment state and module execution history.
- `reporting.py` generates structured assessment output.

## Operating Model

- Discover available modules and chain profiles from the CLI.
- Run a single module, a named chain, or the full module set.
- Persist execution history in local session artifacts.
- Export JSON results for later reporting workflows.

## Current Characteristics

- Dynamic module loading with support for legacy filename drift such as `RCE_module.py`
- Session lifecycle handling with resumable session IDs
- Local logging and result directories created on demand
- Template-based assessment support through the `nuclei` module
- Documentation aligned to the currently reachable client surface

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
4. Review `docs/setup.md` and `docs/QUICKSTART.md` for the documented workflow.

## Documentation

- [docs/README.md](docs/README.md)
- [docs/setup.md](docs/setup.md)
- [docs/QUICKSTART.md](docs/QUICKSTART.md)
- [docs/QUICKREF.md](docs/QUICKREF.md)
- [docs/CHANGELOG.md](docs/CHANGELOG.md)
- [docs/Troubleshooting.md](docs/Troubleshooting.md)
- [docs/SECURITY.md](docs/SECURITY.md)

## Safety and Scope

Use this project only in environments you own or where you have explicit written authorization. The repository documents the framework implementation and operator workflow, not offensive playbooks.
