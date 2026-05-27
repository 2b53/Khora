# Khora Setup Guide

## Requirements

- Python 3.8 or newer
- a working `python` or `python3` executable in `PATH`
- a working `pip`

Optional tools depend on which modules you plan to inspect or test locally.

Common optional tools:

- `nmap` for network discovery modules
- `nuclei` for template-based web and service assessment

## Basic Setup

```bash
python -m venv venv
```

Activate the virtual environment for your shell, then install dependencies:

```bash
pip install -r requirements.txt
```

## Minimal Verification

```bash
python client.py --list
```

If that succeeds, the top-level CLI is reachable and the module registry loads.

## Optional Assessment Tooling

If you want to use the `nuclei` module, install the official `nuclei` binary and ensure it is available in `PATH`.

You can optionally point Khora to a specific template directory with:

```bash
KHORA_NUCLEI_TEMPLATES=/path/to/nuclei-templates
```

## Environment Notes From This Review

- `python` was not available in the current shell `PATH`
- `git` was not available in the current shell `PATH`

If you expect local validation commands to work, restore those tools in the active terminal first.

## Recommended Follow-Up

1. Verify `python --version`
2. Verify `pip --version`
3. Verify `python client.py --help`
4. Verify `python client.py --list`
5. Review `docs/Troubleshooting.md` if any step fails
