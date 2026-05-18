# Khora Quick Start

This quick start focuses on verifying the local framework setup and understanding the current project state.

## 1. Prepare The Environment

```bash
python -m venv venv
```

Activate the environment for your platform, then install dependencies:

```bash
pip install -r requirements.txt
```

## 2. Verify The CLI Loads

```bash
python client.py --list
```

Expected result:

- the banner prints
- available modules are listed
- no module execution is started

## 3. Review The Current Documentation

Start here:

1. `docs/setup.md`
2. `docs/QUICKREF.md`
3. `docs/PAYLOADS.md`

## 4. Recommended Next Local Checks

- inspect `client.py`
- inspect `modules/`
- inspect `sessions.py`
- inspect `reporting.py`
- inspect `STATUS.md`

## 5. If Something Fails

Use `docs/Troubleshooting.md` for environment and dependency issues.
