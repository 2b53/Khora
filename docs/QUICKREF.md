# Khora Quick Reference

## Core Commands

```bash
python client.py --help
python client.py --list
python client.py --list-chains
```

## Single Module Invocation Pattern

```bash
python client.py <target> <lhost> -m <module>
```

## Framework Controls

```bash
python client.py <target> <lhost> --sequential
python client.py <target> <lhost> --workers 3
python client.py <target> <lhost> --chain <profile>
python client.py <target> <lhost> --session <session_id>
```

## Session And Reporting Files

- `logs/`: runtime logs
- `results/`: session JSON output
- `sessions/`: persisted session data

## Useful Files

- `client.py`
- `sessions.py`
- `reporting.py`
- `exploit_chains.py`
- `STATUS.md`
