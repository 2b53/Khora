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

Example:

```bash
python client.py 192.168.1.10 10.10.14.1 -m nuclei
```

## Framework Controls

```bash
python client.py <target> <lhost> --sequential
python client.py <target> <lhost> --workers 3
python client.py <target> <lhost> --chain <profile>
python client.py <target> <lhost> --session <session_id>
```

Useful chain profiles now include:

- `reconnaissance`
- `web_assessment`
- `full_assessment`

## Session And Reporting Files

- `logs/`: runtime logs
- `results/`: session JSON output
- `sessions/`: persisted session data
- `results/*_findings_bundle_*.json`: normalized Khora findings bundles

## Useful Files

- `client.py`
- `sessions.py`
- `reporting.py`
- `exploit_chains.py`
- `STATUS.md`
