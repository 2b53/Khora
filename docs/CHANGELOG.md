# Khora Changelog

## 2026-05-27

- Removed the remaining agent entry from the active `client.py` module registry
- Removed the inactive `modules/agent_module.py` artifact from the framework surface
- Hardened module loading in `client.py` and `exploit_chains.py` to support the legacy `RCE_module.py` filename
- Updated `test_khora.py` to follow the active client module registry instead of a stale hard-coded list
- Reworked the CLI and top-level documentation to present Khora as a consistent operator-facing framework
- Reworked `nmap`, `backdoor`, `c2`, `RCE`, and `jailbreak` module output toward a cleaner framework presentation
- Reworked `blueborne`, `cracker`, `dirtycow`, and `eternalblue` module output to match the same framework surface
- Added a `nuclei` module with JSONL parsing, Khora summaries, and chain integration for legitimate template-based assessments

## 2026-05-18

- Removed the temporary `agents/` package again
- Removed `--agent` handling from `client.py`
- Returned the repository focus to the pentest client, module execution, chains, sessions, and reports
- Corrected documentation drift between markdown files and the actual codebase

## 2026-05-09

- client and module structure were already present
- later agent-oriented documentation drift has been removed
