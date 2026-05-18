# Khora Troubleshooting

## `python` Or `python3` Not Found

Symptom:

- the shell cannot launch Python

What to check:

- Python is installed
- the active terminal session has Python in `PATH`
- the virtual environment is activated if you expect local packages

## `git` Not Found

Symptom:

- repository status commands fail in the shell

What to check:

- Git is installed
- Git is available in the active shell `PATH`

## Dependency Import Errors

Symptom:

- `ModuleNotFoundError`
- `ImportError`

What to do:

```bash
pip install -r requirements.txt
```

Then retry the CLI:

```bash
python client.py --list
```

## Documentation Does Not Match The Code

Symptom:

- docs claim features exist that the code does not implement

Resolution:

- compare against `client.py`, `modules/`, and `STATUS.md`
- keep planned features clearly labeled as planned

## Module Fails To Load

Symptom:

- the CLI logs that a module could not be loaded

What to check:

- the file exists in `modules/`
- the module exposes a `run(target, lhost, lport=4444)` entry point
- required dependencies for that module are installed
