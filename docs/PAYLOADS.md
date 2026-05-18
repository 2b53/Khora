# Khora Payload And Artifact Notes

## Purpose Of This Document

This file tracks the payload- and artifact-related parts of the repository at a documentation level. It does not provide operational delivery steps.

## Current Repository Artifacts

```text
payloads/
|- reverse_shells.txt
|- listener_setup.sh
|- persistence/
|  |- cron_persistence.sh
|  |- systemd_persistence.service

exploits/
|- dirtycow.c
|- kernel_exp.c
```

Some generated artifacts referenced elsewhere in older docs may not be present in a fresh checkout.

## Current Code Sources

- `modules/backdoor_module.py`
- `modules/agent_module.py`
- `generate_payloads.py`
- `modules/c2_module.py`

## Current State Summary

- Payload-related logic exists in modules and scripts.
- The docs previously overstated the maturity of this area and have been corrected.

## Documentation Guidance

When this area changes, document:

1. which files are source templates
2. which files are generated artifacts
3. which outputs are optional or environment-dependent
4. which referenced files are expected to exist after generation rather than in source control
