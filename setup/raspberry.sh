#!/bin/bash
# One-command Raspberry Pi / Linux install with prompts.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "$(id -u)" -ne 0 ]; then echo "Run with sudo:  sudo ./setup/raspberry.sh"; exit 1; fi
echo "Network interfaces on this device:"
ip -o link show | awk -F': ' '{print "  - "$2}' | grep -v ' lo$' || true
read -rp "Interface going to your PC     [eth0]: " PC;  PC=${PC:-eth0}
read -rp "Interface going to the other side [eth1]: " BOX; BOX=${BOX:-eth1}
echo "Installing with PC_IF=$PC BOX_IF=$BOX …"
PC_IF="$PC" BOX_IF="$BOX" ./install.sh
