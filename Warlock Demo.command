#!/bin/bash
# Warlock GRC Platform — Double-click to launch demo
cd /Users/jsn/Coding/GitHub/warlock
exec < /dev/tty

./scripts/demo.sh

source .venv/bin/activate
# Load AI config written by demo.sh
[ -f .env ] && set -a && source .env && set +a
echo ""
echo "  Ready — type commands here (e.g. warlock coverage, warlock dashboard)"
echo ""
exec $SHELL
