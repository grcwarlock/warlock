#!/bin/bash
# Warlock GRC Platform — Double-click to launch demo
cd /Users/jsn/Coding/GitHub/warlock
./scripts/demo.sh
source .venv/bin/activate
echo ""
echo "  Ready — type commands here (e.g. warlock coverage)"
echo ""
exec $SHELL
