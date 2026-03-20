#!/bin/bash
# Warlock GRC Platform — Double-click to launch demo
cd /Users/jsn/Coding/GitHub/warlock

# Ensure stdin is from the terminal (not piped)
exec < /dev/tty

./scripts/demo.sh
source .venv/bin/activate
echo ""
echo "  Ready — type commands here (e.g. warlock coverage)"
echo ""
exec $SHELL
