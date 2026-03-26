#!/bin/bash
# Warlock container entrypoint
# chmod +x entrypoint.sh
set -e

echo "============================================"
echo " Warlock Container Startup"
echo "============================================"

# Run database migrations
echo "[entrypoint] Running database migrations..."
python -m alembic -c alembic.ini upgrade head
echo "[entrypoint] Migrations complete."

# Load OPA policies if OPA_URL is set
if [ -n "$WLK_OPA_URL" ]; then
    echo "[entrypoint] OPA endpoint configured at $WLK_OPA_URL"
fi

# Start the application
echo "[entrypoint] Starting Warlock with: $@"
exec "$@"
