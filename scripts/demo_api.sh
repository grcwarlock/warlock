#!/bin/bash
# Quick demo API helper — authenticates and queries endpoints
# Usage: ./scripts/demo_api.sh [endpoint]
# Examples:
#   ./scripts/demo_api.sh                          # shows coverage
#   ./scripts/demo_api.sh /api/v1/findings?limit=5
#   ./scripts/demo_api.sh /api/v1/poams
#   ./scripts/demo_api.sh /api/v1/drift

BASE="http://localhost:8000"
ENDPOINT="${1:-/api/v1/results/coverage}"

TOKEN=$(curl -s -X POST "$BASE/api/v1/auth/login" -H "Content-Type: application/json" -d '{"email":"admin@acme.com","password":"WarlockAdmin2026!"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

if [ -z "$TOKEN" ]; then
  echo "Failed to authenticate. Is the API running? (warlock-api)"
  exit 1
fi

curl -s -H "Authorization: Bearer $TOKEN" "$BASE$ENDPOINT" | python3 -m json.tool
