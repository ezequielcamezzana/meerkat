#!/usr/bin/env bash
set -euo pipefail

TOKEN="${MEERKAT_TOKEN:-${1:-}}"
SERVER="${MEERKAT_SERVER:-http://localhost:8080}"
DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ -z "$TOKEN" ]]; then
  echo "Usage: MEERKAT_TOKEN=<token> $0" >&2
  echo "   or: $0 <token>" >&2
  exit 1
fi

ok=0; fail=0
for f in "$DIR"/*.json; do
  name="$(basename "$f")"
  status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$SERVER/v1/inventories" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    --data-binary "@$f")
  if [[ "$status" == "200" ]]; then
    echo "✓ $name"
    ((ok++))
  else
    echo "✗ $name (HTTP $status)"
    ((fail++))
  fi
done

echo ""
echo "$ok uploaded, $fail failed"
