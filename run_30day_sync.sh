#!/usr/bin/env bash
# Local helper to run a 30-day sync. Do NOT commit secrets here.
# Prefer GitHub Actions with repository secrets.

set -euo pipefail

# Configure via environment variables before running:
#   export OOMNITZA_URL="https://<instance>.oomnitza.com"
#   export OOMNITZA_API_TOKEN="<oomnitza_api_token>"
#   export INSIGHT_CLIENT_ID="<insight_client_id>"
#   export INSIGHT_CLIENT_KEY="<insight_client_key>"
#   export INSIGHT_CLIENT_SECRET="<insight_client_secret>"
#   export INSIGHT_URL="https://insight-prod.apigee.net/GetStatus"

: "${OOMNITZA_URL:?Set OOMNITZA_URL}"
: "${OOMNITZA_API_TOKEN:?Set OOMNITZA_API_TOKEN}"
: "${INSIGHT_CLIENT_ID:?Set INSIGHT_CLIENT_ID}"
: "${INSIGHT_CLIENT_KEY:?Set INSIGHT_CLIENT_KEY}"
: "${INSIGHT_CLIENT_SECRET:?Set INSIGHT_CLIENT_SECRET}"
: "${INSIGHT_URL:?Set INSIGHT_URL}"

# Date range (defaults to previous 30 days)
START_DATE=${INSIGHT_ORDER_CREATION_DATE_FROM:-$(date -u -d '30 days ago' +%F 2>/dev/null || python - <<'PY'
import datetime; print((datetime.datetime.utcnow()-datetime.timedelta(days=30)).date().isoformat())
PY
)}
END_DATE=${INSIGHT_ORDER_CREATION_DATE_TO:-$(date -u +%F 2>/dev/null || python - <<'PY'
import datetime; print(datetime.datetime.utcnow().date().isoformat())
PY
)}

export INSIGHT_ORDER_CREATION_DATE_FROM="$START_DATE"
export INSIGHT_ORDER_CREATION_DATE_TO="$END_DATE"

python connector.py upload insight --ini config.ini "$@"
