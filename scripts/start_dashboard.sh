#!/usr/bin/env bash
# Start the Falcon Billing web dashboard
# Usage: bash scripts/start_dashboard.sh [port]

set -euo pipefail

PORT="${1:-8080}"

if ! command -v falcon-billing &>/dev/null; then
    echo "ERROR: falcon-billing not found in PATH."
    echo "Run 'pip install -e .' first."
    exit 1
fi

if [ ! -f "sensor_billing.db" ]; then
    echo "ERROR: sensor_billing.db not found in current directory."
    echo "Run 'falcon-billing collect --hourly' first."
    exit 1
fi

echo "Starting dashboard on http://127.0.0.1:${PORT}"
falcon-billing dashboard --port "${PORT}"
