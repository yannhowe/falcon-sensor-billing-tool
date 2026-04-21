#!/usr/bin/env bash
# run.sh — Start the dashboard and collect data periodically.
#
# Usage:
#   ./run.sh                      # collect every 4 hours (default)
#   ./run.sh --interval 2         # collect every 2 hours
#   ./run.sh --no-dashboard       # collection only, no dashboard
#
# Credentials: set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET in env,
# or the script will attempt to load them from macOS Keychain.

set -euo pipefail

INTERVAL_HOURS=4
RUN_DASHBOARD=true
BINARY="./dist/falcon-billing"
DASHBOARD_PID=""

usage() {
    echo "Usage: $0 [--interval HOURS] [--no-dashboard] [--binary PATH]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --interval)   INTERVAL_HOURS="$2"; shift 2 ;;
        --no-dashboard) RUN_DASHBOARD=false; shift ;;
        --binary)     BINARY="$2"; shift 2 ;;
        -h|--help)    usage ;;
        *)            echo "Unknown option: $1"; usage ;;
    esac
done

# --- Credentials from Keychain if not already in env ---
if [[ -z "${FALCON_CLIENT_ID:-}" ]]; then
    FALCON_CLIENT_ID=$(security find-generic-password -s "falcon-client-id" -w 2>/dev/null) || true
fi
if [[ -z "${FALCON_CLIENT_SECRET:-}" ]]; then
    FALCON_CLIENT_SECRET=$(security find-generic-password -s "falcon-client-secret" -w 2>/dev/null) || true
fi
if [[ -z "${FALCON_CLOUD_REGION:-}" ]]; then
    FALCON_CLOUD_REGION=$(security find-generic-password -s "falcon-cloud-region" -w 2>/dev/null || echo "us-1")
fi
export FALCON_CLIENT_ID FALCON_CLIENT_SECRET FALCON_CLOUD_REGION

if [[ -z "$FALCON_CLIENT_ID" || -z "$FALCON_CLIENT_SECRET" ]]; then
    echo "ERROR: Falcon API credentials not found."
    echo "Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET, or store in macOS Keychain."
    exit 1
fi

# --- Use Python fallback if binary doesn't exist ---
if [[ ! -x "$BINARY" ]]; then
    echo "Binary not found at $BINARY, falling back to python3 -m falcon_billing.cli.main"
    BINARY="python3 -m falcon_billing.cli.main"
fi

cleanup() {
    echo ""
    echo "Shutting down..."
    [[ -n "$DASHBOARD_PID" ]] && kill "$DASHBOARD_PID" 2>/dev/null
    exit 0
}
trap cleanup SIGINT SIGTERM

# --- Start dashboard ---
if $RUN_DASHBOARD; then
    echo "Starting dashboard on http://127.0.0.1:8080 ..."
    $BINARY dashboard &
    DASHBOARD_PID=$!
    sleep 2
    if ! kill -0 "$DASHBOARD_PID" 2>/dev/null; then
        echo "ERROR: Dashboard failed to start."
        exit 1
    fi
    echo "Dashboard running (PID $DASHBOARD_PID)"
fi

# --- Collection loop ---
INTERVAL_SECS=$((INTERVAL_HOURS * 3600))
echo "Collecting data every ${INTERVAL_HOURS}h (${INTERVAL_SECS}s)..."
echo ""

while true; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Collecting current hour..."
    $BINARY collect --days 0 --prune 2>&1 | tail -5
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Next collection in ${INTERVAL_HOURS}h"
    echo ""
    sleep "$INTERVAL_SECS"
done
