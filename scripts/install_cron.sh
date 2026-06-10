#!/usr/bin/env bash
# Install cron job for hourly sensor collection
# Usage: bash scripts/install_cron.sh [install_dir]

set -euo pipefail

INSTALL_DIR="${1:-$(pwd)}"
LOG_FILE="/var/log/falcon-billing.log"
CRON_CMD="cd ${INSTALL_DIR} && falcon-billing collect --hourly >> ${LOG_FILE} 2>&1"
CRON_ENTRY="0 * * * * ${CRON_CMD}"

echo "Installing cron job for falcon-billing..."
echo "  Install dir: ${INSTALL_DIR}"
echo "  Log file:    ${LOG_FILE}"
echo "  Cron entry:  ${CRON_ENTRY}"
echo ""

if ! command -v falcon-billing &>/dev/null; then
    echo "ERROR: falcon-billing not found in PATH."
    echo "Run 'pip install -e .' first, or use the full binary path."
    exit 1
fi

if crontab -l 2>/dev/null | grep -qF "falcon-billing collect"; then
    echo "Cron job already installed. Current entry:"
    crontab -l | grep "falcon-billing"
    exit 0
fi

(crontab -l 2>/dev/null; echo "${CRON_ENTRY}") | crontab -
echo "Cron job installed. Verify with: crontab -l"
