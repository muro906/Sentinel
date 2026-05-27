#!/bin/bash
# Continuous alert streaming script for live demos
# Usage: ./stream_alerts.sh [interval_seconds]

INTERVAL=${1:-30}
VENV_PYTHON="/home/millie/Sentinel/.venv/bin/python"
SCRIPT="/home/millie/Sentinel/dashboard/backend/scripts/generate_streaming_data.py"

echo "Starting continuous alert stream..."
echo "Interval: ${INTERVAL} seconds"
echo "Press Ctrl+C to stop"
echo ""

cd /home/millie/Sentinel/dashboard/backend
$VENV_PYTHON $SCRIPT --continuous --interval $INTERVAL
