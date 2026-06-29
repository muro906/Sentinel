#!/usr/bin/env bash
# demo_reset.sh — Wipe all PCAPs, Zeek logs, processed-file markers,
# and DB incidents/alerts so the demo starts from a clean state.
#
# Usage:
#   bash scripts/demo_reset.sh            # full reset
#   bash scripts/demo_reset.sh --soft     # keep DB, only clear files

set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SOFT=0
[[ "${1:-}" == "--soft" ]] && SOFT=1

echo "=== Sentinel Demo Reset ==="

# ── 1. Stop traffic-generating containers (keep core stack) ──────────────────
echo "[1/4] Stopping zeek + feature-extractor to avoid mid-reset processing..."
docker compose -f "$REPO/docker-compose.yml" stop zeek feature-extractor 2>/dev/null || true

# ── 2. Clear PCAPs and Zeek logs ──────────────────────────────────────────────
echo "[2/4] Clearing PCAPs..."
rm -f "$REPO"/capture/pcap/*.pcap "$REPO"/capture/pcap/*.pcapng 2>/dev/null || true

echo "[3/4] Clearing Zeek logs and processed-file markers..."
rm -rf "$REPO"/capture/zeek-logs/ 2>/dev/null || true
# Also clear the processed markers inside the Docker volume path
docker run --rm \
    -v sentinel_zeek-logs:/zeek-logs \
    alpine sh -c "rm -rf /zeek-logs/* /zeek-logs/.processed_pcaps /zeek-logs/.processed_logs" \
    2>/dev/null || true

# ── 3. Clear DB incidents (unless --soft) ────────────────────────────────────
if [ "$SOFT" -eq 0 ]; then
    echo "[4/4] Clearing incidents from database..."
    docker exec sentinel-postgres psql -U sentinel -d sentinel \
        -c "TRUNCATE incidents CASCADE;" 2>/dev/null \
        || echo "  (postgres not running — skip)"
else
    echo "[4/4] --soft: keeping database intact."
fi

# ── 4. Restart ingestion services ─────────────────────────────────────────────
echo ""
echo "Restarting zeek + feature-extractor with clean state..."
docker compose -f "$REPO/docker-compose.yml" start zeek feature-extractor 2>/dev/null || true

echo ""
echo "=== Reset complete. Pipeline is clean and ready for demo. ==="
echo ""
echo "  Generate normal traffic:  python scripts/test_normal_traffic.py --n 30"
echo "  Generate attack traffic:  python scripts/generate_traffic.py --type unsw"
echo "  Watch the pipeline:       python scripts/monitor_pipeline.py"
