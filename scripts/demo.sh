#!/usr/bin/env bash
# demo.sh — Unified Sentinel demo launcher
#
# Starts the stack, runs the appropriate traffic generator, and on exit
# clears the PCAP folder + Zeek state so the next run looks live.
#
# Usage:
#   bash scripts/demo.sh --mode normal                        # normal traffic — no alerts expected
#   bash scripts/demo.sh --mode anomalous                     # all attack types
#   bash scripts/demo.sh --mode anomalous --type unsw         # UNSW attacks only
#   bash scripts/demo.sh --mode anomalous --type ids2018      # IDS-2018 attacks only
#   bash scripts/demo.sh --mode anomalous --type darknet      # Darknet traffic only
#   bash scripts/demo.sh --mode normal    --loop 30           # repeat every 30 s
#   bash scripts/demo.sh --mode anomalous --loop 60           # repeat every 60 s
#   bash scripts/demo.sh --mode anomalous --profile assets    # include real asset containers
#   bash scripts/demo.sh --mode anomalous --profile demo      # include demo mock-network hosts
#   bash scripts/demo.sh --down                               # stop stack + clean up

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_BASE="$REPO/docker-compose.yml"
COMPOSE_ASSETS="$REPO/docker-compose.assets.yml"

# ── Defaults ──────────────────────────────────────────────────────────────────
MODE=""
ATTACK_TYPE="all"
LOOP=0
PROFILE=""
DO_DOWN=0
NORMAL_FLOWS=30

# ── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)      MODE="$2";        shift 2 ;;
        --type)      ATTACK_TYPE="$2"; shift 2 ;;
        --loop)      LOOP="$2";        shift 2 ;;
        --profile)   PROFILE="$2";     shift 2 ;;
        --flows)     NORMAL_FLOWS="$2";shift 2 ;;
        --down)      DO_DOWN=1;        shift   ;;
        -h|--help)
            awk 'NR==1{next} /^[^#]/{exit} {sub(/^# ?/,""); print}' "$0"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Build compose command ─────────────────────────────────────────────────────
_compose_cmd() {
    local cmd="docker compose -f $COMPOSE_BASE"
    if [[ "$PROFILE" == "assets" ]]; then
        cmd="$cmd -f $COMPOSE_ASSETS --profile assets"
    elif [[ -n "$PROFILE" ]]; then
        cmd="$cmd --profile $PROFILE"
    fi
    echo "$cmd"
}

# ── Clean PCAP folder and Zeek state ─────────────────────────────────────────
_clear_pcaps() {
    echo ""
    echo "Clearing PCAP folder (capture/pcap/) for a clean next run..."
    rm -f "$REPO"/capture/pcap/*.pcap "$REPO"/capture/pcap/*.pcapng 2>/dev/null || true

    echo "Clearing Zeek processed-file markers..."
    docker run --rm \
        -v sentinel_zeek-logs:/zeek-logs \
        alpine sh -c "rm -rf /zeek-logs/* /zeek-logs/.processed_pcaps /zeek-logs/.processed_logs" \
        2>/dev/null || echo "  (zeek-logs volume not available — skipped)"
    echo "PCAP folder cleared."
}

# ── Teardown ──────────────────────────────────────────────────────────────────
if [[ "$DO_DOWN" -eq 1 ]]; then
    echo "=== Stopping Sentinel stack ==="
    $(_compose_cmd) down 2>/dev/null || true
    _clear_pcaps
    echo "=== Stack stopped and PCAP folder cleared. ==="
    exit 0
fi

# ── Validate mode ─────────────────────────────────────────────────────────────
if [[ -z "$MODE" ]]; then
    echo "Error: --mode is required (normal|anomalous)" >&2
    echo "       Run with --help for usage." >&2
    exit 1
fi

if [[ "$MODE" != "normal" && "$MODE" != "anomalous" ]]; then
    echo "Error: --mode must be 'normal' or 'anomalous'" >&2
    exit 1
fi

VALID_TYPES="all unsw ids2018 darknet benign"
if [[ "$MODE" == "anomalous" ]] && ! echo "$VALID_TYPES" | grep -qw "$ATTACK_TYPE"; then
    echo "Error: --type must be one of: $VALID_TYPES" >&2
    exit 1
fi

# ── Start stack ───────────────────────────────────────────────────────────────
echo "=== Sentinel Demo — mode: $MODE ==="
[[ "$MODE" == "anomalous" ]] && echo "    Attack type : $ATTACK_TYPE"
[[ "$LOOP" -gt 0 ]]          && echo "    Loop every  : ${LOOP}s"
[[ -n "$PROFILE" ]]          && echo "    Profile     : $PROFILE"
echo ""

echo "[1/3] Starting stack..."
$(_compose_cmd) up -d
echo "      Stack started."

# ── Wait for orchestrator to be ready ────────────────────────────────────────
echo ""
echo "[2/3] Waiting for orchestrator to be healthy..."
for i in $(seq 1 30); do
    if docker inspect --format='{{.State.Status}}' sentinel-orchestrator 2>/dev/null | grep -q "running"; then
        echo "      Orchestrator is running."
        break
    fi
    printf "      (%ds) Waiting...\r" "$((i * 2))"
    sleep 2
done

# ── Traffic generator ─────────────────────────────────────────────────────────
echo ""
echo "[3/3] Starting traffic generator..."

TRAFFIC_PID=""

_launch_traffic() {
    if [[ "$MODE" == "normal" ]]; then
        if [[ "$LOOP" -gt 0 ]]; then
            python3 "$REPO/scripts/test_normal_traffic.py" \
                --n "$NORMAL_FLOWS" --loop "$LOOP" &
        else
            python3 "$REPO/scripts/test_normal_traffic.py" \
                --n "$NORMAL_FLOWS" &
        fi
    else
        if [[ "$LOOP" -gt 0 ]]; then
            python3 "$REPO/scripts/generate_traffic.py" \
                --type "$ATTACK_TYPE" --loop "$LOOP" &
        else
            python3 "$REPO/scripts/generate_traffic.py" \
                --type "$ATTACK_TYPE" &
        fi
    fi
    TRAFFIC_PID=$!
}

# ── Cleanup on exit ───────────────────────────────────────────────────────────
_on_exit() {
    echo ""
    echo "=== Demo stopping... ==="

    if [[ -n "$TRAFFIC_PID" ]]; then
        echo "Stopping traffic generator (PID $TRAFFIC_PID)..."
        kill "$TRAFFIC_PID" 2>/dev/null || true
        wait "$TRAFFIC_PID" 2>/dev/null || true
    fi

    _clear_pcaps

    echo ""
    echo "=== Demo ended. PCAP folder is clean for the next run. ==="
    echo "    To stop the full stack: bash scripts/demo.sh --down"
}
trap _on_exit EXIT INT TERM

_launch_traffic

# ── Status banner ─────────────────────────────────────────────────────────────
echo ""
echo "──────────────────────────────────────────────────────────"
if [[ "$MODE" == "normal" ]]; then
    echo "  Mode   : NORMAL TRAFFIC"
    echo "  Expect : No new alerts in the dashboard."
    echo "  Watch  : Dashboard → Alert Feed should stay quiet."
else
    echo "  Mode   : ANOMALOUS TRAFFIC  (type: $ATTACK_TYPE)"
    echo "  Expect : Alerts appear in the dashboard within ~30s."
    echo "  Watch  : Dashboard → Alert Feed → investigate & approve plans."
fi
[[ "$LOOP" -gt 0 ]] && echo "  Loop   : New PCAP every ${LOOP}s"
echo ""
echo "  Press Ctrl-C to stop traffic and clean up PCAPs."
echo "──────────────────────────────────────────────────────────"
echo ""

# Wait for traffic generator to finish (or Ctrl-C)
wait "$TRAFFIC_PID" 2>/dev/null || true
