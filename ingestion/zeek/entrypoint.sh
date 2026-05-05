#!/usr/bin/env bash
# Sentinel – Zeek entrypoint
# Processes existing PCAPs on startup, then watches for new ones.
# Uses both inotifywait AND a polling loop as a fallback for bind-mount edge cases.

PCAP_DIR="/pcap"
LOG_BASE="/zeek-logs"

# Track which files have already been processed
declare -A PROCESSED

process_pcap() {
    local pcap_file="$1"
    local basename
    basename=$(basename "$pcap_file")
    basename="${basename%.pcapng}"
    basename="${basename%.pcap}"

    local outdir="${LOG_BASE}/${basename}"
    echo "[zeek] Processing: ${pcap_file} → ${outdir}"
    mkdir -p "$outdir"

    (
        cd "$outdir"
        zeek -r "$pcap_file" \
            LogAscii::use_json=T \
            local
    )
    local rc=$?
    if [ $rc -ne 0 ]; then
        echo "[zeek] WARN: zeek returned ${rc} for ${pcap_file} (non-fatal)"
    else
        echo "[zeek] Done: ${basename}"
    fi
    PROCESSED["$pcap_file"]=1 #mark the pcap as processed so that they are not processed again
}

echo "[zeek] Watching ${PCAP_DIR} for PCAP files..."

# ── Process existing PCAPs on startup ─────────────────────────────────────────
found=0
for f in "${PCAP_DIR}"/*.pcap "${PCAP_DIR}"/*.pcapng; do
    if [ -f "$f" ]; then
        process_pcap "$f"
        found=1
    fi
done
if [ "$found" -eq 0 ]; then
    echo "[zeek] No existing PCAPs found. Waiting for new files..."
fi

# ── inotifywait watcher (background) ─────────────────────────────────────────
# Runs in background so the polling loop can also run
inotifywait -m -e close_write -e moved_to --format "%w%f" "${PCAP_DIR}" 2>/dev/null \
| while IFS= read -r new_file; do
    case "$new_file" in
        *.pcap|*.pcapng)
            if [ -z "${PROCESSED[$new_file]+x}" ]; then
                echo "[zeek] inotify: New file: ${new_file}"
                process_pcap "$new_file"
            fi
            ;;
    esac
done &

INOTIFY_PID=$!
echo "[zeek] inotifywait started (pid ${INOTIFY_PID})"

# ── Polling fallback loop ──────────────────────────────────────────────────────
# Catches files that inotifywait misses (e.g. files copied across filesystems
# or written by some tools that don't trigger close_write inside the container)
while true; do
    sleep 5
    for f in "${PCAP_DIR}"/*.pcap "${PCAP_DIR}"/*.pcapng; do
        if [ -f "$f" ] && [ -z "${PROCESSED[$f]+x}" ]; then
            echo "[zeek] poll: New file detected: ${f}"
            process_pcap "$f"
        fi
    done
done
