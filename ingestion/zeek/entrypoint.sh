#!/usr/bin/env bash
# Sentinel – Zeek entrypoint
# Processes existing PCAPs on startup, then watches for new ones.

PCAP_DIR="/pcap"
LOG_BASE="/zeek-logs"

process_pcap() {
    local pcap_file="$1"
    # Strip both .pcap and .pcapng extensions
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
}

echo "[zeek] Watching ${PCAP_DIR} for PCAP files..."

# Process any PCAPs already present on startup
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

# Watch for new PCAPs dropped into the directory
inotifywait -m -e close_write -e moved_to --format "%w%f" "${PCAP_DIR}" 2>/dev/null \
| while IFS= read -r new_file; do
    case "$new_file" in
        *.pcap|*.pcapng)
            echo "[zeek] New file detected: ${new_file}"
            process_pcap "$new_file"
            ;;
    esac
done
