#!/bin/bash
# Caps Ollama CPU usage to 4 cores (400%) via systemd cgroup CPUQuota.
# Works with both llama.cpp and --ollama-engine backends.
# Run once with: sudo bash scripts/fix_ollama_cpu.sh

set -e

CORES=${1:-4}
QUOTA=$((CORES * 100))

echo "Setting Ollama CPUQuota=${QUOTA}% (${CORES} cores)..."

mkdir -p /etc/systemd/system/ollama.service.d

cat > /etc/systemd/system/ollama.service.d/override.conf << EOF
[Service]
CPUQuota=${QUOTA}%
EOF

echo "Written: /etc/systemd/system/ollama.service.d/override.conf"
cat /etc/systemd/system/ollama.service.d/override.conf

systemctl daemon-reload
systemctl restart ollama

echo ""
echo "Done. Verifying..."
sleep 2
systemctl show ollama | grep CPUQuota
echo ""
echo "Ollama is now capped at ${CORES} cores (${QUOTA}% CPU)."
echo "To change: sudo bash scripts/fix_ollama_cpu.sh <num_cores>"
