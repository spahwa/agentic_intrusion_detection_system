#!/bin/bash
set -e

IFACE="${NETWORK_INTERFACE:-enp1s0f0}"

LOG_DIR="/var/log/ids/${LOG_SUBDIR:-zeek}"
mkdir -p "$LOG_DIR"

exec /usr/local/zeek/bin/zeek \
    -i "$IFACE" \
    /usr/local/zeek/share/zeek/site/local.zeek \
    "LogAscii::use_json=T" \
    "Log::default_logdir=$LOG_DIR"
