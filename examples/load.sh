#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Load VIP config into running kondor daemon.
# Usage: ./load.sh <config.json> [api_url]

set -e

CONFIG=${1:?usage: load.sh <config.json> [api_url]}
API=${2:-http://127.0.0.1:8080}

if ! command -v jq &>/dev/null; then
	echo "error: jq required" >&2
	exit 1
fi

NUM_VIPS=$(jq length "$CONFIG")
echo "loading $NUM_VIPS VIPs from $CONFIG"

for i in $(seq 0 $((NUM_VIPS - 1))); do
	VIP=$(jq -c ".[$i]" "$CONFIG")
	ADDR=$(echo "$VIP" | jq -r .address)
	PORT=$(echo "$VIP" | jq -r .port)
	PROTO=$(echo "$VIP" | jq -r .protocol)

	curl -s -X POST "$API/api/v1/vips" \
		-H 'Content-Type: application/json' \
		-d "$VIP" | jq -c .

	echo "  VIP $ADDR:$PORT/$PROTO loaded"
done

echo "done"
