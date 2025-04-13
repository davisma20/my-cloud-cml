#!/bin/bash
# Script to wait for the CML API endpoint to become ready.

set -e

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - WAIT_API: $1"
}

MAX_WAIT_SECONDS=300
WAIT_INTERVAL=10
ELAPSED_TIME=0
API_ENDPOINT='http://127.0.0.1/api/v0/about'

log "Waiting up to $MAX_WAIT_SECONDS seconds for CML API at $API_ENDPOINT..."

until curl --output /dev/null --silent --head --fail "$API_ENDPOINT"; do
  log "API endpoint $API_ENDPOINT not ready yet. Waiting ${WAIT_INTERVAL}s..."
  sleep "$WAIT_INTERVAL"
  ELAPSED_TIME=$(($ELAPSED_TIME + $WAIT_INTERVAL))
  if [ "$ELAPSED_TIME" -ge "$MAX_WAIT_SECONDS" ]; then
    log "ERROR: CML API endpoint $API_ENDPOINT did not become ready within $MAX_WAIT_SECONDS seconds."
    exit 1
  fi
done

log "CML API endpoint $API_ENDPOINT is ready."
exit 0
