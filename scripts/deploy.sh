#!/bin/bash
# Build the release server and CLI, and put the server on the public relay.
#
#   scripts/deploy.sh server          build, strip, copy to artisan, restart the relay
#   scripts/deploy.sh sudfa-test [DROP]
#                                     copy the CLI to sudfa and send 100 MB from there
#                                     over UDP to this machine (optionally dropping
#                                     DROP, e.g. 0.2, of the data datagrams here)
#
# The relay is restarted with ~/bitmule-relay/start-prod.sh (not pkill -f, which
# once matched its own ssh shell). See "Relay on artisan" in docs/v2-status.md.
set -euo pipefail

RELAY_HOST=${RELAY_HOST:-artisan}
RELAY_URL=${RELAY_URL:-https://bitmule.qdat.net}
TEST_HOST=${TEST_HOST:-sudfa.mywire.org}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${TMPDIR:-/tmp}/bitmule-deploy
mkdir -p "$OUT"

deploy_server() {
    cd "$ROOT"
    cargo build --release -p bitmule-server
    cp target/release/bitmule-server "$OUT/bitmule-server.prod"
    strip "$OUT/bitmule-server.prod"
    scp "$OUT/bitmule-server.prod" "$RELAY_HOST:bitmule-relay/bitmule-server.prod"
    ssh "$RELAY_HOST" '~/bitmule-relay/start-prod.sh'
    sleep 2
    curl -fsS -o /dev/null "$RELAY_URL/" && echo "relay answers at $RELAY_URL"
}

sudfa_test() {
    local drop=${1:-0}
    cd "$ROOT"
    cargo build --release -p bitmule
    scp target/release/bitmule "$TEST_HOST:/tmp/bitmule-udp-test"
    ssh "$TEST_HOST" 'head -c 100000000 /dev/urandom > /tmp/f100u; sha256sum < /tmp/f100u' > "$OUT/sudfa.sha"
    ssh "$TEST_HOST" 'cd /tmp && rm -f send.log && (nohup ./bitmule-udp-test --server '"$RELAY_URL"' --udp-only send f100u >send.log 2>&1 &)'
    local link=""
    for _ in $(seq 1 30); do
        link=$(ssh "$TEST_HOST" "grep -o 'https://[^ ]*#[A-Za-z0-9_-]*' /tmp/send.log | head -1" || true)
        [ -n "$link" ] && break
        sleep 1
    done
    [ -n "$link" ] || { echo "no share link from $TEST_HOST"; exit 1; }
    rm -rf "$OUT/recv"; mkdir -p "$OUT/recv"
    local start=$SECONDS
    BITMULE_UDP_DROP=$drop timeout 300 "$ROOT/target/release/bitmule" --server "$RELAY_URL" --udp-only recv "$link" --out "$OUT/recv"
    echo "took $((SECONDS - start)) s, drop $drop"
    if [ "$(sha256sum < "$OUT/recv/f100u")" = "$(cat "$OUT/sudfa.sha")" ]; then echo "hash matched"; else echo "HASH MISMATCH"; exit 1; fi
    ssh "$TEST_HOST" 'pkill -x bitmule-udp-test; rm -f /tmp/bitmule-udp-test /tmp/f100u /tmp/send.log' || true
}

case "${1:-}" in
    server) deploy_server ;;
    sudfa-test) sudfa_test "${2:-0}" ;;
    *) sed -n '2,11p' "$0"; exit 2 ;;
esac
